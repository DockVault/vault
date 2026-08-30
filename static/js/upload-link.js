/* Anonymous receiver ("Upload link") page.
 *
 * Reads the token from /u/{token}, opens an upload session (POST /receivers/{token}/upload-session),
 * streams the chosen file in fixed-size chunks (PUT .../chunks/{i}), then finalizes
 * (POST .../complete). A secret-protected link first gets a 401 {error:"secret_required"}; the page
 * then prompts for the PIN/password and retries. All status text is written with textContent only; no
 * inline handlers (strict CSP). */
(function () {
  "use strict";

  var CHUNK = 8 * 1024 * 1024;   // 8 MiB per chunk (well under the server's per-chunk ceiling)

  function $(id) { return document.getElementById(id); }
  function show(id) { $(id).classList.remove("hidden"); }
  function hide(id) { $(id).classList.add("hidden"); }

  var parts = window.location.pathname.split("/").filter(Boolean);
  var token = parts.length ? decodeURIComponent(parts[parts.length - 1]) : "";
  var secret = null;

  function notice(text) {
    hide("loading"); hide("form");
    var n = $("notice"); n.textContent = text; show("notice");
  }

  function msg(text, cls) {
    var m = $("msg");
    m.textContent = text || "";
    m.className = "msg" + (cls ? " " + cls : "");
    if (text) { m.classList.remove("hidden"); } else { m.classList.add("hidden"); }
  }

  function promptSecret(kind, errorText) {
    show("secret-label"); show("secret-input");
    $("secret-label").textContent = kind === "pin"
      ? "This link is protected. Enter the PIN."
      : "This link is protected. Enter the password.";
    if (kind === "pin") {
      $("secret-input").setAttribute("inputmode", "numeric");
      $("secret-input").setAttribute("autocomplete", "one-time-code");
    }
    if (errorText) { msg(errorText, "error"); }
    $("secret-input").focus();
  }

  function openSession(file) {
    var total_chunks = Math.max(1, Math.ceil(file.size / CHUNK));
    var body = { filename: file.name, total_size: file.size, total_chunks: total_chunks };
    if (secret != null) { body.secret = secret; }
    return fetch("/receivers/" + encodeURIComponent(token) + "/upload-session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  function putChunk(sessionId, index, blob) {
    return fetch("/receivers/" + encodeURIComponent(token) + "/upload-session/"
                 + encodeURIComponent(sessionId) + "/chunks/" + index, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: blob
    });
  }

  function complete(sessionId) {
    return fetch("/receivers/" + encodeURIComponent(token) + "/upload-session/"
                 + encodeURIComponent(sessionId) + "/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });
  }

  function setProgress(pct) {
    show("bar");
    $("bar-fill").style.width = Math.max(0, Math.min(100, pct)) + "%";
  }

  async function run() {
    var file = $("file-input").files[0];
    if (!file) { msg("Choose a file first.", "error"); return; }
    var btn = $("upload-btn");
    btn.disabled = true;
    msg("Starting…", null);
    try {
      var resp = await openSession(file);
      if (resp.status === 401) {
        var d = (await resp.json()).detail || {};
        promptSecret(d.secret_kind || "password",
                     d.error === "wrong_secret" ? "That code is incorrect. Please try again." : null);
        btn.disabled = false;
        return;
      }
      if (resp.status === 429) { msg("Too many attempts. Please wait and try again.", "error"); btn.disabled = false; return; }
      if (resp.status === 413) { msg("This file is too large for this link.", "error"); btn.disabled = false; return; }
      if (resp.status === 404) { notice("This upload link is not available."); return; }
      if (resp.status !== 200) { msg("Could not start the upload.", "error"); btn.disabled = false; return; }

      var sess = await resp.json();
      var sid = sess.session_id;
      var total = Math.max(1, Math.ceil(file.size / CHUNK));
      for (var i = 0; i < total; i++) {
        var slice = file.slice(i * CHUNK, Math.min(file.size, (i + 1) * CHUNK));
        var cr = await putChunk(sid, i, slice);
        if (cr.status !== 200) { msg("Upload failed while sending the file.", "error"); btn.disabled = false; return; }
        setProgress((i + 1) * 100 / total);
        msg("Uploading… " + Math.round((i + 1) * 100 / total) + "%", null);
      }
      var fr = await complete(sid);
      if (fr.status === 200) {
        setProgress(100);
        msg("Uploaded. Thank you — the file has been delivered.", "ok");
        $("file-input").disabled = true;
      } else if (fr.status === 409) {
        msg("A file with that name already exists here. Rename it and try again.", "error");
        btn.disabled = false;
      } else {
        msg("The upload could not be finalized.", "error");
        btn.disabled = false;
      }
    } catch (e) {
      msg("Network error. Please try again.", "error");
      btn.disabled = false;
    }
  }

  function start() {
    if (!token) { notice("This upload link is not available."); return; }
    hide("loading"); show("form");
    $("upload-btn").addEventListener("click", function () {
      var v = $("secret-input").value;
      if (v) { secret = v; }
      run();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
