/* Anonymous receiver ("Upload link") page.
 *
 * Reads the token from /u/{token}. First asks GET /receivers/{token}/page what the page may show before
 * anything is sent (the deployment's name, whether a code is asked for, and the owner's message when the
 * link asks for no code). Takes several files, chosen or dropped, and sends them one after another: each
 * opens an upload session (POST /receivers/{token}/upload-session), streams its bytes in fixed-size chunks
 * (PUT .../chunks/{i}) and finalizes (POST .../complete). A secret-protected link first gets a 401
 * {error:"secret_required"}; the page then prompts for the PIN/password and retries, and the owner's
 * message arrives with the first session the accepted code opens. When everything chosen has been sent, a
 * receipt lists each file by the name it was sent as, with its size, the time and a reference the owner can
 * find it by (a file whose name was already taken is stored under a new name; the owner sees that, the
 * uploader is not told which names are taken). All status text is written with textContent only; no inline
 * handlers (strict CSP). */
(function () {
  "use strict";

  var CHUNK = 8 * 1024 * 1024;   // 8 MiB per chunk (well under the server's per-chunk ceiling)
  var MAX_FILES = 50;

  function $(id) { return document.getElementById(id); }
  function show(id) { $(id).classList.remove("hidden"); }
  function hide(id) { $(id).classList.add("hidden"); }

  var parts = window.location.pathname.split("/").filter(Boolean);
  var token = parts.length ? decodeURIComponent(parts[parts.length - 1]) : "";
  var secret = null;
  var queue = [];        // { file, li, state }
  var delivered = [];    // the receipt's rows: { name, size, at, reference }
  var busy = false;

  function notice(text) {
    hide("loading"); hide("form"); hide("receipt");
    var n = $("notice"); n.textContent = text; show("notice");
  }

  function msg(text, cls) {
    var m = $("msg");
    m.textContent = text || "";
    m.className = "msg" + (cls ? " " + cls : "");
    if (text) { m.classList.remove("hidden"); } else { m.classList.add("hidden"); }
  }

  function humanSize(n) {
    n = Number(n) || 0;
    if (n < 1024) { return n + " B"; }
    var u = ["KB", "MB", "GB", "TB"], i = -1;
    do { n = n / 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(1) + " " + u[i];
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
    msg(errorText || "", errorText ? "error" : null);
    $("secret-input").focus();
  }

  // ---- what the page shows before anything is sent ----------------------------------------------------------
  function pageInfo() {
    return fetch("/receivers/" + encodeURIComponent(token) + "/page", { headers: { "Accept": "application/json" } });
  }

  function showOwnerMessage(text) {
    var m = $("owner-message");
    if (!text) { return; }
    m.textContent = text; m.classList.remove("hidden");
  }

  function applyPageInfo(info) {
    if (info && info.brand) { $("brand").textContent = info.brand + " · Upload files"; document.title = info.brand + " · Upload files"; }
    showOwnerMessage(info && info.message);
    if (info && info.secret_kind && info.secret_kind !== "none") { promptSecret(info.secret_kind, null); }
  }

  // ---- the chosen files ----------------------------------------------------------------------------------------
  function addFiles(list) {
    var added = 0;
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      if (!f || !f.name) { continue; }
      if (queue.length >= MAX_FILES) { msg("At most " + MAX_FILES + " files at a time.", "error"); break; }
      var dup = queue.some(function (q) { return q.file.name === f.name && q.file.size === f.size && q.file.lastModified === f.lastModified; });
      if (dup) { continue; }
      queue.push({ file: f, li: null, state: "waiting" });
      added++;
    }
    renderQueue();
    if (added) { msg("", null); }
  }

  function renderQueue() {
    var ul = $("files");
    ul.textContent = "";
    queue.forEach(function (q, index) {
      var li = document.createElement("li");
      var name = document.createElement("span"); name.className = "name"; name.textContent = q.file.name; name.title = q.file.name;
      var size = document.createElement("span"); size.className = "size"; size.textContent = humanSize(q.file.size);
      var state = document.createElement("span"); state.className = "state" + (q.stateCls ? " " + q.stateCls : ""); state.textContent = q.stateText || "";
      li.appendChild(name); li.appendChild(size); li.appendChild(state);
      if (!busy && q.state === "waiting") {
        var rm = document.createElement("button"); rm.type = "button"; rm.className = "remove"; rm.textContent = "Remove";
        rm.setAttribute("aria-label", "Remove " + q.file.name);
        rm.addEventListener("click", function () { queue.splice(index, 1); renderQueue(); });
        li.appendChild(rm);
      }
      q.li = li; q.stateEl = state;
      ul.appendChild(li);
    });
    $("upload-btn").disabled = busy || !queue.some(function (q) { return q.state === "waiting"; });
    $("upload-btn").textContent = queue.length > 1 ? "Upload " + queue.length + " files" : "Upload";
  }

  function setState(q, text, cls) {
    q.stateText = text; q.stateCls = cls || "";
    if (q.stateEl) { q.stateEl.textContent = text; q.stateEl.className = "state" + (cls ? " " + cls : ""); }
  }

  // ---- one file's trip ------------------------------------------------------------------------------------------
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

  // Sends one file. Resolves to "sent", "secret" (the link wants its code, nothing sent), "stop" (the link is
  // not available: nothing more can be sent) or "failed" (this file did not go; the next may).
  async function sendOne(q, position, count) {
    var file = q.file;
    setState(q, "Uploading…", null);
    var resp = await openSession(file);
    if (resp.status === 401) {
      var d = (await resp.json()).detail || {};
      var kind = d.secret_kind || "password";
      promptSecret(kind, d.error === "wrong_secret" ? (kind === "pin" ? "That PIN is incorrect. Please try again." : "That password is incorrect. Please try again.") : null);
      setState(q, "", null);
      return "secret";
    }
    if (resp.status === 429) { setState(q, "Too many attempts; wait and try again", "error"); return "failed"; }
    if (resp.status === 413) { setState(q, "Too large for this link", "error"); return "failed"; }
    if (resp.status === 404) { return "stop"; }
    if (resp.status !== 200) { setState(q, "Could not start", "error"); return "failed"; }

    var sess = await resp.json();
    showOwnerMessage(sess.message);   // a protected link's message, now that its code has been accepted
    var sid = sess.session_id;
    var total = Math.max(1, Math.ceil(file.size / CHUNK));
    for (var i = 0; i < total; i++) {
      var slice = file.slice(i * CHUNK, Math.min(file.size, (i + 1) * CHUNK));
      var cr = await putChunk(sid, i, slice);
      if (cr.status !== 200) { setState(q, "Failed while sending", "error"); return "failed"; }
      var filePct = (i + 1) * 100 / total;
      setProgress(((position - 1) * 100 + filePct) / count);
      msg("Uploading " + position + " of " + count + "… " + Math.round(filePct) + "%", null);
    }
    var fr = await complete(sid);
    if (fr.status === 200) {
      var done = await fr.json();
      delivered.push({ name: file.name,
                       size: done.size != null ? done.size : file.size, at: done.received_at || new Date().toISOString(),
                       reference: done.reference || String(done.id || "").slice(0, 8).toUpperCase() });
      setState(q, "Delivered", "ok");
      q.state = "sent";
      return "sent";
    }
    if (fr.status === 409) { setState(q, await notFinalizedWhy(fr), "error"); return "failed"; }
    setState(q, "Could not be finalized; try again", "error"); return "failed";
  }

  // What a 409 from /complete says, by the server's own detail: parts missing, a size that did not match, or
  // a session that cannot be completed. (A name already taken is never a refusal: it is stored under a new name.)
  async function notFinalizedWhy(resp) {
    var detail = null;
    try { detail = (await resp.json()).detail; } catch (e) { detail = null; }
    if (detail && detail.error === "incomplete") { return "Not every part arrived; try again"; }
    if (detail && detail.code === "size_mismatch") { return "Arrived with a different size than expected; try again"; }
    return "Could not be finalized; try again";
  }

  async function run() {
    var waiting = queue.filter(function (q) { return q.state === "waiting"; });
    if (!waiting.length) { msg("Choose a file first.", "error"); return; }
    busy = true; renderQueue();
    var btn = $("upload-btn");
    btn.disabled = true;
    msg("Starting…", null);
    var stopped = false, needSecret = false, failed = 0;
    try {
      for (var i = 0; i < waiting.length; i++) {
        var result = await sendOne(waiting[i], i + 1, waiting.length);
        if (result === "secret") { needSecret = true; break; }
        if (result === "stop") { stopped = true; break; }
        if (result === "failed") { failed++; waiting[i].state = "failed"; }
      }
    } catch (e) {
      msg("Network error. Please try again.", "error");
      busy = false; renderQueue();
      return;
    }
    busy = false;
    if (stopped) {
      if (delivered.length) { showReceipt("This link took no more files after these."); return; }
      notice("This upload link is not available."); return;
    }
    if (needSecret) { renderQueue(); return; }
    var sent = waiting.filter(function (q) { return q.state === "sent"; }).length;
    if (sent && !failed) { setProgress(100); showReceipt(); return; }
    queue.forEach(function (q) { if (q.state === "failed") { q.state = "waiting"; } });
    renderQueue();
    if (sent && failed) {
      msg(sent + " delivered, " + failed + " not. The ones not delivered can be tried again.", "error");
      var more = document.createElement("button"); more.type = "button"; more.className = "quiet"; more.textContent = "Show the receipt for what was delivered";
      more.style.marginTop = ".75rem";
      more.addEventListener("click", showReceipt);
      $("msg").appendChild(document.createElement("br")); $("msg").appendChild(more);
    } else if (failed) {
      msg("Nothing was delivered. Check the messages beside each file and try again.", "error");
    }
  }

  // ---- the receipt ----------------------------------------------------------------------------------------------
  function when(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return iso || ""; }
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function showReceipt(note) {
    hide("form"); hide("notice");
    var n = $("receipt-note");
    if (n) { n.textContent = note || ""; n.classList.toggle("hidden", !note); }
    var rows = $("receipt-rows");
    rows.textContent = "";
    delivered.forEach(function (r) {
      var tr = document.createElement("tr");
      var name = document.createElement("td"); name.className = "name"; name.textContent = r.name;
      var size = document.createElement("td"); size.className = "size"; size.textContent = humanSize(r.size);
      var at = document.createElement("td"); at.textContent = when(r.at);
      var ref = document.createElement("td"); ref.className = "ref"; ref.textContent = r.reference;
      tr.appendChild(name); tr.appendChild(size); tr.appendChild(at); tr.appendChild(ref);
      rows.appendChild(tr);
    });
    $("receipt-intro").textContent = delivered.length === 1
      ? "1 file was delivered to the owner of this link."
      : delivered.length + " files were delivered to the owner of this link.";
    show("receipt");
    // The form the person was in is gone: say so by moving them to the receipt's heading (the intro beside
    // it is a status region, so the count is read out too).
    $("receipt-title").focus();
  }

  function sendMore() {
    queue = queue.filter(function (q) { return q.state !== "sent"; });
    $("file-input").value = "";
    hide("receipt"); show("form");
    hide("bar"); msg("", null);
    renderQueue();
  }

  // ---- wiring -----------------------------------------------------------------------------------------------------
  function start() {
    if (!token) { notice("This upload link is not available."); return; }
    $("upload-btn").addEventListener("click", function () {
      var v = $("secret-input").value;
      if (v) { secret = v; }
      run();
    });
    $("file-input").addEventListener("change", function () { addFiles($("file-input").files); $("file-input").value = ""; });
    var drop = $("drop");
    ["dragenter", "dragover"].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove("over"); });
    });
    drop.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files) { addFiles(e.dataTransfer.files); }
    });
    // A drop anywhere else on the page must not open the file in the browser.
    document.addEventListener("dragover", function (e) { e.preventDefault(); });
    document.addEventListener("drop", function (e) { e.preventDefault(); });
    $("more-btn").addEventListener("click", sendMore);
    $("print-btn").addEventListener("click", function () { window.print(); });

    pageInfo().then(function (resp) {
      if (resp.status === 404) { notice("This upload link is not available."); return; }
      if (resp.status === 429) { notice("Too many attempts. Please wait and try again."); return; }
      return resp.ok ? resp.json().then(applyPageInfo) : null;
    }).catch(function () { /* the page still works without its name and message */ })
      .then(function () { if ($("notice").classList.contains("hidden")) { hide("loading"); show("form"); renderQueue(); } });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
