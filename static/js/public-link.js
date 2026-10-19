/* Anonymous public FILE/FOLDER-link page.
 *
 * Reads the token from /p/{token}, POSTs to /public-links/{token}/redeem with peek=true to render
 * either one file or a one-level folder listing (a visit spends nothing). The Download click redeems
 * for real, which spends one use of the link and returns a single-use download GRANT, and then hands
 * the file to the browser itself: an ordinary GET of the download address with the grant in its query,
 * which the browser saves as the server's Content-Disposition says. Nothing is fetched into the page,
 * so a file of any size never sits in its memory, and in-app browsers that cannot save a script's blob
 * can still save it. The grant is used by that one request and otherwise expires within 60 s, and the
 * page sends no more than its origin in a Referer, so the address it appears in holds nothing worth
 * keeping. A public file link never serves a zero-knowledge file (the server refuses one), so there is
 * nothing for the page to decrypt.
 *
 * All names come from the server as data and are written with textContent only (never innerHTML), so a
 * file name can never inject markup. No inline handlers (strict CSP: script-src 'self'); everything is
 * wired with addEventListener. */
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }
  function show(id) { $(id).classList.remove("hidden"); }
  function hide(id) { $(id).classList.add("hidden"); }

  var parts = window.location.pathname.split("/").filter(Boolean);
  var token = parts.length ? decodeURIComponent(parts[parts.length - 1]) : "";

  var secret = null;        // the PIN/password the user entered, if any (reused when re-redeeming)

  function notice(text) {
    hide("loading"); hide("secret-form"); hide("content");
    var n = $("notice"); n.textContent = text; show("notice");
  }

  function humanSize(n) {
    n = Number(n) || 0;
    if (n < 1024) { return n + " B"; }
    var u = ["KB", "MB", "GB", "TB"], i = -1;
    do { n = n / 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(1) + " " + u[i];
  }

  function parseDetail(payload) {
    var d = payload && payload.detail;
    return (d && typeof d === "object") ? d : {};
  }

  function redeem(peek) {
    var body = {};
    if (secret != null) { body.secret = secret; }
    // A peek renders the landing page WITHOUT spending a use; the download click redeems for real.
    if (peek) { body.peek = true; }
    return fetch("/public-links/" + encodeURIComponent(token) + "/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  function promptSecret(secretKind, errorText) {
    hide("loading"); hide("content"); hide("notice");
    $("secret-label").textContent = secretKind === "pin"
      ? "This link is protected. Enter the PIN to open it."
      : "This link is protected. Enter the password to open it.";
    var input = $("secret-input");
    if (secretKind === "pin") {
      input.setAttribute("inputmode", "numeric");
      input.setAttribute("autocomplete", "one-time-code");
    }
    var err = $("secret-error");
    if (errorText) { err.textContent = errorText; err.classList.remove("hidden"); }
    else { err.classList.add("hidden"); }
    show("secret-form");
    input.focus();
  }

  // The address the browser downloads from: the grant rides the query of this one request.
  function downloadAddress(fileId, grant) {
    return "/public-links/" + encodeURIComponent(token) + "/download/" + encodeURIComponent(fileId) +
      "?grant=" + encodeURIComponent(grant);
  }

  // Hand the download to the browser: a link made for this click and removed after it, so nothing on
  // the page holds the grant for a prefetch or a later look to find.
  function startDownload(fileId, grant) {
    var a = document.createElement("a");
    a.href = downloadAddress(fileId, grant);
    a.rel = "noreferrer";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function refusedText(status) {
    if (status === 429) { return "Too many attempts. Please wait a minute and try again."; }
    if (status === 503) { return "The service is busy. Please try again shortly."; }
    return "That file is no longer available.";
  }

  // Redeem for a single-use grant (this is where the link's use is spent), then let the browser fetch
  // and save the file itself.
  function download(fileId, btn) {
    var errBox = $("dl-error");
    errBox.classList.add("hidden");
    btn.disabled = true;
    redeem(false).then(function (resp) {
      if (resp.status !== 200) {
        errBox.textContent = refusedText(resp.status);
        errBox.classList.remove("hidden");
        return null;
      }
      return resp.json().then(function (data) {
        if (!data || !data.grant) { throw new Error("no grant"); }
        startDownload(fileId, data.grant);
      });
    }).catch(function () {
      errBox.textContent = "Network error. Please try again.";
      errBox.classList.remove("hidden");
    }).then(function () {
      // Kept off for a moment, so a double click does not spend a second use on the same file.
      setTimeout(function () { btn.disabled = false; }, 1500);
    });
  }

  function fileRow(entry) {
    var row = document.createElement("div");
    row.className = "row";
    var left = document.createElement("div");
    var name = document.createElement("div");
    name.className = "name"; name.textContent = entry.name || "(unnamed)";
    left.appendChild(name);
    if (!entry.is_folder) {
      var sub = document.createElement("div");
      sub.className = "sub"; sub.textContent = humanSize(entry.size);
      left.appendChild(sub);
    } else {
      var sub2 = document.createElement("div");
      sub2.className = "sub"; sub2.textContent = "Folder";
      left.appendChild(sub2);
    }
    row.appendChild(left);
    if (!entry.is_folder) {
      var btn = document.createElement("button");
      btn.type = "button"; btn.textContent = "Download";
      btn.addEventListener("click", function () { download(entry.id, btn); });
      row.appendChild(btn);
    }
    return row;
  }

  function render(data) {
    hide("loading"); hide("secret-form"); hide("notice");
    var listing = $("listing");
    listing.textContent = "";
    if (data.kind === "file") {
      $("title").textContent = data.name || "Shared file";
      listing.appendChild(fileRow({ id: data.file_id, name: data.name, size: data.size, is_folder: false }));
    } else {
      $("title").textContent = data.name ? ("Folder: " + data.name) : "Shared folder";
      var entries = data.entries || [];
      if (!entries.length) {
        var empty = document.createElement("div");
        empty.className = "center"; empty.textContent = "This folder is empty.";
        listing.appendChild(empty);
      } else {
        entries.forEach(function (e) { listing.appendChild(fileRow(e)); });
      }
    }
    show("content");
  }

  function handle(resp) {
    if (resp.status === 200) { return resp.json().then(render); }
    if (resp.status === 401) {
      return resp.json().then(function (payload) {
        var d = parseDetail(payload);
        var kind = d.secret_kind || "password";
        promptSecret(kind, d.error === "wrong_secret" ? (kind === "pin" ? "That PIN is incorrect. Please try again." : "That password is incorrect. Please try again.") : null);
      });
    }
    if (resp.status === 429) { notice("Too many attempts. Please wait a few minutes and try again."); return; }
    if (resp.status === 404) { notice("This link is not available. It may have expired, been used up, or been revoked."); return; }
    if (resp.status === 503) { notice("The service is temporarily unavailable. Please try again shortly."); return; }
    notice("Something went wrong opening this link.");
  }

  function submitSecret(ev) {
    ev.preventDefault();
    var btn = $("secret-submit"); var input = $("secret-input");
    secret = input.value;
    btn.disabled = true;
    redeem(true).then(handle)
      .catch(function () { notice("Network error. Please try again."); })
      .then(function () { btn.disabled = false; });
  }

  function start() {
    if (!token) { notice("This link is not available."); return; }
    $("secret-form").addEventListener("submit", submitSecret);
    // First try with no secret: a public link renders immediately; a protected one returns 401 with
    // its secret_kind and we prompt (no use consumed, no failed attempt recorded).
    redeem(true).then(handle).catch(function () { notice("Network error. Please try again."); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
