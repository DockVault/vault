/* Anonymous public-note-link redemption page.
 *
 * Reads the token from /l/{token}, POSTs to /note-links/{token}/redeem, and renders the frozen
 * snapshot. A secret-protected link first gets a 401 {error:"secret_required", secret_kind}; the
 * page then prompts for the PIN/password and re-submits. Title/body are rendered with textContent
 * only (never innerHTML), so a note's contents can never inject markup or script. No inline handlers
 * (strict CSP: script-src 'self'); everything is wired with addEventListener. */
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  // token is the last path segment of /l/{token}
  var parts = window.location.pathname.split("/").filter(Boolean);
  var token = parts.length ? decodeURIComponent(parts[parts.length - 1]) : "";

  function show(id) { $(id).classList.remove("hidden"); }
  function hide(id) { $(id).classList.add("hidden"); }

  function notice(text) {
    hide("loading"); hide("secret-form"); hide("content");
    var n = $("notice");
    n.textContent = text;
    show("notice");
  }

  function renderContent(data) {
    hide("loading"); hide("secret-form"); hide("notice");
    $("note-title").textContent = data.title || "Untitled note";
    $("note-body").textContent = data.body || "";
    show("content");
  }

  function promptSecret(secretKind, errorText) {
    hide("loading"); hide("content"); hide("notice");
    var label = secretKind === "pin"
      ? "This note is protected. Enter the PIN to view it."
      : "This note is protected. Enter the password to view it.";
    $("secret-label").textContent = label;
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

  function redeem(secret) {
    var body = {};
    if (secret != null) { body.secret = secret; }
    return fetch("/note-links/" + encodeURIComponent(token) + "/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  // Some error details arrive as an object ({error, secret_kind}); FastAPI wraps them under "detail".
  function parseDetail(payload) {
    var d = payload && payload.detail;
    if (d && typeof d === "object") { return d; }
    return {};
  }

  function handle(resp) {
    if (resp.status === 200) {
      return resp.json().then(renderContent);
    }
    if (resp.status === 401) {
      return resp.json().then(function (payload) {
        var d = parseDetail(payload);
        var kind = d.secret_kind || "password";
        if (d.error === "wrong_secret") {
          promptSecret(kind, "That code is incorrect. Please try again.");
        } else {
          promptSecret(kind, null);
        }
      });
    }
    if (resp.status === 429) {
      notice("Too many attempts. Please wait a few minutes and try again.");
      return;
    }
    if (resp.status === 404) {
      notice("This link is not available. It may have expired, been used up, or been revoked.");
      return;
    }
    if (resp.status === 503) {
      notice("The service is temporarily unavailable. Please try again shortly.");
      return;
    }
    notice("Something went wrong opening this link.");
  }

  function submitSecret(ev) {
    ev.preventDefault();
    var btn = $("secret-submit");
    var input = $("secret-input");
    btn.disabled = true;
    redeem(input.value)
      .then(handle)
      .catch(function () { notice("Network error. Please try again."); })
      .then(function () { btn.disabled = false; });
  }

  function start() {
    if (!token) { notice("This link is not available."); return; }
    $("secret-form").addEventListener("submit", submitSecret);
    // First try with no secret: a public (no-secret) link renders immediately; a protected link
    // returns 401 with its secret_kind and we prompt (no view consumed, no failed attempt recorded).
    redeem(null)
      .then(handle)
      .catch(function () { notice("Network error. Please try again."); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
