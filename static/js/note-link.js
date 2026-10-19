/* Anonymous public-note-link redemption page.
 *
 * Reads the token from /l/{token} and asks /note-links/{token}/redeem, with peek=true, whether the link
 * opens and with what; a peek spends nothing. A link with no secret then shows a "Show note" button,
 * and only its click redeems for real, spending one view and showing the note: a scanner or a link
 * preview that loads the page and runs its script uses nothing. A protected link answers the peek with
 * 401 {error:"secret_required", secret_kind}; the page prompts for the PIN/password and submits it,
 * which spends the view and shows the note, as it always has. Title/body are rendered with textContent
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
    hide("loading"); hide("secret-form"); hide("reveal"); hide("content");
    var n = $("notice");
    n.textContent = text;
    show("notice");
  }

  function renderContent(data) {
    hide("loading"); hide("secret-form"); hide("reveal"); hide("notice");
    $("note-title").textContent = data.title || "Untitled note";
    $("note-body").textContent = data.body || "";
    show("content");
  }

  function offerReveal() {
    hide("loading"); hide("secret-form"); hide("content"); hide("notice");
    $("reveal-error").classList.add("hidden");
    show("reveal");
  }

  function promptSecret(secretKind, errorText) {
    hide("loading"); hide("content"); hide("reveal"); hide("notice");
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

  function redeem(secret, peek) {
    var body = {};
    if (secret != null) { body.secret = secret; }
    if (peek) { body.peek = true; }
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
      return resp.json().then(function (data) {
        // A peek's answer (no note in it) offers the button; a redeem's answer is the note.
        if (data && data.available === true && !("body" in data)) { offerReveal(); return; }
        renderContent(data);
      });
    }
    if (resp.status === 401) {
      return resp.json().then(function (payload) {
        var d = parseDetail(payload);
        var kind = d.secret_kind || "password";
        if (d.error === "wrong_secret") {
          promptSecret(kind, kind === "pin" ? "That PIN is incorrect. Please try again." : "That password is incorrect. Please try again.");
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
    redeem(input.value, false)
      .then(handle)
      .catch(function () { notice("Network error. Please try again."); })
      .then(function () { btn.disabled = false; });
  }

  function reveal() {
    var btn = $("reveal-btn");
    btn.disabled = true;
    redeem(null, false)
      .then(handle)
      .catch(function () {
        var err = $("reveal-error");
        err.textContent = "Network error. Please try again.";
        err.classList.remove("hidden");
      })
      .then(function () { btn.disabled = false; });
  }

  function start() {
    if (!token) { notice("This link is not available."); return; }
    $("secret-form").addEventListener("submit", submitSecret);
    $("reveal-btn").addEventListener("click", reveal);
    // A peek first: a link with no secret offers "Show note", a protected one returns 401 with its
    // secret_kind and we prompt. Neither spends a view or records a failed attempt.
    redeem(null, true)
      .then(handle)
      .catch(function () { notice("Network error. Please try again."); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
