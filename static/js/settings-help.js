// Settings help texts, kept short (static/js/settings-help.js).
//
// A help text under a setting says one plain sentence; when it has more to say, the rest waits under "More".
// Done when the Settings page is wired, on every help text in it longer than LONG_WORDS words and made of
// text alone (a help with a link or code in it is left as written). Idempotent: a text already split is
// not split again. Nothing here reads a value or talks to the server.
(function () {
    'use strict';

    const LONG_WORDS = 40;
    // The first sentence ends at the first full stop, question or exclamation mark that is followed by a space
    // and a capital letter or an opening quote or bracket (so "e.g. a vault" and "2.5 GB" do not end it).
    const FIRST_SENTENCE = /^(.*?[.!?])\s+(?=[A-Z"“(])(.*)$/s;

    function words(text) { return text.trim().split(/\s+/).filter(Boolean).length; }

    function split(text) {
        const m = text.trim().match(FIRST_SENTENCE);
        if (!m || !m[2].trim()) return null;
        return { first: m[1].trim(), rest: m[2].trim() };
    }

    function shortenOne(el) {
        if (el.dataset.helpShortened) return false;
        if (el.children.length) return false;                      // markup inside: left as written
        const text = el.textContent || '';
        if (words(text) <= LONG_WORDS) return false;
        const parts = split(text);
        if (!parts) return false;
        el.textContent = parts.first + ' ';
        const more = document.createElement('details');
        more.className = 'help-more';
        const summary = document.createElement('summary');
        summary.textContent = 'More';
        const rest = document.createElement('span');
        rest.className = 'help-more-text';
        rest.textContent = parts.rest;
        more.appendChild(summary);
        more.appendChild(rest);
        el.appendChild(more);
        el.dataset.helpShortened = '1';
        return true;
    }

    function shorten(root) {
        const scope = root || document.getElementById('settings-section');
        if (!scope) return 0;
        let n = 0;
        scope.querySelectorAll('.form-help, .settings-tab-content p.text-secondary').forEach((el) => {
            if (el.closest('.help-more')) return;
            if (shortenOne(el)) n++;
        });
        return n;
    }

    window.SettingsHelp = { shorten, split, LONG_WORDS };
})();
