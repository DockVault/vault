// Settings help texts, kept short (static/js/settings-help.js).
//
// A help text under a setting says one plain sentence; when it has more to say, the rest waits under "More".
// Done when the Settings page is wired, on every help text in it longer than LONG_WORDS words: a plain
// paragraph, a <small> hint or an email hint, with or without markup inside (a link, a code span or a bold
// word travels whole into the part under "More", or stays in the first sentence when it is part of it).
// Idempotent: a text already split is not split again. Nothing here reads a value or talks to the server.
(function () {
    'use strict';

    const LONG_WORDS = 40;
    // The first sentence ends at the first full stop, question or exclamation mark that is followed by a space
    // and a capital letter or an opening quote or bracket (so "e.g. a vault" and "2.5 GB" do not end it).
    const FIRST_SENTENCE = /^(.*?[.!?])\s+(?=[A-Z"“(])(.*)$/s;
    // Where a long help text lives in Settings: the paragraph under a setting, a <small> hint, an email hint.
    const HELP_SELECTOR = '.form-help, .settings-tab-content p.text-secondary, .settings-tab-content small, .settings-tab-content .email-hint';

    function words(text) { return text.trim().split(/\s+/).filter(Boolean).length; }

    function split(text) {
        const m = text.trim().match(FIRST_SENTENCE);
        if (!m || !m[2].trim()) return null;
        return { first: m[1].trim(), rest: m[2].trim() };
    }

    function moreBox() {
        const more = document.createElement('details');
        more.className = 'help-more';
        const summary = document.createElement('summary');
        summary.textContent = 'More';
        const rest = document.createElement('span');
        rest.className = 'help-more-text';
        more.appendChild(summary);
        more.appendChild(rest);
        return { more, rest };
    }

    // Moves everything after the first sentence into the "More" box, node by node, so markup survives: the
    // text node the sentence ends in is cut in two; an element the boundary falls inside stays whole in the
    // first part (a sentence is never cut inside a link or a code span).
    function splitNodes(el, firstLength) {
        const nodes = Array.from(el.childNodes);
        let seen = 0;
        const { more, rest } = moreBox();
        let moving = false;
        for (const node of nodes) {
            if (moving) { rest.appendChild(node); continue; }
            const len = (node.textContent || '').length;
            if (seen + len <= firstLength) { seen += len; continue; }
            // The boundary falls inside this node.
            if (node.nodeType === Node.TEXT_NODE) {
                const cut = firstLength - seen;
                const tail = node.textContent.slice(cut).replace(/^\s+/, '');
                node.textContent = node.textContent.slice(0, cut) + ' ';
                if (tail) rest.appendChild(document.createTextNode(tail));
            }
            // An element the boundary falls inside stays whole in the first part.
            moving = true;
        }
        if (!rest.childNodes.length) return false;
        el.appendChild(more);
        return true;
    }

    function shortenOne(el) {
        if (el.dataset.helpShortened) return false;
        if (el.querySelector('.help-more')) return false;         // split by hand in the markup
        const text = el.textContent || '';
        if (words(text) <= LONG_WORDS) return false;
        const parts = split(text);
        if (!parts) return false;
        // The first sentence's length as the full text is laid out, leading space dropped: the point where the
        // child nodes are cut.
        const leading = text.length - text.replace(/^\s+/, '').length;
        const firstLength = leading + parts.first.length;
        if (!el.children.length) {
            el.textContent = parts.first + ' ';
            const { more, rest } = moreBox();
            rest.textContent = parts.rest;
            el.appendChild(more);
        } else if (!splitNodes(el, firstLength)) {
            return false;
        }
        el.dataset.helpShortened = '1';
        return true;
    }

    function shorten(root) {
        const scope = root || document.getElementById('settings-section');
        if (!scope) return 0;
        let n = 0;
        scope.querySelectorAll(HELP_SELECTOR).forEach((el) => {
            if (el.closest('.help-more')) return;
            if (el.querySelector(HELP_SELECTOR)) return;           // a box that holds help texts, not one itself
            if (shortenOne(el)) n++;
        });
        return n;
    }

    window.SettingsHelp = { shorten, split, LONG_WORDS, HELP_SELECTOR };
})();
