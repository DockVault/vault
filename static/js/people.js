// People you can tell apart, and moments you can read: one chip for a person and one element for a
// time, used by every list that names people.
//
//   People.chip(person, options)   -> a <span class="person-chip"> with an initials avatar and the name.
//                                     person: {id, username, display_name?, deleted?}. options: {nameless, small}.
//   People.time(iso, options)      -> a <time class="when" datetime="..."> whose text is relative within a
//                                     week ("3 h ago") and a date after; the exact local time and the UTC
//                                     time are its tooltip. options: {fallback}.
//   People.placeholder(person, options), People.whenPlaceholder(iso, options)
//                                  -> the same two as HTML placeholders, for a list drawn from a template
//                                     string; People.hydrate(root) then turns every placeholder under root
//                                     into the real element. Attribute values are escaped here; the real
//                                     elements are built with createElement and textContent only.
//   People.initials(name), People.colourIndex(id)
//
// The colour comes from a hash of the account's stable id, never the name, so a renamed account keeps its
// colour and two people with similar names differ. Without an id (a name the server could not link to an
// account) the chip is grey, like a deleted account's. The initials are drawn from a data attribute, so a
// chip's text content is the person's name alone.
(function () {
    'use strict';

    const COLOURS = 12;
    const WEEK = 7 * 24 * 3600 * 1000;

    // FNV-1a over the id's UTF-16 units: fast, stable, well spread over twelve buckets.
    function colourIndex(id) {
        const s = String(id == null ? '' : id);
        if (!s) return 0;
        let h = 0x811c9dc5;
        for (let i = 0; i < s.length; i++) {
            h ^= s.charCodeAt(i);
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return (h % COLOURS) + 1;
    }

    function graphemes(text) {
        if (typeof Intl !== 'undefined' && Intl.Segmenter) {
            const seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
            return Array.from(seg.segment(text), (s) => s.segment);
        }
        return Array.from(text);
    }

    // The first grapheme of the first two words ("Ada Lovelace" -> "AL"), or the first two graphemes of
    // a single word ("ada.l" -> "AD"); upper-cased where the script has a case.
    function initials(name) {
        const words = String(name || '').trim().split(/[\s._-]+/).filter(Boolean);
        if (!words.length) return '?';
        let out;
        if (words.length >= 2) out = graphemes(words[0])[0] + graphemes(words[1])[0];
        else out = graphemes(words[0]).slice(0, 2).join('');
        return out.toLocaleUpperCase();
    }

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function chip(person, options) {
        const p = person || {};
        const o = options || {};
        const username = p.username || '';
        const display = p.display_name || '';
        const shown = display || username || 'Unknown';
        const gone = !!p.deleted || (!p.id && !o.unlinked_ok && !username);
        const wrap = el('span', 'person-chip' + (gone || (!p.id && !username) ? ' person-deleted' : ''));
        const avatar = el('span', 'person-avatar' + (o.small ? ' person-sm' : '') + (p.id ? ' person-c' + colourIndex(p.id) : ''));
        avatar.setAttribute('data-initials', initials(shown));
        avatar.setAttribute('aria-hidden', 'true');
        wrap.appendChild(avatar);
        if (!o.nameless) wrap.appendChild(el('span', 'person-name', shown));
        const parts = [];
        if (display && username && display !== username) parts.push(display + ' (' + username + ')');
        else parts.push(shown);
        if (p.deleted) parts.push('account deleted');
        else if (!p.id) parts.push('no account');
        wrap.title = parts.join(' · ');
        if (o.nameless) wrap.setAttribute('aria-label', wrap.title);
        return wrap;
    }

    function parse(value) {
        if (typeof parseServerTime === 'function') return parseServerTime(value);
        const d = new Date(value);
        return isNaN(d.getTime()) ? null : d;
    }

    function relative(date, now) {
        const seconds = Math.floor((now - date) / 1000);
        if (seconds < 45) return 'just now';
        if (seconds < 3600) return Math.max(1, Math.floor(seconds / 60)) + ' min ago';
        if (seconds < 86400) return Math.floor(seconds / 3600) + ' h ago';
        return Math.floor(seconds / 86400) + ' d ago';
    }

    function time(iso, options) {
        const o = options || {};
        const date = parse(iso);
        if (!date) return el('span', 'when-none text-tertiary', o.fallback === undefined ? '—' : o.fallback);
        const now = new Date();
        const node = el('time', 'when');
        node.setAttribute('datetime', date.toISOString());
        const age = now - date;
        node.textContent = (age >= 0 && age < WEEK) ? relative(date, now) : date.toLocaleDateString();
        node.title = date.toLocaleString() + ' · ' + date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
        return node;
    }

    function attr(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function placeholder(person, options) {
        const p = person || {};
        const o = options || {};
        return '<span data-person="1"'
            + (p.id ? ' data-person-id="' + attr(p.id) + '"' : '')
            + ' data-person-name="' + attr(p.username || '') + '"'
            + (p.display_name ? ' data-person-display="' + attr(p.display_name) + '"' : '')
            + (p.deleted ? ' data-person-deleted="1"' : '')
            + (o.nameless ? ' data-person-nameless="1"' : '')
            + (o.small ? ' data-person-small="1"' : '')
            + (o.className ? ' class="' + attr(o.className) + '"' : '')
            + '></span>';
    }

    function whenPlaceholder(iso, options) {
        const o = options || {};
        return '<span data-when="' + attr(iso || '') + '"'
            + (o.fallback !== undefined ? ' data-when-fallback="' + attr(o.fallback) + '"' : '')
            + (o.className ? ' class="' + attr(o.className) + '"' : '') + '></span>';
    }

    // Every placeholder under root becomes its element; a class on the placeholder is kept on the element.
    function hydrate(root) {
        const scope = root || document;
        scope.querySelectorAll('span[data-person]').forEach((ph) => {
            const node = chip({
                id: ph.getAttribute('data-person-id') || null,
                username: ph.getAttribute('data-person-name') || '',
                display_name: ph.getAttribute('data-person-display') || '',
                deleted: ph.hasAttribute('data-person-deleted'),
            }, { nameless: ph.hasAttribute('data-person-nameless'), small: ph.hasAttribute('data-person-small') });
            if (ph.className) ph.classList.forEach((c) => node.classList.add(c));
            ph.replaceWith(node);
        });
        scope.querySelectorAll('span[data-when]').forEach((ph) => {
            const fb = ph.hasAttribute('data-when-fallback') ? ph.getAttribute('data-when-fallback') : undefined;
            const node = time(ph.getAttribute('data-when'), { fallback: fb });
            if (ph.className) ph.classList.forEach((c) => node.classList.add(c));
            ph.replaceWith(node);
        });
    }

    // Placeholders become elements as soon as a list draws them: the page is watched for additions, so a
    // list drawn from a template string needs no call of its own.
    function start() {
        hydrate(document);
        new MutationObserver((records) => {
            records.forEach((r) => r.addedNodes.forEach((n) => {
                if (n.nodeType !== 1) return;
                if (n.matches && (n.matches('span[data-person]') || n.matches('span[data-when]'))) hydrate(n.parentNode || document);
                else hydrate(n);
            }));
        }).observe(document.body, { childList: true, subtree: true });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    window.People = { chip, time, placeholder, whenPlaceholder, hydrate, initials, colourIndex };
})();
