/* Activity page (administrators): what happened, who did it, and how it came in.
 *
 * One page: a header (the time range, Pause, Export), a summary band whose marks are filters, and the
 * events list with the selected event's detail beside it. One state object (the range, the filters,
 * the page, the page size and the event shown) is the single source of truth: the chips, the filter
 * panel, the band, the list and the URL hash all read it, and every change goes through setState().
 *
 * New events arrive live. The app socket signals each committed audit row with its id and category
 * only ("dockvault:activity"); the page then fetches exactly those rows through the Events API, with
 * its filters, so every name in them is resolved for this viewer by the server.
 *
 * Uses app.js's helpers (apiRequest, _el, auditStatusBadge, openModal, showToast and friends). Every
 * value from the server is written with textContent or as an SVG attribute; nothing here builds markup
 * from text, and positions are set through the CSSOM, which the page's CSP allows. */
(function () {
    'use strict';

    // ---- vocabulary ------------------------------------------------------------------------------

    const CHANNELS = ['web', 'sftp', 'public_link', 'upload_link', 'device_sync', 'unknown'];
    const CHANNEL_LABELS = {
        web: 'Web', sftp: 'SFTP', public_link: 'Public link', upload_link: 'Upload link',
        device_sync: 'Device sync', unknown: 'Not recorded',
    };
    const STATUS_CHOICES = [['success', 'Succeeded'], ['authorized', 'Allowed'], ['failed', 'Failed or refused']];
    const STATUS_LABELS = {
        success: 'Succeeded', authorized: 'Allowed', failure: 'Failed', failed: 'Failed', error: 'Failed',
        refused: 'Refused', active: 'Active', revoked: 'Revoked', unconfirmed: 'Unconfirmed',
    };
    const BAD_STATUSES = new Set(['failure', 'failed', 'error', 'refused']);
    const PRESETS = ['24h', '7d', '30d'];
    const RANGE_NAMES = { '24h': 'the last 24 hours', '7d': 'the last 7 days', '30d': 'the last 30 days', all: 'all time' };
    const RANGE_TITLES = { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days', all: 'All time' };
    const WIDER = { '24h': '7d', '7d': '30d', '30d': 'all' };
    const PAGE_SIZES = ['25', '50', '100', 'all'];
    const ALL_STEP = 100;          // rows per step in "All"
    const ALL_CAP = 5000;          // "All" stops here until asked for more
    const ALL_MORE = 1000;
    const MAX_OFFSET = 100000;     // the server opens a page by number within this many rows of an end
    const IDS_PER_FETCH = 100;     // signalled rows fetched per request
    const KEEP_IDS = 500;          // ids kept while hidden or paused
    const LIVE_BURST = 100;        // more signalled ids than this in a second reload page 1 instead
    const WIDE_MIN = 980, MEDIUM_MIN = 600;

    // ---- state -------------------------------------------------------------------------------------

    function emptyFilters() {
        return {
            cat: [], act: [], status: [], ch: [], user: '', userMatch: 'contains', noAccount: false,
            ip: '', tcId: '', tcName: '', vault: '', time: null, q: '',
        };
    }

    function freshState() {
        return {
            ready: false, active: false, blocked: null,
            catalog: null, actionInfo: {}, catLabels: {}, catOrder: [], outcomes: null,
            // The one state: the range, the filters, the page, the page size and the event shown.
            range: { kind: '7d', from: null, to: null },
            f: emptyFilters(),
            page: 1, pageSize: '50', selectedId: null, detailOpen: false,
            // The list.
            rows: [], total: null, pages: null, listLoaded: false, listError: null, listSeq: 0,
            listBusy: false, listFromUsed: null, allCursor: null, allDone: true, allCap: ALL_CAP,
            allLoading: false, newestCursor: null,
            // The detail.
            detail: null, detailWhere: null, detailEdge: { newer: false, older: false }, detailMissing: false,
            // The band.
            band: null, bandSeq: 0, bandBusy: false, bandError: null, bandHeld: null, bandFrom: null, bandDirty: false,
            now: null, nowError: false, nowSeq: 0,
            // Live.
            paused: false, pausedAt: null, kept: new Set(), keptOver: false, keptCount: null,
            held: [], heldExtra: 0, heldBurst: false, heldIds: new Set(), fetchQueue: new Set(), recent: [], burst: false,
            newestRow: null, newMarks: new Map(), lastRead: null, vaultList: null, tcStates: {},
            socketState: window.dockvaultSocketState || 'connecting', socketDownSince: null,
            liveState: null, liveAnnounced: null, highlightOff: false, batches: [],
            lastPointer: 0, pointerDown: false, lastKey: 0,
            newPending: 0, lastNewAnnounce: 0,
            // Saved searches.
            saved: null, savedLoaded: null,
            layout: 'wide',
            undo: null,
        };
    }

    let S = freshState();
    let wired = false;

    // ---- small helpers -----------------------------------------------------------------------------

    const $ = (id) => document.getElementById(id);
    const SVGNS = 'http://www.w3.org/2000/svg';
    const isConsole = () => document.documentElement.getAttribute('data-ui') === 'v2';
    const nf = (n) => Number(n || 0).toLocaleString();

    function el(tag, cls, text) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    function icon(name, cls) {
        const svg = document.createElementNS(SVGNS, 'svg');
        svg.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
        svg.setAttribute('aria-hidden', 'true');
        svg.setAttribute('focusable', 'false');
        const use = document.createElementNS(SVGNS, 'use');
        use.setAttribute('href', '#i-' + name);
        svg.appendChild(use);
        return svg;
    }

    function svg(tag, attrs, cls) {
        const e = document.createElementNS(SVGNS, tag);
        if (cls) e.setAttribute('class', cls);
        Object.keys(attrs || {}).forEach((k) => e.setAttribute(k, String(attrs[k])));
        return e;
    }

    function button(cls, text, attrs) {
        const b = el('button', cls, text);
        b.type = 'button';
        Object.keys(attrs || {}).forEach((k) => b.setAttribute(k, attrs[k]));
        return b;
    }

    function toDate(v) {
        const d = v ? new Date(v) : null;
        return d && !isNaN(d.getTime()) ? d : null;
    }

    function iso(d) { return d ? new Date(d).toISOString() : null; }
    function utcText(v) {
        const d = toDate(v);
        return d ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace(/Z$/, ' UTC') : '';
    }
    function timeText(d) { return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
    function hmText(d) { return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }); }
    function dayShort(d) { return d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' }); }
    function dayMonth(d, withYear) {
        const o = { day: 'numeric', month: 'short' };
        if (withYear) o.year = 'numeric';
        return d.toLocaleDateString(undefined, o);
    }
    function fullWhen(d) {
        const date = d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });
        const zone = zoneShort(d);
        return `${date}, ${timeText(d)}${zone ? ' ' + zone : ''}`;
    }
    function sameDay(a, b) {
        return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
    }
    function zoneShort(at) {
        try {
            const p = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(at || new Date());
            const z = p.find((x) => x.type === 'timeZoneName');
            return z ? z.value : '';
        } catch (_) { return ''; }
    }
    function zoneName() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) { return ''; }
    }
    function ago(d) {
        const s = Math.round((Date.now() - d.getTime()) / 1000);
        let rtf = null;
        try { rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }); } catch (_) { /* old browser */ }
        const fmt = (v, u) => (rtf ? rtf.format(-v, u) : `${v} ${u}${v === 1 ? '' : 's'} ago`);
        if (s < 45) return rtf ? rtf.format(0, 'second') : 'just now';
        if (s < 3600) return fmt(Math.round(s / 60), 'minute');
        if (s < 86400) return fmt(Math.round(s / 3600), 'hour');
        return fmt(Math.round(s / 86400), 'day');
    }

    // A time span as short text: "Thu 25 Sep 12:00–18:00", or across days "Thu 25 Sep 12:00 – Fri 26 Sep 06:00".
    function spanText(from, to) {
        const a = toDate(from), b = toDate(to);
        if (!a || !b) return '';
        const end = new Date(b.getTime() - 1);
        const midnightA = a.getHours() === 0 && a.getMinutes() === 0;
        const midnightB = b.getHours() === 0 && b.getMinutes() === 0;
        if (midnightA && midnightB) {
            if (sameDay(a, end)) return dayShort(a);
            return `${dayShort(a)} – ${dayShort(end)}`;
        }
        if (sameDay(a, end)) {
            return `${dayShort(a)} ${hmText(a)}–${midnightB ? '24:00' : hmText(b)}`;
        }
        return `${dayShort(a)} ${hmText(a)} – ${dayShort(b)} ${hmText(b)}`;
    }

    // An IPv6 address shortened in the middle, the whole of it kept for the title.
    function midEllipsis(s, keep) {
        const k = keep || 18;
        if (!s || s.length <= k) return s || '';
        const half = Math.floor((k - 1) / 2);
        return s.slice(0, half) + '…' + s.slice(-half);
    }

    function channelLabel(c) { return CHANNEL_LABELS[c || 'unknown'] || c; }
    function statusLabel(s) { return STATUS_LABELS[s] || s || '—'; }
    function isBad(ev) { return BAD_STATUSES.has(ev.status); }
    function catLabel(key) { return S.catLabels[key] || key; }
    function actionLabel(name) { return (S.actionInfo[name] && S.actionInfo[name].label) || name; }
    function actionCategory(name) { return (S.actionInfo[name] && S.actionInfo[name].category) || null; }
    function actionsOf(key) {
        const c = S.catalog && S.catalog.categories.find((x) => x.key === key);
        return c ? c.actions.map((a) => a.name) : [];
    }

    function storeGet(key) { try { return localStorage.getItem(key); } catch (_) { return null; } }
    function storeSet(key, value) { try { localStorage.setItem(key, value); } catch (_) { /* private mode */ } }

    function reducedMotion() {
        try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (_) { return false; }
    }

    // A call `ms` after the last one. `now` calls at once; `flush` calls at once only if a call is
    // waiting.
    function debounce(fn, ms) {
        let t = null, last = [];
        const d = (...args) => { last = args; clearTimeout(t); t = setTimeout(() => { t = null; fn(...args); }, ms); };
        d.cancel = () => { clearTimeout(t); t = null; };
        d.now = (...args) => { clearTimeout(t); t = null; fn(...args); };
        d.flush = () => { if (t) { clearTimeout(t); t = null; fn(...last); } };
        return d;
    }

    async function copyText(text) {
        try {
            if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
        } catch (_) { /* fall back */ }
        const ta = el('textarea', 'act-copy-buffer');
        ta.value = text;
        ta.setAttribute('readonly', '');
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
        ta.remove();
        return ok;
    }

    function announce(text) {
        const r = $('act-announce');
        if (!r) return;
        r.textContent = '';
        setTimeout(() => { r.textContent = text; }, 30);
    }

    // ---- the server --------------------------------------------------------------------------------

    class RequestError extends Error {
        constructor(message, status, detail) { super(message); this.status = status; this.detail = detail; }
    }

    // A GET under /activity (or the session probe). A 401 is handed to the app's own sign-in handling;
    // a refusal for a temporary credential stops the page (see blockAsTemporary).
    async function get(path) {
        const resp = await fetch(API_BASE + path, { headers: { Authorization: `Bearer ${authToken}` } });
        if (resp.status === 401) {
            await apiRequest(path, { silent: true });          // the app signs out
            throw new RequestError('Your session has ended.', 401, null);
        }
        let data = null;
        try { data = await resp.json(); } catch (_) { data = null; }
        if (!resp.ok) {
            const detail = data && data.detail;
            const text = typeof detail === 'string' ? detail : `the server answered ${resp.status}`;
            const err = new RequestError(text, resp.status, detail);
            if (resp.status === 403) refused(err);
            throw err;
        }
        return data;
    }

    function refused(err) {
        const text = String(err.message || '');
        if (/temporary credential/i.test(text)) block('temp');
        else block('admin');
    }

    // ---- the range ---------------------------------------------------------------------------------

    // Where a preset starts, on the viewer's clock, as the server snaps it: the top of the hour 23 hours
    // ago, the six-hour block 27 blocks ago, midnight 29 days ago. The server's own start (the band's
    // `from`) replaces this once the band arrives; the two agree except in rare daylight-saving corners,
    // and then the list is read again with the server's.
    function presetStart(kind, now) {
        const d = new Date(now || Date.now());
        if (kind === '24h') {
            d.setMinutes(0, 0, 0);
            return new Date(d.getTime() - 23 * 3600 * 1000);
        }
        if (kind === '7d') {
            return new Date(d.getFullYear(), d.getMonth(), d.getDate(), Math.floor(d.getHours() / 6) * 6 - 27 * 6, 0, 0, 0);
        }
        return new Date(d.getFullYear(), d.getMonth(), d.getDate() - 29, 0, 0, 0, 0);
    }

    // The range's start and end as the list reads them (ISO instants, or null for none).
    function rangeBounds() { return rangeBoundsFor(S.range); }

    function rangeBoundsFor(r) {
        if (PRESETS.includes(r.kind)) {
            const snapped = presetStart(r.kind);
            // The band's start holds for as long as the block it was asked in: once a new hour, block
            // or day starts, the page's own start is newer until the band is read again.
            const b = S.bandFrom;
            const from = b && b.kind === r.kind && b.snap === snapped.getTime() ? b.from : iso(snapped);
            return { from, to: null };
        }
        if (r.kind === 'custom') return { from: r.from, to: r.to || null };
        return { from: null, to: r.to || null };                                   // all time
    }

    function rangeKey() { return [S.range.kind, S.range.from || '', S.range.to || ''].join('|'); }

    // A range is live when it ends now: every preset, and a chosen range without an end in the past.
    function rangeIsLive() {
        const to = S.range.kind === 'custom' || S.range.kind === 'all' ? toDate(S.range.to) : null;
        return !to || to.getTime() > Date.now();
    }

    function rangeName() {
        const r = S.range;
        if (RANGE_NAMES[r.kind] && !(r.kind === 'all' && r.to)) return RANGE_NAMES[r.kind];
        return 'this time range';
    }

    // A chosen range in short form for the header's fourth button: "12–20 Sep".
    function customShort() {
        const a = toDate(S.range.from), b = toDate(S.range.to);
        const now = new Date();
        if (a && b) {
            const end = new Date(b.getTime() - 1);
            if (sameDay(a, end)) return `${dayMonth(a)} ${hmText(a)}–${hmText(b)}`;
            if (a.getMonth() === end.getMonth() && a.getFullYear() === end.getFullYear()) {
                return `${a.getDate()}–${dayMonth(end, end.getFullYear() !== now.getFullYear())}`;
            }
            return `${dayMonth(a)} – ${dayMonth(end, end.getFullYear() !== now.getFullYear())}`;
        }
        if (a) return `From ${dayMonth(a, a.getFullYear() !== now.getFullYear())}`;
        if (b) return `Until ${dayMonth(b, b.getFullYear() !== now.getFullYear())}`;
        return 'All time';
    }

    function customLong() {
        const a = toDate(S.range.from), b = toDate(S.range.to);
        if (a && b) return `${fullWhen(a)} to ${fullWhen(b)}`;
        if (a) return `From ${fullWhen(a)} to now`;
        if (b) return `Everything until ${fullWhen(b)}`;
        return 'All time';
    }

    // ---- the filters as the API reads them --------------------------------------------------------

    // The categories and single events that are chosen. A category is chosen whole (`cat`) or through
    // some of its events (`act`), never both (see setCategory and setActions), so together they mean
    // "these categories, and these events": the API narrows by both at once, so each is widened by the
    // other's members.
    function catActInto(p, f) {
        const cat = f.cat, act = f.act;
        if (cat.length && act.length) {
            const cats = cat.slice();
            act.forEach((a) => { const c = actionCategory(a); if (c && !cats.includes(c)) cats.push(c); });
            const acts = act.slice();
            cat.forEach((c) => actionsOf(c).forEach((a) => { if (!acts.includes(a)) acts.push(a); }));
            cats.forEach((c) => p.append('category', c));
            acts.forEach((a) => p.append('action', a));
            return;
        }
        cat.forEach((c) => p.append('category', c));
        act.forEach((a) => p.append('action', a));
    }

    // Every filter but time: the list, the band, the export and the live fetches all take these.
    function filterParams(f) {
        const p = new URLSearchParams();
        catActInto(p, f);
        f.status.forEach((s) => p.append('status', s));
        f.ch.forEach((c) => p.append('channel', c));
        if (f.noAccount) p.set('no_account', 'true');
        else if (f.user) {
            p.set('user', f.user);
            if (f.userMatch === 'exact') p.set('user_match', 'exact');
        }
        if (f.ip) p.set('ip', f.ip);
        if (f.q) p.set('q', f.q);
        if (f.tcId) p.set('temp_credential_id', f.tcId);
        else if (f.tcName) p.set('temp_credential', f.tcName);
        if (f.vault) p.set('vault_id', f.vault);
        return p;
    }

    // The list's params: the filters, the range, and a time picked on the chart inside it.
    function listParams() { return listParamsFor(S.range, S.f); }

    function listParamsFor(range, f) {
        const p = filterParams(f);
        const r = rangeBoundsFor(range);
        let from = r.from, to = r.to;
        const t = f.time;
        if (t) {
            if (!from || new Date(t.from) > new Date(from)) from = t.from;
            if (!to || new Date(t.to) < new Date(to)) to = t.to;
        }
        if (from) p.set('from_date', from);
        if (to) p.set('to_date', to);
        return p;
    }

    // The categories a signalled row can belong to and still match: all of them, unless a Category or
    // Event filter is set.
    function signalCategories() {
        if (!S.f.cat.length && !S.f.act.length) return null;
        const out = new Set(S.f.cat);
        S.f.act.forEach((a) => { const c = actionCategory(a); if (c) out.add(c); else out.add('legacy'); });
        return out;
    }

    function activeFilterCount(f) {
        f = f || S.f;
        let n = 0;
        ['cat', 'act', 'status', 'ch'].forEach((k) => { if (f[k].length) n++; });
        if (f.user || f.noAccount) n++;
        if (f.ip) n++;
        if (f.tcId || f.tcName) n++;
        if (f.vault) n++;
        if (f.time) n++;
        return n;
    }

    function hasFilters(f) { f = f || S.f; return activeFilterCount(f) > 0 || !!f.q; }

    // ---- the URL hash ------------------------------------------------------------------------------
    // #activity?range=7d&cat=sign_in&status=failed&user=alex&ev=<id>. It stays in this browser, never
    // reaches the server, and is written with replaceState so filtering does not fill the history.

    function hashParams(withEvent) {
        const p = new URLSearchParams();
        const r = S.range;
        p.set('range', r.kind);
        if (r.kind === 'custom' || r.kind === 'all') {
            if (r.from) p.set('from', r.from);
            if (r.to) p.set('to', r.to);
        }
        const f = S.f;
        if (f.cat.length) p.set('cat', f.cat.join(','));
        if (f.act.length) p.set('act', f.act.join(','));
        if (f.status.length) p.set('status', f.status.join(','));
        if (f.ch.length) p.set('ch', f.ch.join(','));
        if (f.noAccount) p.set('noAccount', '1');
        else if (f.user) {
            p.set('user', f.user);
            if (f.userMatch === 'exact') p.set('userMatch', 'exact');
        }
        if (f.ip) p.set('ip', f.ip);
        if (f.tcId) p.set('tc', f.tcId);
        if (f.tcName) p.set('tcn', f.tcName);
        if (f.vault) p.set('vault', f.vault);
        if (f.time) p.set('t', `${f.time.from}~${f.time.to}`);
        if (f.q) p.set('q', f.q);
        if (S.pageSize !== 'all' && S.page > 1) p.set('page', String(S.page));
        if (withEvent && S.selectedId) p.set('ev', S.selectedId);
        return p;
    }

    function writeHash() {
        if (!S.active || S.blocked) return;
        const qs = hashParams(S.detailOpen).toString();
        try { history.replaceState(history.state, '', location.pathname + location.search + '#activity' + (qs ? '?' + qs : '')); }
        catch (_) { /* a sandboxed frame */ }
    }

    function dropHash() {
        if (!location.hash) return;
        try { history.replaceState(history.state, '', location.pathname + location.search); } catch (_) { /* ignore */ }
    }

    function linkToEvent(id) {
        const p = hashParams(false);
        p.set('ev', id);
        return location.origin + location.pathname + '#activity?' + p.toString();
    }

    const list = (v) => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : []);

    // The state a hash holds, or null when it is not an Activity hash.
    function readHash(hash) {
        if (!hash || !hash.startsWith('#activity')) return null;
        const q = hash.indexOf('?');
        const p = new URLSearchParams(q >= 0 ? hash.slice(q + 1) : '');
        const kind = p.get('range');
        const range = { kind: ['24h', '7d', '30d', 'all', 'custom'].includes(kind) ? kind : '7d', from: null, to: null };
        if (range.kind === 'custom' || range.kind === 'all') {
            range.from = toDate(p.get('from')) ? p.get('from') : null;
            range.to = toDate(p.get('to')) ? p.get('to') : null;
            if (range.kind === 'custom' && !range.from) range.kind = 'all';
        }
        const f = emptyFilters();
        f.cat = list(p.get('cat'));
        f.act = list(p.get('act'));
        f.status = list(p.get('status')).filter((s) => STATUS_CHOICES.some(([k]) => k === s));
        f.ch = list(p.get('ch')).filter((c) => CHANNELS.includes(c));
        f.noAccount = p.get('noAccount') === '1';
        if (!f.noAccount) {
            f.user = (p.get('user') || '').slice(0, 128);
            f.userMatch = p.get('userMatch') === 'exact' ? 'exact' : 'contains';
        }
        f.ip = (p.get('ip') || '').slice(0, 64);
        f.tcId = (p.get('tc') || '').slice(0, 64);
        f.tcName = (p.get('tcn') || '').slice(0, 128);
        f.vault = (p.get('vault') || '').slice(0, 64);
        f.q = (p.get('q') || '').slice(0, 128);
        const t = (p.get('t') || '').split('~');
        if (t.length === 2 && toDate(t[0]) && toDate(t[1])) f.time = { from: t[0], to: t[1] };
        const page = parseInt(p.get('page') || '1', 10);
        return { range, f, page: page > 0 ? page : 1, ev: p.get('ev') || null };
    }

    // ---- preferences on the account ---------------------------------------------------------------

    const savePrefs = debounce(() => {
        if (typeof saveUserPreference !== 'function' || S.blocked) return;
        const patch = { activity_page_size: S.pageSize };
        if (S.range.kind !== 'custom' && !(S.range.kind === 'all' && S.range.to)) patch.activity_range = S.range.kind;
        saveUserPreference(patch);
        if (state.userPreferences) Object.assign(state.userPreferences, patch);
    }, 1000);

    function pref(key) {
        const p = (typeof state !== 'undefined' && state.userPreferences) || {};
        return p[key];
    }

    // ---- setState: the one way the state changes ---------------------------------------------------

    const reloadSoon = debounce(() => { reloadList(); loadBand(); }, 300);

    // Apply a change to the range, the filters, the page size or the page, then redraw what reads them
    // and read the list and band again (300 ms after the last change). A change to anything but the page
    // starts again at page 1.
    function setState(patch, opts) {
        const o = opts || {};
        if (patch.range) {
            S.range = Object.assign({ from: null, to: null }, patch.range);
            S.f.time = null;                               // a picked time belongs to the old range
            if (!o.keepPrefs) savePrefs();
        }
        if (patch.f) S.f = Object.assign(S.f, patch.f);
        if (patch.pageSize) { S.pageSize = patch.pageSize; savePrefs(); }
        S.page = patch.page || 1;
        if (!o.keepUndo) S.undo = null;
        renderControls();
        writeHash();
        if (o.reload === false) return;
        clearKept();
        if (o.now) reloadSoon.now(); else reloadSoon();
    }

    // Everything that shows the state without being read from the server.
    function renderControls() {
        renderRange();
        renderChips();
        renderFilterButton();
        renderSavedButton();
        renderLive();
        renderPanelState();
        if (S.band) renderBand();
    }

    // ---- header ------------------------------------------------------------------------------------

    function renderRange() {
        const kind = S.range.kind;
        const chosen = PRESETS.includes(kind) ? kind : 'custom';
        document.querySelectorAll('#act-range [data-range]').forEach((b) => {
            const on = b.getAttribute('data-range') === chosen;
            b.classList.toggle('active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
            b.tabIndex = on ? 0 : -1;
        });
        const custom = $('act-range-custom');
        if (custom) {
            if (chosen === 'custom') {
                custom.textContent = customShort();
                custom.title = customLong();
            } else {
                custom.textContent = 'Custom…';
                custom.title = 'Choose a time range, or all time';
            }
        }
    }

    function wireRange() {
        const group = $('act-range');
        group.addEventListener('click', (e) => {
            const b = e.target.closest('[data-range]');
            if (!b) return;
            const kind = b.getAttribute('data-range');
            if (kind === 'custom') { openPanel('time'); return; }
            if (S.range.kind !== kind) setState({ range: { kind } });
        });
        group.addEventListener('keydown', (e) => {
            if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Home' && e.key !== 'End') return;
            const buttons = Array.from(group.querySelectorAll('[data-range]'));
            let i = buttons.indexOf(document.activeElement);
            if (i < 0) return;
            e.preventDefault();
            if (e.key === 'Home') i = 0;
            else if (e.key === 'End') i = buttons.length - 1;
            else i = (i + (e.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
            buttons[i].focus();
            const kind = buttons[i].getAttribute('data-range');
            if (kind !== 'custom' && S.range.kind !== kind) setState({ range: { kind } });
        });
    }

    // Menus in this page: one open at a time; a click elsewhere or Escape closes it.
    let openMenu = null;
    function toggleMenu(btn, menu, onOpen) {
        if (openMenu && openMenu.menu === menu) { closeMenu(); return; }
        closeMenu();
        closePopovers();
        if (onOpen) onOpen();
        menu.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        openMenu = { btn, menu };
        const first = menu.querySelector('button:not([disabled]), input');
        if (first) first.focus();
    }
    function closeMenu(returnFocus) {
        if (!openMenu) return false;
        const { btn, menu } = openMenu;
        menu.hidden = true;
        btn.setAttribute('aria-expanded', 'false');
        openMenu = null;
        if (returnFocus) btn.focus();
        return true;
    }
    function menuKeys(menu) {
        menu.addEventListener('keydown', (e) => {
            if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
            const items = Array.from(menu.querySelectorAll('button:not([disabled])'));
            let i = items.indexOf(document.activeElement);
            e.preventDefault();
            i = (i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
            if (items[i]) items[i].focus();
        });
    }

    function wireExport() {
        const btn = $('activity-export'), menu = $('act-export-menu');
        btn.addEventListener('click', () => { if (!btn.getAttribute('aria-disabled')) toggleMenu(btn, menu); });
        menuKeys(menu);
        menu.querySelectorAll('[data-activity-export]').forEach((b) => {
            b.addEventListener('click', () => { closeMenu(); exportEvents(b.getAttribute('data-activity-export')); });
        });
    }

    function renderExport() {
        const btn = $('activity-export');
        const empty = S.listLoaded && !S.rows.length && !S.listError;
        if (empty) {
            btn.setAttribute('aria-disabled', 'true');
            btn.title = 'Nothing to export: no events match.';
        } else {
            btn.removeAttribute('aria-disabled');
            btn.title = 'Export';
        }
    }

    // Every event that matches the filters, as a file. The server streams it, stops at its row limit and
    // says so in the last line; the headers carry both counts.
    async function exportEvents(fmt) {
        const btn = $('activity-export');
        const p = listParams();
        p.set('format', fmt);
        btn.setAttribute('aria-busy', 'true');
        try {
            const resp = await fetch(`${API_BASE}/activity/export?${p.toString()}`, {
                headers: { Authorization: `Bearer ${authToken}` },
            });
            if (resp.status === 403) {
                let data = null;
                try { data = await resp.json(); } catch (_) { /* no body */ }
                refused(new RequestError((data && data.detail) || 'Refused', 403, null));
                return;
            }
            if (!resp.ok) {
                // Say the server's reason: an export it could not record in the audit log is refused (503).
                let data = null;
                try { data = await resp.json(); } catch (_) { /* no body */ }
                throw new Error((data && typeof data.detail === 'string' && data.detail) || `the server answered ${resp.status}`);
            }
            const totalHeader = resp.headers.get('X-Export-Total');
            const total = Number(totalHeader || 0);
            const rows = Number(resp.headers.get('X-Export-Rows') || 0);
            const match = (resp.headers.get('Content-Disposition') || '').match(/filename=([^;]+)/);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = match ? match[1].trim() : `activity.${fmt}`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            if (totalHeader === null) showSuccess('Export downloaded');
            else if (rows < total) {
                showWarning(`Exported ${rows.toLocaleString()} of ${total.toLocaleString()} events, the most one export holds. Narrow the filters to export the rest.`);
            } else showSuccess(`Exported ${rows.toLocaleString()} ${rows === 1 ? 'event' : 'events'}`);
        } catch (err) {
            showError(`Export failed: ${err.message}`);
        } finally {
            btn.removeAttribute('aria-busy');
        }
    }

    // ---- chips -------------------------------------------------------------------------------------

    function plusMore(labels) {
        return labels.length > 1 ? `${labels[0]} +${labels.length - 1}` : labels[0];
    }

    // A vault chip is named from this viewer's own vault list, as the Vaults page names it (a locked
    // zero-knowledge vault by its label); a vault not in it is shown by the start of its id. A saved
    // search holds the id only. The app's list is not read yet when a link or a saved search opens the
    // page straight after signing in, so this viewer's own list is read once and the chip named again.
    let vaultNamesAsked = false;
    function vaultChipName(id) {
        const pool = [].concat((typeof state !== 'undefined' && state.allVaults) || [], S.vaultList || []);
        const v = pool.find((x) => x && String(x.id) === String(id));
        if (v) return typeof vaultDisplayName === 'function' ? vaultDisplayName(v) : (v.name || 'Vault');
        if (!S.vaultList && !vaultNamesAsked && S.active && !S.blocked) {
            vaultNamesAsked = true;
            vaultList().then(() => {
                vaultNamesAsked = false;
                if (S.active && !S.blocked) renderChips();
            });
        }
        return `name not shown (${String(id).slice(0, 6)})`;
    }

    // One chip per filter dimension: [text, title, panel section, what removing it clears].
    function chipList(f) {
        const out = [];
        if (f.cat.length) {
            const labels = f.cat.map(catLabel);
            out.push([`Category: ${plusMore(labels)}`, labels.join(', '), 'category', { cat: [] }]);
        }
        if (f.act.length) {
            const labels = f.act.map(actionLabel);
            out.push([`Event: ${plusMore(labels)}`, labels.join(', '), 'category', { act: [] }]);
        }
        if (f.status.length) {
            const labels = STATUS_CHOICES.filter(([k]) => f.status.includes(k)).map(([, l]) => l);
            out.push([`Status: ${labels.join(', ')}`, labels.join(', '), 'status', { status: [] }]);
        }
        if (f.ch.length) {
            const labels = CHANNELS.filter((c) => f.ch.includes(c)).map(channelLabel);
            out.push([`Channel: ${labels.join(', ')}`, labels.join(', '), 'channel', { ch: [] }]);
        }
        if (f.noAccount) {
            out.push(['Person: names with no account', "Names typed at failed sign-ins, deleted accounts, and the server's operator (operator@host)", 'person', { noAccount: false }]);
        } else if (f.user) {
            const t = f.userMatch === 'exact' ? `Person: ${f.user}` : `Person contains: ${f.user}`;
            out.push([t, t, 'person', { user: '', userMatch: 'contains' }]);
        }
        if (f.ip) out.push([`Address: ${f.ip}`, f.ip, 'address', { ip: '' }]);
        if (f.tcId || f.tcName) {
            const name = f.tcName || String(f.tcId).slice(0, 8);
            const t = f.tcId ? `Temporary credential: ${name}` : `Temporary credential contains: ${name}`;
            out.push([t, t, 'tc', { tcId: '', tcName: '' }]);
        }
        if (f.vault) {
            const t = `Vault: ${vaultChipName(f.vault)}`;
            out.push([t, t, 'vault', { vault: '' }]);
        }
        if (f.time) {
            const t = `Time: ${spanText(f.time.from, f.time.to)}`;
            out.push([t, t, 'time-pick', { time: null }]);
        }
        return out;
    }

    function renderChips() {
        const host = $('act-chips');
        if (!host) return;
        host.replaceChildren();
        if (S.savedLoaded) host.appendChild(el('span', 'act-chip-saved', `Saved search: ${S.savedLoaded.name}`));
        const chips = chipList(S.f);
        chips.forEach(([text, title, section, clear]) => {
            const chip = el('span', 'chip act-chip');
            chip.title = title;
            const body = button('act-chip-body', text);
            body.addEventListener('click', () => {
                if (section === 'time-pick') { focusChartSelection(); return; }
                openPanel(section);
            });
            const x = button('chip-remove act-chip-x', null, { 'aria-label': `Remove ${text}` });
            x.appendChild(icon('x'));
            x.addEventListener('click', () => {
                setState({ f: clear });
                const next = $('act-chips').querySelector('.act-chip-x');
                if (next) next.focus(); else $('act-search').focus();
            });
            chip.append(body, x);
            host.appendChild(chip);
        });
        if (chips.length >= 2) {
            const all = button('btn btn-ghost btn-sm act-clear-all', 'Clear all');
            all.addEventListener('click', () => clearAllFilters());
            host.appendChild(all);
        }
        host.hidden = !chips.length && !S.savedLoaded;
    }

    function clearAllFilters() {
        setState({ f: Object.assign(emptyFilters(), { q: S.f.q }) });
    }

    function renderFilterButton() {
        const n = activeFilterCount();
        const label = $('act-filter-label');
        const word = isNarrow() ? 'Filters' : 'Filter';
        if (label) label.textContent = n ? (isNarrow() ? `${word} ${n}` : `${word} · ${n}`) : word;
        const btn = $('act-filter-btn');
        if (btn) btn.classList.toggle('has-filters', n > 0);
    }

    // ---- search ------------------------------------------------------------------------------------

    const searchSoon = debounce(() => applySearch(), 400);

    function applySearch() {
        const v = ($('act-search').value || '').trim().slice(0, 128);
        if (v !== S.f.q) setState({ f: { q: v } });
    }

    function wireSearch() {
        const input = $('act-search');
        input.addEventListener('input', () => searchSoon());
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); searchSoon.cancel(); applySearch(); }
            else if (e.key === 'Escape' && input.value) {
                e.preventDefault();
                e.stopPropagation();
                input.value = '';
                searchSoon.cancel();
                applySearch();
            }
        });
    }

    // ---- the list ----------------------------------------------------------------------------------

    function isNarrow() { return S.layout === 'narrow'; }

    function whoText(ev) {
        const anonymous = ev.channel === 'public_link' || ev.channel === 'upload_link';
        if (ev.username) return { text: ev.username, quiet: false };
        if (anonymous) return { text: 'Someone with the link', quiet: true };
        if (ev.automatic) return { text: 'System', quiet: true };
        return { text: 'Unknown', quiet: true };
    }

    // The vault and the file or folder an event is about, named by the server for this viewer only.
    function namesText(ev) {
        const n = ev.names || {};
        return [n.vault, n.item && n.item !== n.vault ? n.item : null].filter(Boolean).join(' / ');
    }

    function statusNode(ev, plain) {
        const s = ev.status;
        if (s === 'success') return plain ? el('span', 'act-st-plain act-st-ok', 'Succeeded') : null;
        if (s === 'authorized') return plain ? el('span', 'act-st-plain act-st-allowed', 'Allowed') : null;
        return el('span', 'badge badge-' + auditStatusBadge(s), statusLabel(s));
    }

    function tempBadge(ev) {
        const b = el('span', 'badge badge-secondary act-temp', 'temporary');
        b.title = `Temporary credential: ${ev.temp_credential_name || ev.temp_credential_id}`;
        return b;
    }

    function ruleClass(ev) {
        if (isBad(ev)) return ' is-bad';
        if (ev.severity === 'warning') return ' is-warn';
        return '';
    }

    function dayLabel(d) {
        const today = new Date();
        const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
        const opts = isConsole() ? { weekday: 'short', day: 'numeric', month: 'short' } : { weekday: 'long', day: 'numeric', month: 'long' };
        if (d.getFullYear() !== today.getFullYear()) opts.year = 'numeric';
        const date = d.toLocaleDateString(undefined, opts);
        if (sameDay(d, today)) return `Today · ${date}`;
        if (sameDay(d, yesterday)) return `Yesterday · ${date}`;
        return date;
    }

    function tableRow(ev) {
        const tr = el('tr', 'act-row' + ruleClass(ev));
        tr.dataset.id = ev.id;
        tr.tabIndex = -1;
        const d = toDate(ev.timestamp);
        const time = el('td', 'act-c-time', d ? timeText(d) : '—');
        if (d) time.title = utcText(ev.timestamp);
        const evTd = el('td', 'act-c-ev');
        const evWrap = el('div', 'act-ev');
        evWrap.appendChild(el('span', 'act-ev-label', ev.label));
        const names = namesText(ev);
        if (names) {
            const n = el('span', 'act-ev-names', ` · ${names}`);
            n.title = names;
            evWrap.appendChild(n);
        }
        evTd.appendChild(evWrap);
        const whoTd = el('td', 'act-c-who');
        const who = whoText(ev);
        const whoWrap = el('div', 'act-who');
        const name = el('span', 'act-who-name' + (who.quiet ? ' is-quiet' : ''), who.text);
        name.title = who.text;
        whoWrap.appendChild(name);
        if (ev.temp_credential_id) whoWrap.appendChild(tempBadge(ev));
        whoTd.appendChild(whoWrap);
        const ch = el('td', 'act-c-ch');
        if (ev.channel) ch.textContent = channelLabel(ev.channel);
        else {
            const dash = el('span', 'act-none', '—');
            dash.title = 'Not recorded (before 0.33.0 or server work)';
            ch.appendChild(dash);
        }
        const ip = el('td', 'act-c-ip');
        if (ev.ip_address) {
            ip.textContent = midEllipsis(ev.ip_address, 18);
            ip.title = ev.ip_address;
        }
        const st = el('td', 'act-c-st');
        const sn = statusNode(ev, true);
        if (sn) st.appendChild(sn);
        tr.append(time, evTd, whoTd, ch, ip, st);
        return tr;
    }

    function cardRow(ev) {
        const li = el('li', 'act-card-item');
        const b = button('act-card' + ruleClass(ev));
        b.dataset.id = ev.id;
        b.tabIndex = -1;
        const l1 = el('span', 'act-card-l1');
        l1.appendChild(el('span', 'act-card-label', ev.label));
        const d = toDate(ev.timestamp);
        const t = el('span', 'act-card-time', d ? timeText(d) : '—');
        if (d) t.title = utcText(ev.timestamp);
        l1.appendChild(t);
        const l2 = el('span', 'act-card-l2');
        const who = whoText(ev);
        const parts = [who.text, ev.channel ? channelLabel(ev.channel) : null, ev.ip_address].filter(Boolean);
        const names = namesText(ev);
        if (names) parts.push(names);
        l2.appendChild(el('span', 'act-card-meta', parts.join(' · ')));
        if (ev.temp_credential_id) l2.appendChild(tempBadge(ev));
        const sn = statusNode(ev, false);
        if (sn) l2.appendChild(sn);
        b.append(l1, l2);
        li.appendChild(b);
        return li;
    }

    function dayRow(d, narrow) {
        if (narrow) return el('li', 'act-day', dayLabel(d));
        const tr = el('tr', 'act-day');
        const th = el('th', '', dayLabel(d));
        th.colSpan = 6;
        th.scope = 'colgroup';
        tr.appendChild(th);
        return tr;
    }

    function listHost() { return isNarrow() ? $('activity-cards') : $('activity-rows'); }
    function rowSelector() { return isNarrow() ? '.act-card' : 'tr.act-row'; }
    function rowNodes() { return Array.from(listHost().querySelectorAll(rowSelector())); }
    function rowNode(id) {
        if (!id) return null;
        return listHost().querySelector(`${rowSelector()}[data-id="${CSS.escape(id)}"]`);
    }

    // Draw the rows on screen. Only the layout in use is drawn: a table from a tablet up, a ruled list on
    // a phone. The focused row keeps its focus.
    function renderList(fresh) {
        const narrow = isNarrow();
        const table = $('activity-rows'), cards = $('activity-cards');
        const active = document.activeElement;
        const focusedId = active && active.dataset && active.dataset.id && listHost().contains(active) ? active.dataset.id : null;
        table.replaceChildren();
        cards.replaceChildren();
        $('act-table').hidden = narrow;
        cards.hidden = !narrow;
        const host = narrow ? cards : table;
        const frag = document.createDocumentFragment();
        if (!S.listLoaded) {
            if (narrow) frag.appendChild(el('li', 'act-loading', 'Loading events…'));
            else {
                const tr = el('tr', 'act-loading');
                const td = el('td', '', 'Loading events…');
                td.colSpan = 6;
                tr.appendChild(td);
                frag.appendChild(tr);
            }
        }
        let lastDay = null;
        S.rows.forEach((ev) => {
            const d = toDate(ev.timestamp);
            if (d) {
                const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
                if (key !== lastDay) { frag.appendChild(dayRow(d, narrow)); lastDay = key; }
            }
            frag.appendChild(narrow ? cardRow(ev) : tableRow(ev));
        });
        if (S.pageSize === 'all' && S.listLoaded && S.rows.length) frag.appendChild(allModeTail(narrow));
        host.appendChild(frag);
        renderEmpty();
        renderSelection();
        renderCount();
        renderPager();
        renderExport();
        setRovingRow();
        if (focusedId) {
            const again = rowNode(focusedId);
            if (again) again.focus({ preventScroll: true });
        }
        if (fresh && fresh.size) markNew(fresh);
        watchAllSentinel();
        fitDaySpans();
    }

    // A full-width row spans the columns on screen. The columns shown depend on the page's width and on
    // the detail being open (CSS), and a span over hidden columns would add empty ones to the table.
    function fitDaySpans() {
        const table = $('act-table');
        if (!table || table.hidden) return;
        const n = Array.from(table.querySelectorAll('thead th')).filter((th) => getComputedStyle(th).display !== 'none').length || 6;
        table.querySelectorAll('tbody tr.act-day > th, tbody tr.act-loading > td, tbody tr.act-more > td').forEach((c) => {
            if (c.colSpan !== n) c.colSpan = n;
        });
    }

    // The empty states: nothing recorded yet, nothing in the range, or nothing matches the filters.
    function renderEmpty() {
        const box = $('act-empty');
        box.replaceChildren();
        const empty = S.listLoaded && !S.rows.length && !S.listError;
        box.hidden = !empty;
        $('act-list').classList.toggle('is-empty', empty);
        if (!empty) return;
        const filtered = hasFilters();
        const allTime = S.range.kind === 'all' && !S.range.to;
        if (!filtered && allTime) {
            box.append(el('p', 'act-empty-title', 'No events recorded yet.'),
                el('p', 'act-empty-text', 'Sign-ins, file changes and administrator actions appear here as they happen.'));
            return;
        }
        const row = el('div', 'act-empty-actions');
        if (!filtered) {
            box.appendChild(el('p', 'act-empty-title', `No events in ${rangeName()}.`));
            const wider = WIDER[S.range.kind] || 'all';
            const b = button('btn btn-secondary btn-sm', wider === 'all' ? 'Show all time' : `Show ${RANGE_NAMES[wider]}`);
            b.addEventListener('click', () => setState({ range: { kind: wider } }));
            row.appendChild(b);
            box.appendChild(row);
            return;
        }
        box.appendChild(el('p', 'act-empty-title', `No events match these filters in ${rangeName()}.`));
        const clear = button('btn btn-secondary btn-sm', 'Clear filters');
        clear.addEventListener('click', () => setState({ f: emptyFilters() }));
        row.appendChild(clear);
        if (!allTime) {
            const all = button('btn btn-ghost btn-sm', 'Search all time');
            all.addEventListener('click', () => setState({ range: { kind: 'all' } }));
            row.appendChild(all);
        }
        box.appendChild(row);
    }

    function plural(n, one, many) { return `${nf(n)} ${n === 1 ? one : many}`; }

    function renderCount() {
        reconcileTotals();
        const c = $('activity-summary');
        if (!c) return;
        if (!S.listLoaded || !S.rows.length) { c.textContent = ''; return; }
        const n = S.rows.length;
        if (S.pageSize === 'all') {
            c.textContent = S.total == null ? `${nf(n)} shown` : `${nf(n)} of ${nf(S.total)} loaded`;
            return;
        }
        if (S.total == null) { c.textContent = `${nf(n)} shown`; return; }
        const first = (S.page - 1) * Number(S.pageSize) + 1;
        c.textContent = `${nf(first)}–${nf(first + n - 1)} of ${nf(S.total)}`;
    }

    // ---- paging ------------------------------------------------------------------------------------

    // 1, the current page and two either side, and the last; a page the server cannot open by number
    // (more than MAX_OFFSET rows from both ends) is left to the "…".
    function pageNumbers(current, last) {
        const size = Number(S.pageSize);
        const total = S.total || 0;
        const reachable = (n) => n === current || Math.min((n - 1) * size, total - n * size) <= MAX_OFFSET;
        const want = new Set([1, last]);
        for (let n = current - 2; n <= current + 2; n++) if (n >= 1 && n <= last) want.add(n);
        const nums = Array.from(want).filter(reachable).sort((a, b) => a - b);
        const out = [];
        nums.forEach((n, i) => {
            if (i && n - nums[i - 1] > 1) out.push(null);
            out.push(n);
        });
        return out;
    }

    function renderPager() {
        const pager = $('act-pager');
        pager.replaceChildren();
        const paged = S.pageSize !== 'all';
        const pages = S.pages || 1;
        const showNav = paged && S.listLoaded && S.rows.length > 0;
        const prevTop = $('act-prev'), nextTop = $('act-next');
        prevTop.hidden = !paged;
        nextTop.hidden = !paged;
        prevTop.disabled = !showNav || S.page <= 1;
        nextTop.disabled = !showNav || S.page >= pages;
        const left = el('div', 'act-pager-info');
        const mid = el('div', 'act-pager-nav');
        if (showNav) {
            const first = (S.page - 1) * Number(S.pageSize) + 1;
            if (S.total != null) left.textContent = `Showing ${nf(first)}–${nf(first + S.rows.length - 1)} of ${nf(S.total)}`;
            const prev = button('btn btn-ghost btn-sm act-pg-prev', null, { 'aria-label': 'Previous page' });
            prev.append(icon('chevron-left', 'icon-sm'), el('span', 'act-pg-word', 'Previous'));
            prev.disabled = S.page <= 1;
            prev.addEventListener('click', () => gotoPage(S.page - 1));
            const next = button('btn btn-ghost btn-sm act-pg-next', null, { 'aria-label': 'Next page' });
            next.append(el('span', 'act-pg-word', 'Next'), icon('chevron-right', 'icon-sm'));
            next.disabled = S.page >= pages;
            next.addEventListener('click', () => gotoPage(S.page + 1));
            mid.appendChild(prev);
            if (isNarrow()) {
                mid.appendChild(el('span', 'act-pg-where', `${nf(S.page)} of ${nf(pages)}`));
            } else {
                const nums = el('span', 'act-pg-nums');
                pageNumbers(S.page, pages).forEach((n) => {
                    if (n === null) { nums.appendChild(el('span', 'act-pg-gap', '…')); return; }
                    const b = button(`btn btn-sm ${n === S.page ? 'btn-secondary' : 'btn-ghost'} act-pg-num`, nf(n),
                        { 'aria-label': `Page ${n}` });
                    if (n === S.page) b.setAttribute('aria-current', 'page');
                    b.addEventListener('click', () => { if (n !== S.page) gotoPage(n); });
                    nums.appendChild(b);
                });
                mid.appendChild(nums);
            }
            mid.appendChild(next);
        }
        const right = el('label', 'act-pager-size');
        right.appendChild(el('span', '', 'Rows'));
        const sel = el('select', 'form-control act-page-size');
        sel.id = 'act-page-size';
        PAGE_SIZES.forEach((v) => {
            const o = el('option', '', v === 'all' ? 'All' : v);
            o.value = v;
            if (v === S.pageSize) o.selected = true;
            sel.appendChild(o);
        });
        sel.addEventListener('change', () => setState({ pageSize: sel.value }, { now: true }));
        right.appendChild(sel);
        pager.append(left, mid, right);
        pager.hidden = !S.listLoaded;
    }

    async function gotoPage(n, opts) {
        if (S.pageSize === 'all') return;
        const o = opts || {};
        const last = S.pages || 1;
        n = Math.max(1, Math.min(n, last));
        const forward = n === S.page + 1 && S.rows.length ? S.rows[S.rows.length - 1].cursor : null;
        S.page = n;
        writeHash();
        clearHeld();
        await reloadList({ cursor: forward, select: o.select, keepDetail: true });
        if (!o.select) {
            const top = $('act-list');
            if (top && top.getBoundingClientRect().top < 0) top.scrollIntoView({ block: 'start' });
        }
    }

    // ---- reading the list --------------------------------------------------------------------------

    function setBusy(on) {
        S.listBusy = on;
        const list = $('act-list');
        list.classList.toggle('is-busy', on && S.listLoaded);
        list.setAttribute('aria-busy', on ? 'true' : 'false');
    }

    // Read the list for the current state. A newer read replaces one in flight: only the latest reply is
    // shown. `cursor` continues after a row (moving to the next page); `select` picks the first or last
    // row of the page read (moving past the page's edge from the detail).
    async function reloadList(opts) {
        if (S.blocked || !S.active) return;
        const o = opts || {};
        const seq = ++S.listSeq;
        const params = listParams();
        const usedFrom = params.get('from_date');
        const all = S.pageSize === 'all';
        if (all) params.set('limit', String(ALL_STEP));
        else {
            params.set('page', String(S.page));
            params.set('limit', S.pageSize);
            if (o.cursor) params.set('cursor', o.cursor);
        }
        setBusy(true);
        const detailId = S.detailOpen && !o.keepDetail ? S.selectedId : null;
        try {
            const reads = [get('/activity/events?' + params.toString())];
            if (detailId) {
                const q = listParams();
                q.set('ids', detailId);
                reads.push(get('/activity/events?' + q.toString()).catch(() => null));
            }
            const [data, one] = await Promise.all(reads);
            if (seq !== S.listSeq) return;
            const stillMatches = detailId ? !!(one && one.events && one.events.length) : null;
            if (!all && data.pages && S.page > data.pages) {
                S.page = data.pages;
                writeHash();
                reloadList(Object.assign({}, o, { cursor: null }));
                return;
            }
            S.rows = data.events || [];
            S.total = data.total;
            S.pages = all ? null : (data.pages || 1);
            if (all) { S.allCursor = data.next_cursor || null; S.allDone = !data.next_cursor; S.allCap = ALL_CAP; }
            if (all || S.page === 1) {
                S.newestRow = null;
                S.newestCursor = null;
                noteNewest(S.rows);
                if (!S.newestCursor) S.newestCursor = data.head_cursor || null;
            }
            S.listFromUsed = usedFrom;
            S.lastRead = new Date();
            S.listLoaded = true;
            S.listError = null;
            clearHeld();
            renderListError();
            renderList();
            afterListRead(o, stillMatches);
        } catch (err) {
            if (seq !== S.listSeq || S.blocked) return;
            S.listError = err.message || 'unknown error';
            S.listLoaded = true;
            renderListError();
            renderList();
        } finally {
            if (seq === S.listSeq) setBusy(false);
        }
    }

    function renderListError() {
        const box = $('act-list-alert');
        box.replaceChildren();
        box.hidden = !S.listError;
        if (!S.listError) return;
        box.appendChild(el('span', '', `Events could not be loaded: ${S.listError.replace(/\.$/, '')}.`));
        const again = button('btn btn-secondary btn-sm', 'Try again');
        again.addEventListener('click', () => reloadList());
        box.appendChild(again);
    }

    // After a read: keep the detail on its event when it still matches; move the selection when the read
    // was a step past the page's edge.
    function afterListRead(o, stillMatches) {
        if (o.select === 'first' && S.rows.length) { select(S.rows[0].id, { open: S.detailOpen, focus: true }); return; }
        if (o.select === 'last' && S.rows.length) { select(S.rows[S.rows.length - 1].id, { open: S.detailOpen, focus: true }); return; }
        if (!S.detailOpen || !S.selectedId) return;
        const i = S.rows.findIndex((r) => r.id === S.selectedId);
        if (i >= 0) { S.detail = S.rows[i]; S.detailWhere = null; renderDetail(); return; }
        if (stillMatches === false) { closeDetail(false); return; }
        if (stillMatches === true) S.detailWhere = 'later';
        renderDetail();
    }

    // "All": 100 rows at a time as the end of the list comes into view, up to 5,000 unless asked for more.
    function allModeTail(narrow) {
        const node = el(narrow ? 'li' : 'tr', 'act-more');
        const box = narrow ? node : el('td');
        if (!narrow) { box.colSpan = 6; node.appendChild(box); }
        if (!S.allDone && S.rows.length >= S.allCap) {
            box.appendChild(el('span', '', `${nf(S.rows.length)} events loaded. More would slow this page down: narrow the filters or export them.`));
            const more = button('btn btn-ghost btn-sm', 'Load 1,000 more anyway');
            more.addEventListener('click', () => { S.allCap = S.rows.length + ALL_MORE; renderList(); loadMore(); });
            box.appendChild(more);
            node.classList.add('is-capped');
        } else if (!S.allDone) {
            box.textContent = 'Loading more events…';
            node.classList.add('is-sentinel');
        } else {
            const n = S.total != null ? S.total : S.rows.length;
            box.textContent = `That's all: ${plural(n, 'event matches', 'events match')}.`;
        }
        return node;
    }

    let allObserver = null;
    function watchAllSentinel() {
        if (allObserver) { allObserver.disconnect(); allObserver = null; }
        const sentinel = listHost().querySelector('.act-more.is-sentinel');
        if (!sentinel || typeof IntersectionObserver !== 'function') return;
        allObserver = new IntersectionObserver((entries) => {
            if (entries.some((e) => e.isIntersecting)) loadMore();
        }, { rootMargin: '200px 0px' });
        allObserver.observe(sentinel);
    }

    async function loadMore() {
        if (S.pageSize !== 'all' || S.allDone || S.allLoading || !S.allCursor || S.rows.length >= S.allCap) return false;
        S.allLoading = true;
        const seq = S.listSeq;
        try {
            const p = listParams();
            p.set('limit', String(ALL_STEP));
            p.set('cursor', S.allCursor);
            const data = await get('/activity/events?' + p.toString());
            if (seq !== S.listSeq) return false;
            const have = new Set(S.rows.map((r) => r.id));
            S.rows = S.rows.concat((data.events || []).filter((r) => !have.has(r.id)));
            S.allCursor = data.next_cursor || null;
            S.allDone = !data.next_cursor;
            renderList();
            return true;
        } catch (err) {
            if (!S.blocked) { S.listError = err.message; renderListError(); }
            return false;
        } finally {
            S.allLoading = false;
        }
    }

    // ---- selection and the keyboard ----------------------------------------------------------------

    function renderSelection() {
        rowNodes().forEach((n) => {
            const on = n.dataset.id === S.selectedId;
            n.classList.toggle('is-selected', on);
            if (on) n.setAttribute('aria-current', 'true');
            else n.removeAttribute('aria-current');
        });
    }

    // The list is one tab stop: the selected row, else the first.
    function setRovingRow() {
        const nodes = rowNodes();
        if (!nodes.length) return;
        const pick = nodes.find((n) => n.dataset.id === S.selectedId) || nodes[0];
        nodes.forEach((n) => { n.tabIndex = n === pick ? 0 : -1; });
    }

    function indexOfSelected() { return S.rows.findIndex((r) => r.id === S.selectedId); }

    function select(id, opts) {
        const o = opts || {};
        S.selectedId = id;
        const ev = S.rows.find((r) => r.id === id);
        if (ev) { S.detail = ev; S.detailWhere = null; S.detailMissing = false; S.detailEdge = { newer: false, older: false }; }
        renderSelection();
        setRovingRow();
        const node = rowNode(id);
        if (node && o.focus) {
            node.focus({ preventScroll: true });
            node.scrollIntoView({ block: 'nearest' });
        } else if (node && o.scroll) node.scrollIntoView({ block: 'nearest' });
        if (o.open) openDetail();
        else if (S.detailOpen) renderDetail();
        if (o.byKey && S.detailOpen && ev) {
            announce(`Showing ${ev.label}, ${positionText()}.`);
        }
        writeHash();
    }

    function focusInList() {
        const a = document.activeElement;
        return !!(a && $('act-list').contains(a));
    }

    function wireList() {
        const list = $('act-list');
        list.addEventListener('click', (e) => {
            const row = e.target.closest('tr.act-row, .act-card');
            if (!row || !list.contains(row)) return;
            select(row.dataset.id, { open: true, focus: true });
        });
        list.addEventListener('keydown', (e) => {
            S.lastKey = Date.now();
            const row = e.target.closest('tr.act-row, .act-card');
            if (!row) return;
            if (e.altKey || e.ctrlKey || e.metaKey) return;
            const nodes = rowNodes();
            const i = nodes.indexOf(row);
            const go = (j) => {
                const n = nodes[Math.max(0, Math.min(j, nodes.length - 1))];
                if (n) select(n.dataset.id, { focus: true, byKey: true });
            };
            switch (e.key) {
                case 'ArrowDown': case 'j':
                    e.preventDefault();
                    if (S.detailOpen || i === nodes.length - 1) { if (row.dataset.id !== S.selectedId) select(row.dataset.id, {}); step(1, true); } else go(i + 1);
                    break;
                case 'ArrowUp': case 'k':
                    e.preventDefault();
                    if (S.detailOpen || i === 0) { if (row.dataset.id !== S.selectedId) select(row.dataset.id, {}); step(-1, true); } else go(i - 1);
                    break;
                case 'Home': e.preventDefault(); go(0); break;
                case 'End': e.preventDefault(); go(nodes.length - 1); break;
                case 'Enter':
                    if (row.tagName === 'BUTTON') return;                 // a phone row is a button: its click opens it
                    e.preventDefault();
                    select(row.dataset.id, { open: true, focus: true });
                    break;
                case 'PageDown': if (S.pageSize !== 'all' && S.page < (S.pages || 1)) { e.preventDefault(); gotoPage(S.page + 1); } break;
                case 'PageUp': if (S.pageSize !== 'all' && S.page > 1) { e.preventDefault(); gotoPage(S.page - 1); } break;
                case '/': e.preventDefault(); $('act-search').focus(); break;
                default: break;
            }
        });
        // What the live list needs to know: is someone about to click, or reading with the keys?
        list.addEventListener('pointermove', () => { S.lastPointer = Date.now(); });
        list.addEventListener('pointerdown', () => { S.pointerDown = true; S.lastPointer = Date.now(); });
        document.addEventListener('pointerup', () => { if (S.pointerDown) { S.pointerDown = false; S.lastPointer = Date.now(); } });
        list.addEventListener('pointerleave', () => { S.lastPointer = 0; S.pointerDown = false; flushHeldSoon(); });
        $('act-prev').addEventListener('click', () => gotoPage(S.page - 1));
        $('act-next').addEventListener('click', () => gotoPage(S.page + 1));
    }

    // Move to the next (older, +1) or previous (newer, -1) event, across the page's edge, and from an
    // event that is not in the list, by keyset under the current filters.
    let stepping = false;
    async function step(dir, byKey) {
        if (stepping) return;
        stepping = true;
        try {
            const i = indexOfSelected();
            const focus = byKey && focusInList();
            if (i >= 0) {
                const j = i + dir;
                if (j >= 0 && j < S.rows.length) { select(S.rows[j].id, { focus, byKey, scroll: true }); return; }
                if (S.pageSize === 'all') {
                    if (dir > 0 && await loadMore() && S.rows[j]) select(S.rows[j].id, { focus, byKey, scroll: true });
                    return;
                }
                if (dir > 0 && S.page < (S.pages || 1)) { await gotoPage(S.page + 1, { select: 'first' }); return; }
                if (dir < 0 && S.page > 1) { await gotoPage(S.page - 1, { select: 'last' }); return; }
                return;
            }
            if (!S.detail || !S.detail.cursor) return;
            const p = listParams();
            p.set(dir > 0 ? 'cursor' : 'after', S.detail.cursor);
            p.set('limit', '1');
            const data = await get('/activity/events?' + p.toString());
            const n = (data.events || [])[0];
            if (!n) {
                S.detailEdge[dir > 0 ? 'older' : 'newer'] = true;
                renderDetail();
                return;
            }
            if (S.rows.some((r) => r.id === n.id)) { select(n.id, { focus, byKey, scroll: true }); return; }
            S.selectedId = n.id;
            S.detail = n;
            S.detailEdge = { newer: false, older: false };
            renderSelection();
            renderDetail();
            writeHash();
            if (byKey) announce(`Showing ${n.label}, ${positionText()}.`);
        } catch (err) {
            if (!S.blocked) showError(`The next event could not be loaded: ${err.message}`);
        } finally {
            stepping = false;
        }
    }

    // ---- the detail --------------------------------------------------------------------------------

    function positionText() {
        const i = indexOfSelected();
        if (i >= 0) return S.pageSize === 'all' ? `${nf(i + 1)} of ${nf(S.rows.length)} loaded` : `${nf(i + 1)} of ${nf(S.rows.length)}`;
        if (S.detailWhere === 'later') return 'On a later page';
        if (typeof S.detailWhere === 'number') return `On page ${nf(S.detailWhere)}`;
        return 'Not in the list below';
    }

    function edgeState() {
        const i = indexOfSelected();
        if (i < 0) return { newer: S.detailEdge.newer, older: S.detailEdge.older };
        const lastPage = S.pageSize === 'all' ? S.allDone : S.page >= (S.pages || 1);
        return {
            newer: i === 0 && (S.pageSize === 'all' || S.page === 1),
            older: i === S.rows.length - 1 && lastPage,
        };
    }

    function statusGroup(status) {
        if (status === 'success' || status === 'authorized') return status;
        if (BAD_STATUSES.has(status)) return 'failed';
        return null;
    }

    function vaultIdOf(ev) {
        if (ev.resource_type === 'vault' && ev.resource_id) return ev.resource_id;
        const d = ev.details;
        return d && typeof d === 'object' && d.vault_id ? String(d.vault_id) : null;
    }

    function cidrOf(ip) {
        if (!ip) return null;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split('.').slice(0, 3).join('.') + '.0/24';
        if (ip.includes(':')) {
            const full = expandV6(ip);
            if (!full) return null;
            return full.slice(0, 4).map((h) => h.replace(/^0+(?=.)/, '')).join(':') + '::/64';
        }
        return null;
    }

    function expandV6(ip) {
        const main = ip.split('%')[0];
        if (main.includes('.')) return null;
        const halves = main.split('::');
        if (halves.length > 2) return null;
        const head = halves[0] ? halves[0].split(':') : [];
        const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
        const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
        const parts = head.concat(Array(Math.max(0, fill)).fill('0'), tail);
        return parts.length === 8 ? parts : null;
    }

    // A filter link in the detail: it sets that one dimension, keeping the others.
    function detailFilter(label, patch, extraCls) {
        const b = button('act-d-filter' + (extraCls ? ' ' + extraCls : ''), null, { 'aria-label': label, title: label });
        b.appendChild(icon('filter'));
        b.addEventListener('click', () => {
            if (patch.act) patch = actionsPatch(patch.act, true);
            else if (patch.cat) patch = categoryPatch(patch.cat, true);
            setState({ f: patch });
        });
        return b;
    }

    function field(dl, label, value, actions, cls) {
        if (value == null || value === '') return;
        const dt = el('dt', '', label);
        const dd = el('dd', cls || '');
        if (typeof value === 'string') dd.appendChild(el('span', 'act-d-value', value));
        else dd.appendChild(value);
        (actions || []).forEach((a) => { if (a) dd.appendChild(a); });
        dl.append(dt, dd);
    }

    function section(title) {
        const sec = el('section', 'act-d-sec');
        sec.appendChild(el('h4', 'act-d-sec-title', title));
        const dl = el('dl', 'act-d-fields');
        sec.appendChild(dl);
        return { sec, dl };
    }

    // The detail's sections: who, what, the request, when, and the recorded details.
    function detailBody(ev) {
        const frag = document.createDocumentFragment();
        const who = section('Who');
        const w = whoText(ev);
        field(who.dl, 'Person', el('span', 'act-d-value' + (w.quiet ? ' is-quiet' : ''), w.text),
            [ev.username ? detailFilter("Show this person's events", { user: ev.username, userMatch: 'exact', noAccount: false }) : null]);
        if (ev.temp_credential_id) {
            const name = ev.temp_credential_name || String(ev.temp_credential_id).slice(0, 8);
            const known = S.tcStates[ev.temp_credential_id];
            if (known === undefined && ev.temp_credential_name) lookupTcState(ev.temp_credential_id, ev.temp_credential_name);
            field(who.dl, 'Temporary credential', known ? `${name} · ${known}` : name,
                [detailFilter("Show this credential's events", { tcId: ev.temp_credential_id, tcName: ev.temp_credential_name || '' })]);
        }
        if (ev.ip_address) {
            const cidr = cidrOf(ev.ip_address);
            const actions = [detailFilter('Show events from this address', { ip: ev.ip_address })];
            if (cidr) {
                const net = button('btn btn-ghost btn-sm act-d-net', cidr.includes(':') ? '/64' : '/24',
                    { 'aria-label': `Show events from this network (${cidr})`, title: `Show events from this network (${cidr})` });
                net.addEventListener('click', () => setState({ f: { ip: cidr } }));
                actions.push(net);
            }
            field(who.dl, 'Address', el('span', 'act-d-value act-mono', ev.ip_address), actions);
        }
        field(who.dl, 'Channel', channelLabel(ev.channel),
            [detailFilter('Show events on this channel', { ch: [ev.channel || 'unknown'] })]);
        if (ev.user_agent) {
            const ua = el('span', 'act-d-value act-mono act-d-ua is-clamped', ev.user_agent);
            const wrap = el('span', 'act-d-ua-wrap');
            wrap.appendChild(ua);
            if (ev.user_agent.length > 80) {
                const all = button('act-link-btn', 'Show all');
                all.addEventListener('click', () => { ua.classList.remove('is-clamped'); all.remove(); });
                wrap.appendChild(all);
            }
            field(who.dl, 'Browser or client', wrap);
        }
        frag.appendChild(who.sec);

        const what = section('What');
        field(what.dl, 'Event', ev.label, [detailFilter('Show only this event type', { act: [ev.action] })]);
        field(what.dl, 'Category', catLabel(ev.category), [detailFilter('Show this category', { cat: [ev.category] })]);
        const st = el('span', 'act-d-value');
        st.appendChild(el('span', '', statusLabel(ev.status)));
        if (ev.error_message) st.appendChild(el('span', 'act-d-error', ev.error_message));
        const group = statusGroup(ev.status);
        field(what.dl, 'Status', st, [group ? detailFilter('Show events with this status', { status: [group] }) : null]);
        const names = ev.names || {};
        const vid = vaultIdOf(ev);
        if (names.vault || vid) {
            field(what.dl, 'Vault', names.vault || 'Not shown',
                [vid ? detailFilter('Show events for this vault', { vault: vid }) : null]);
        }
        if (names.item) field(what.dl, ev.resource_type === 'folder' ? 'Folder' : 'File', names.item);
        if (ev.resource_type) {
            const text = `${ev.resource_type} ${ev.resource_id || ''}`.trim();
            const copy = button('act-d-filter', null, { 'aria-label': 'Copy', title: 'Copy' });
            copy.appendChild(icon('copy'));
            copy.addEventListener('click', async () => { if (await copyText(ev.resource_id || text)) showSuccess('Copied.'); });
            field(what.dl, 'Affected', el('span', 'act-d-value act-mono', text), [ev.resource_id ? copy : null]);
        }
        frag.appendChild(what.sec);

        if (ev.endpoint) {
            const req = section('Request');
            field(req.dl, 'Request', el('span', 'act-d-value act-mono', ev.method ? `${ev.method} ${ev.endpoint}` : ev.endpoint));
            frag.appendChild(req.sec);
        }

        const when = section('When');
        const d = toDate(ev.timestamp);
        if (d) {
            field(when.dl, 'Local time', fullWhen(d));
            field(when.dl, 'UTC', el('span', 'act-d-value act-mono', utcText(ev.timestamp)));
        }
        frag.appendChild(when.sec);

        const det = el('details', 'act-d-sec act-d-raw');
        det.open = storeGet('activity.detailsOpen') === '1';
        det.addEventListener('toggle', () => storeSet('activity.detailsOpen', det.open ? '1' : '0'));
        const sum = el('summary', 'act-d-raw-sum');
        // The summary is a flex row, which drops the browser's own marker: a chevron says it opens.
        sum.append(icon('chevron-right', 'act-d-raw-chev'), el('span', 'act-d-sec-title', 'Recorded details'));
        const hasDetails = ev.details && typeof ev.details === 'object' && Object.keys(ev.details).length;
        const json = hasDetails ? JSON.stringify(ev.details, null, 2) : '';
        if (hasDetails) {
            const copy = button('act-link-btn act-d-raw-copy', 'Copy');
            copy.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (await copyText(json)) showSuccess('Copied.');
            });
            sum.appendChild(copy);
        }
        det.appendChild(sum);
        if (hasDetails) det.appendChild(el('pre', 'act-d-json', json));
        det.appendChild(el('p', 'act-d-stored', `Stored as ${ev.action} · id ${String(ev.id).slice(0, 8)}…`));
        frag.appendChild(det);
        return frag;
    }

    // A temporary credential's state for the detail ("active · expires 30 Sep", "expired 12 Sep",
    // "revoked"), looked up once by its name; a deleted credential has none.
    function tcStateText(t) {
        const exp = toDate(t.expires_at);
        if (t.state === 'active') return exp ? `active · expires ${dayMonth(exp)}` : 'active';
        if (t.state === 'expired') return exp ? `expired ${dayMonth(exp)}` : 'expired';
        return 'revoked';
    }

    async function lookupTcState(id, name) {
        if (id in S.tcStates || String(name).length < 2) return;
        S.tcStates[id] = null;
        try {
            const d = await get(`/activity/temp-credentials?q=${encodeURIComponent(String(name).slice(0, 64))}&limit=20`);
            const t = (d.temp_credentials || []).find((x) => String(x.id) === String(id));
            if (!t) return;
            S.tcStates[id] = tcStateText(t);
            if (S.detailOpen && S.detail && S.detail.temp_credential_id === id) renderDetail();
        } catch (_) { /* the name alone is shown */ }
    }

    function titleWithBadge(tag, id, ev) {
        const h = el(tag, 'act-d-title');
        h.id = id;
        h.appendChild(el('span', 'act-d-title-text', ev ? ev.label : 'Event'));
        if (ev && ev.status !== 'success' && ev.status !== 'authorized') {
            const b = statusNode(ev, false);
            if (b) h.appendChild(b);
        }
        return h;
    }

    function whenLine(ev) {
        const d = toDate(ev.timestamp);
        return d ? `${fullWhen(d)} · ${ago(d)}` : '';
    }

    function navButtons(phone) {
        const e = edgeState();
        const newer = button('btn btn-secondary btn-sm act-d-newer', null,
            { 'aria-keyshortcuts': 'K ArrowUp', 'data-fkey': 'd-newer' });
        newer.append(icon(phone ? 'chevron-left' : 'chevron-up', 'icon-sm'), el('span', '', 'Newer'));
        const older = button('btn btn-secondary btn-sm act-d-older', null,
            { 'aria-keyshortcuts': 'J ArrowDown', 'data-fkey': 'd-older' });
        if (phone) older.append(el('span', '', 'Older'), icon('chevron-right', 'icon-sm'));
        else older.append(icon('chevron-down', 'icon-sm'), el('span', '', 'Older'));
        newer.disabled = e.newer;
        older.disabled = e.older;
        if (e.newer) newer.title = 'This is the newest event that matches.';
        if (e.older) older.title = 'This is the oldest event that matches.';
        newer.addEventListener('click', () => step(-1, false));
        older.addEventListener('click', () => step(1, false));
        return [newer, older];
    }

    function aroundButton() {
        const b = button('btn btn-secondary btn-sm act-d-around', 'Events around this time');
        b.addEventListener('click', () => aroundThisTime(S.detail));
        return b;
    }

    function renderDetail() {
        if (!S.detailOpen) return;
        if (isNarrow()) renderPhoneDetail();
        else { renderPane(); fitOverlays(); }
    }

    // Draw the detail again, keeping the focus on the same control (Newer, Older) when it was in it.
    function keepFocus(box, draw) {
        const key = focusKeyIn(box);
        draw();
        if (!key) return;
        const n = box.querySelector(`[data-fkey="${key}"]`);
        if (n && !n.disabled) n.focus({ preventScroll: true });
        else {
            const other = box.querySelector('.act-d-newer:not([disabled]), .act-d-older:not([disabled]), .act-sheet-back, .act-d-close');
            if (other) other.focus({ preventScroll: true });
        }
    }

    function renderPane() { keepFocus($('act-detail'), drawPane); }

    function drawPane() {
        const pane = $('act-detail');
        pane.hidden = false;
        pane.replaceChildren();
        const inner = el('div', 'act-detail-inner');
        const head = el('div', 'act-d-head');
        const ev = S.detail;
        if (S.detailMissing || !ev) {
            head.appendChild(titleWithBadge('h3', 'act-detail-title', null));
            inner.appendChild(head);
            const body = el('div', 'act-d-body');
            body.appendChild(el('p', 'act-d-missing', 'This event could not be found.'));
            const close = button('btn btn-secondary btn-sm', 'Close details');
            close.addEventListener('click', () => closeDetail(true));
            body.appendChild(close);
            inner.appendChild(body);
            pane.appendChild(inner);
            return;
        }
        head.appendChild(titleWithBadge('h3', 'act-detail-title', ev));
        head.appendChild(el('p', 'act-d-when', whenLine(ev)));
        const tools = el('div', 'act-d-tools');
        navButtons(false).forEach((b) => tools.appendChild(b));
        tools.appendChild(el('span', 'act-d-pos', positionText()));
        const link = button('act-d-icon', null, { 'aria-label': 'Copy link to this event', title: 'Copy link to this event' });
        link.appendChild(icon('link'));
        link.addEventListener('click', () => copyLink(ev.id));
        const close = button('act-d-icon act-d-close', null, { 'aria-label': 'Close details', title: 'Close details' });
        close.appendChild(icon('x'));
        close.addEventListener('click', () => closeDetail(true));
        tools.append(link, close);
        head.appendChild(tools);
        inner.appendChild(head);
        const body = el('div', 'act-d-body');
        body.appendChild(detailBody(ev));
        inner.appendChild(body);
        const foot = el('div', 'act-d-foot');
        foot.appendChild(aroundButton());
        foot.appendChild(el('p', 'act-d-hint', '↑↓ or j k to move · Esc to close'));
        inner.appendChild(foot);
        pane.appendChild(inner);
    }

    async function copyLink(id) {
        if (await copyText(linkToEvent(id))) showSuccess('Link copied.');
        else showError('The link could not be copied.');
    }

    function openDetail() {
        S.detailOpen = true;
        $('act-body').classList.add('has-detail');
        fitDaySpans();
        if (isNarrow()) { $('act-detail').hidden = true; openPhoneDetail(); }
        else closePhoneDetail(false);
        renderDetail();
        writeHash();
    }

    function closeDetail(returnFocus) {
        if (!S.detailOpen) return;
        S.detailOpen = false;
        S.detailMissing = false;
        $('act-body').classList.remove('has-detail');
        fitDaySpans();
        const pane = $('act-detail');
        pane.hidden = true;
        pane.replaceChildren();
        closePhoneDetail(false);
        writeHash();
        const node = rowNode(S.selectedId);
        if (node) {
            node.scrollIntoView({ block: 'nearest' });
            if (returnFocus) node.focus({ preventScroll: true });
        }
        flushHeldSoon();
    }

    // "Events around this time": five minutes either side, no filters, the same event shown. Undo puts
    // the range and filters back.
    function aroundThisTime(ev) {
        const t = ev && toDate(ev.timestamp);
        if (!t) return;
        const before = { range: Object.assign({}, S.range), f: JSON.parse(JSON.stringify(S.f)) };
        const from = new Date(t.getTime() - 5 * 60 * 1000), to = new Date(t.getTime() + 5 * 60 * 1000);
        setState({ range: { kind: 'custom', from: iso(from), to: iso(to) }, f: emptyFilters() }, { keepPrefs: true });
        const toast = showToast(`Showing all events from ${hmText(from)} to ${hmText(to)}.`, 'info', 10000);
        if (!toast) return;
        const undo = button('btn btn-ghost btn-sm act-toast-undo', 'Undo');
        undo.addEventListener('click', () => {
            toast.remove();
            setState({ range: before.range, f: before.f }, { keepPrefs: true });   // the filters' picked time too
        });
        const content = toast.querySelector('.toast-content') || toast;
        content.appendChild(undo);
    }

    // ---- the detail on a phone: full screen, with Newer and Older, closed by Back ------------------

    let phonePushed = false;
    let ignorePop = false;

    function openPhoneDetail() {
        const m = $('activity-event-modal');
        if (m.classList.contains('active')) return;
        openModal('activity-event-modal');
        m.dataset.actOpen = '1';
        try { history.pushState({ activityDetail: true }, '', location.href); phonePushed = true; } catch (_) { phonePushed = false; }
        setTimeout(() => { const b = m.querySelector('.act-sheet-back'); if (b) b.focus(); }, 0);
    }

    function closePhoneDetail(fromPop) {
        const m = $('activity-event-modal');
        if (!m.classList.contains('active') && !m.dataset.actOpen) return;
        delete m.dataset.actOpen;
        m.classList.remove('active');
        if (phonePushed && !fromPop) { ignorePop = true; history.back(); }
        phonePushed = false;
    }

    function renderPhoneDetail() { keepFocus($('activity-event-modal'), drawPhoneDetail); }

    function drawPhoneDetail() {
        const m = $('activity-event-modal');
        const box = m.querySelector('.modal-content');
        box.replaceChildren();
        const ev = S.detail;
        const top = el('div', 'act-sheet-top');
        const back = button('btn btn-ghost btn-sm act-sheet-back', null, { 'aria-label': 'Back to the events' });
        back.append(icon('chevron-left', 'icon-sm'), el('span', '', 'Events'));
        back.addEventListener('click', () => closeDetail(true));
        top.appendChild(back);
        top.appendChild(el('span', 'act-sheet-pos', ev && !S.detailMissing ? positionText() : ''));
        if (ev && !S.detailMissing) {
            const wrap = el('div', 'menu-wrap act-sheet-menu');
            const more = button('btn btn-ghost btn-sm act-sheet-more', null, { 'aria-label': 'More', 'aria-haspopup': 'true', 'aria-expanded': 'false' });
            more.appendChild(icon('more'));
            const menu = el('div', 'dropdown-menu act-sheet-dropdown');
            menu.setAttribute('role', 'menu');
            menu.hidden = true;
            const copy = button('', 'Copy link to this event', { role: 'menuitem' });
            copy.addEventListener('click', () => { closeMenu(); copyLink(ev.id); });
            const around = button('', 'Events around this time', { role: 'menuitem' });
            around.addEventListener('click', () => { closeMenu(); aroundThisTime(ev); });
            menu.append(copy, around);
            menuKeys(menu);
            more.addEventListener('click', () => toggleMenu(more, menu));
            wrap.append(more, menu);
            top.appendChild(wrap);
        }
        box.appendChild(top);
        const body = el('div', 'act-sheet-body');
        if (!ev || S.detailMissing) {
            body.appendChild(titleWithBadge('h2', 'activity-event-title', null));
            body.appendChild(el('p', 'act-d-missing', 'This event could not be found.'));
        } else {
            body.appendChild(titleWithBadge('h2', 'activity-event-title', ev));
            body.appendChild(el('p', 'act-d-when', whenLine(ev)));
            body.appendChild(detailBody(ev));
        }
        box.appendChild(body);
        if (ev && !S.detailMissing) {
            const bottom = el('div', 'act-sheet-bottom');
            navButtons(true).forEach((b) => bottom.appendChild(b));
            box.appendChild(bottom);
        }
    }

    function wirePhoneDetail() {
        const m = $('activity-event-modal');
        window.addEventListener('popstate', () => {
            if (ignorePop) { ignorePop = false; return; }
            if (m.classList.contains('active') && S.detailOpen) { phonePushed = false; closeDetail(true); }
        });
        // Closed from outside (the backdrop, or the app closing every dialog): close the detail too.
        new MutationObserver(() => {
            if (!m.classList.contains('active') && m.dataset.actOpen && S.detailOpen) {
                delete m.dataset.actOpen;
                if (phonePushed) { phonePushed = false; ignorePop = true; history.back(); }
                closeDetail(false);
            }
        }).observe(m, { attributes: true, attributeFilter: ['class'] });
        m.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (closeMenu(true)) { e.stopPropagation(); return; }
                e.stopPropagation();
                closeDetail(true);
            } else if (e.key === 'Tab') trapFocus(m, e);
        });
    }

    function trapFocus(container, e) {
        const items = Array.from(container.querySelectorAll('button, [href], input, select, textarea, summary, [tabindex]:not([tabindex="-1"])'))
            .filter((x) => !x.disabled && x.offsetParent !== null);
        if (!items.length) return;
        const first = items[0], last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }

    function wirePane() {
        const pane = $('act-detail');
        pane.addEventListener('keydown', (e) => {
            const t = e.target;
            if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT')) return;
            if (e.altKey || e.ctrlKey || e.metaKey) return;
            if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); step(1, true); }
            else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); step(-1, true); }
            else if (e.key === '/') { e.preventDefault(); $('act-search').focus(); }
        });
    }

    // Open an event named in the URL (a copied link): from the list when it is there, else on its own.
    async function openLinkedEvent(id) {
        if (S.rows.some((r) => r.id === id)) { select(id, { open: true, focus: false, scroll: true }); return; }
        S.selectedId = id;
        S.detail = null;
        try {
            S.detail = await get('/activity/events/' + encodeURIComponent(id));
            S.detailMissing = false;
            S.detailWhere = null;
        } catch (err) {
            if (S.blocked) return;
            S.detailMissing = err.status === 404 || err.status === 422;
            if (!S.detailMissing) { showError(`The event could not be loaded: ${err.message}`); return; }
        }
        openDetail();
    }

    // ---- category and event choices ----------------------------------------------------------------
    // A category is chosen whole or through some of its events, never both: choosing a category drops
    // its single events, and choosing single events drops their categories.

    function categoryPatch(keys, replace) {
        const cat = replace ? keys.slice() : Array.from(new Set(S.f.cat.concat(keys)));
        const act = replace ? [] : S.f.act.filter((a) => !cat.includes(actionCategory(a)));
        return { cat, act };
    }

    function actionsPatch(names, replace) {
        const act = replace ? names.slice() : Array.from(new Set(S.f.act.concat(names)));
        const touched = new Set(act.map(actionCategory));
        return { act, cat: replace ? [] : S.f.cat.filter((c) => !touched.has(c)) };
    }

    // The categories the Category and Event filters touch, whole or in part.
    function chosenCategories() {
        const out = new Set(S.f.cat);
        S.f.act.forEach((a) => { const c = actionCategory(a); if (c) out.add(c); });
        return out;
    }

    function toggleCategory(key) {
        if (chosenCategories().has(key)) {
            setState({ f: { cat: S.f.cat.filter((c) => c !== key), act: S.f.act.filter((a) => actionCategory(a) !== key) } });
        } else {
            setState({ f: categoryPatch([key], false) });
        }
    }

    function outcomeActions(key) {
        return (S.outcomes && S.outcomes[key]) || [];
    }

    function outcomeChosen(key) {
        const names = outcomeActions(key);
        return names.length > 0 && names.every((n) => S.f.act.includes(n));
    }

    function toggleOutcome(key) {
        const names = outcomeActions(key);
        if (!names.length) return;
        if (outcomeChosen(key)) setState({ f: { act: S.f.act.filter((a) => !names.includes(a)) } });
        else setState({ f: actionsPatch(names, false) });
    }

    // ---- the summary band --------------------------------------------------------------------------

    function bandParams() {
        const p = filterParams(S.f);
        const r = S.range;
        if (r.kind === 'custom') {
            p.set('range', 'custom');
            p.set('range_from', r.from);
            if (r.to) p.set('range_to', r.to);
        } else if (r.kind === 'all') {
            p.set('range', 'all');
            if (r.to) p.set('range_to', r.to);
        } else p.set('range', r.kind);
        const tz = zoneName();
        if (tz && /^[A-Za-z0-9_+-]+(\/[A-Za-z0-9_+-]+)*$/.test(tz)) p.set('tz', tz);
        p.set('tz_offset', String(-new Date().getTimezoneOffset()));
        if (S.f.time) { p.set('from_date', S.f.time.from); p.set('to_date', S.f.time.to); }
        return p;
    }

    function bandInUse() {
        const band = $('act-band');
        return band.matches(':hover') || band.contains(document.activeElement);
    }

    // Read the band. A newer read replaces one in flight. A read the viewer did not ask for (a live
    // refresh) waits while the pointer is over the band or focus is in it, so nothing moves under a
    // click; it is drawn when the pointer leaves or focus moves.
    async function loadBand(live) {
        if (S.blocked || !S.active) return;
        const seq = ++S.bandSeq;
        const p = bandParams();
        const kind = S.range.kind;
        const snap = PRESETS.includes(kind) ? presetStart(kind).getTime() : null;
        S.bandBusy = true;
        renderBandBusy();
        try {
            const data = await get('/activity/summary?' + p.toString());
            if (seq !== S.bandSeq) return;
            S.bandError = null;
            if (live && bandInUse()) { S.bandHeld = { data, snap }; return; }
            applyBand(data, snap);
        } catch (err) {
            if (seq !== S.bandSeq || S.blocked) return;
            S.bandError = err.message || 'error';
            renderBand();
        } finally {
            if (seq === S.bandSeq) { S.bandBusy = false; renderBandBusy(); }
        }
    }

    function applyHeldBand() {
        if (!S.bandHeld || bandInUse()) return;
        const h = S.bandHeld;
        S.bandHeld = null;
        applyBand(h.data, h.snap);
    }

    function applyBand(data, snap) {
        S.band = data;
        if (snap != null) S.bandFrom = { kind: data.range, from: data.from, snap };
        if (!S.now && data.now) S.now = data.now;
        renderBand();
        renderPanelState();
        reconcileTotals();
        // The list starts where the band does: when the server snapped the range's start differently
        // from the page (a daylight-saving corner), read the list again from the server's start.
        if (PRESETS.includes(S.range.kind) && data.range === S.range.kind && !S.f.time && S.listFromUsed) {
            const want = rangeBounds().from;
            if (want && Date.parse(want) !== Date.parse(S.listFromUsed)) reloadList({ keepDetail: true });
        }
    }

    function renderBandBusy() {
        const band = $('act-band');
        if (band) band.classList.toggle('is-busy', S.bandBusy && !!S.band);
    }

    // Whether a panel counts under filters other than its own: its title then says "· filtered".
    function panelFiltered(panel) {
        const f = S.f;
        const on = [];
        if (f.cat.length) on.push('cat');
        if (f.act.length) on.push('act');
        if (f.status.length) on.push('status');
        if (f.ch.length) on.push('ch');
        if (f.user) on.push('user');
        if (f.noAccount) on.push('noAccount');
        if (f.ip) on.push('ip');
        if (f.tcId || f.tcName) on.push('tc');
        if (f.vault) on.push('vault');
        if (f.time) on.push('time');
        if (f.q) on.push('q');
        const own = {
            time: ['time'], cat: ['cat', 'act'], signin: ['act'],
            active: mostActiveMode() === 'addresses' ? ['ip'] : ['user', 'noAccount'],
        }[panel] || [];
        return on.some((k) => !own.includes(k));
    }

    // A panel's title, with " · filtered" when filters other than its own apply, so no one reads a
    // filtered number as the whole picture. Where the title row has no room for the words (Most active,
    // beside its People and Addresses choice) a filter mark says it, with the words for screen readers.
    function panelHead(panel, title, filteredKey, compact) {
        const head = el('div', 'act-ptitle');
        const t = el('span', 'act-ptitle-text', title);
        if (filteredKey && panelFiltered(filteredKey)) {
            if (compact) {
                const mark = el('span', 'act-ptitle-mark');
                mark.title = 'Filtered: counted under the other filters';
                mark.append(icon('filter'), el('span', 'sr-only', ' · filtered'));
                t.appendChild(mark);
            } else t.appendChild(el('span', 'act-ptitle-filtered', ' · filtered'));
            head.classList.add('is-filtered');
        }
        head.appendChild(t);
        return head;
    }

    function plotState(plot) {
        if (S.bandError) {
            plot.appendChild(el('span', 'act-plot-note', "Couldn't load."));
            const retry = button('act-link-btn act-retry', 'Retry');
            retry.addEventListener('click', () => loadBand());
            plot.appendChild(retry);
            return true;
        }
        if (!S.band) { plot.appendChild(el('span', 'act-plot-note', 'Loading…')); return true; }
        return false;
    }

    // Keep keyboard focus on the same mark when a panel is drawn again.
    function focusKeyIn(panel) {
        const a = document.activeElement;
        return a && panel.contains(a) ? a.getAttribute('data-fkey') : null;
    }
    function refocus(panel, key) {
        if (!key) return;
        const n = panel.querySelector(`[data-fkey="${CSS.escape(key)}"]`);
        if (n) n.focus({ preventScroll: true });
    }

    function renderBand() {
        const band = $('act-band');
        if (!band || S.blocked) return;
        band.classList.toggle('show-more', storeGet('activity.moreCharts') === '1');
        renderNowPanel();
        renderTimePanel();
        renderCatPanel();
        renderSignInPanel();
        renderActivePanel();
        const more = $('act-more-charts');
        if (more) {
            const open = band.classList.contains('show-more');
            more.setAttribute('aria-expanded', open ? 'true' : 'false');
            more.querySelector('.act-more-text').textContent = open ? 'Fewer charts' : 'More charts';
        }
    }

    // A roving tab stop over a panel's buttons: one Tab stop, the arrows move between them.
    function roving(group, selector, keys) {
        group.addEventListener('keydown', (e) => {
            const items = Array.from(group.querySelectorAll(selector)).filter((x) => !x.disabled);
            let i = items.indexOf(document.activeElement);
            if (i < 0) return;
            const back = keys === 'x' ? 'ArrowLeft' : 'ArrowUp';
            const fwd = keys === 'x' ? 'ArrowRight' : 'ArrowDown';
            if (e.key === fwd) i = Math.min(items.length - 1, i + 1);
            else if (e.key === back) i = Math.max(0, i - 1);
            else if (e.key === 'Home') i = 0;
            else if (e.key === 'End') i = items.length - 1;
            else if (e.key === '/') { e.preventDefault(); $('act-search').focus(); return; }
            else return;
            e.preventDefault();
            items.forEach((x, j) => { x.tabIndex = j === i ? 0 : -1; });
            items[i].focus();
        });
    }

    function setRoving(items, key) {
        const pick = items.find((x) => x.getAttribute('data-fkey') === key) || items.find((x) => x.getAttribute('aria-pressed') === 'true') || items[0];
        items.forEach((x) => { x.tabIndex = x === pick ? 0 : -1; });
    }

    // A small horizontal bar: failed or refused from the left, the rest after a 2 px gap.
    function hbar(width, count, failed, max) {
        const s = svg('svg', { width, height: 6, viewBox: `0 0 ${width} 6`, 'aria-hidden': 'true', focusable: 'false' }, 'act-hbar');
        const total = Math.max(0, count || 0);
        if (!total || !max) return s;
        const w = Math.max(1, Math.round(total / max * width));
        const bad = Math.min(total, failed || 0);
        let wb = bad ? Math.max(1, Math.round(bad / total * w)) : 0;
        const gap = bad && bad < total ? 2 : 0;
        const wo = total > bad ? Math.max(1, w - wb - gap) : 0;
        if (wb && !wo) wb = w;
        if (wb) s.appendChild(svg('rect', { x: 0, y: 0, width: wb, height: 6, rx: wo ? 0 : 1 }, 'act-bad'));
        if (wo) s.appendChild(svg('rect', { x: wb + gap, y: 0, width: wo, height: 6, rx: 1 }, 'act-bar'));
        return s;
    }

    function rankRow(opts) {
        const b = button('act-rank-row' + (opts.cls ? ' ' + opts.cls : ''), null, {
            'aria-pressed': opts.pressed ? 'true' : 'false',
            'aria-label': opts.aria,
            title: opts.title || opts.aria,
            'data-fkey': opts.key,
        });
        const label = el('span', 'act-rank-label' + (opts.mono ? ' act-mono' : ''), opts.label);
        b.append(label, hbar(opts.barWidth, opts.count, opts.failed, opts.max), el('span', 'act-rank-count', nf(opts.count)));
        b.addEventListener('click', opts.onClick);
        return b;
    }

    // ---- Now ----

    function renderNowPanel() {
        const panel = $('act-p-now');
        const key = focusKeyIn(panel);
        // The Online now popover stays where it is (and keeps its focus) while the counts are redrawn.
        Array.from(panel.children).forEach((c) => { if (c !== onlinePop) c.remove(); });
        const head = el('div', 'act-ptitle');
        const t = el('span', 'act-ptitle-text');
        const dot = el('span', 'act-now-dot' + (S.liveState === 'live' ? ' is-live' : ''));
        dot.setAttribute('aria-hidden', 'true');
        t.append(dot, document.createTextNode('Now'));
        head.appendChild(t);
        head.title = "Right now. The time range and filters don't change these numbers.";
        panel.insertBefore(head, onlinePop && onlinePop.parentNode === panel ? onlinePop : null);
        const plot = el('div', 'act-plot act-now-rows');
        plot.setAttribute('role', 'group');
        plot.setAttribute('aria-label', 'Now');
        const n = S.now;
        const unavailable = S.nowError || !n;
        if (S.nowError) panel.title = 'Live counts are unavailable right now. Events still load.';
        else panel.removeAttribute('title');
        const val = (v) => (unavailable || v == null ? '—' : nf(v));
        const rows = [
            ['online', 'Online', val(n && n.people), 'Accounts with a session active in the last hour'],
            ['sessions', 'Sessions', val(n && n.sessions), 'Sessions active in the last hour'],
            ['temp', 'Temp. credentials', val(n && n.temporary_credentials), 'Temporary credentials'],
        ];
        rows.forEach(([k, label, value, title]) => {
            const b = button('act-now-row', null, { 'data-fkey': 'now-' + k, title, 'aria-haspopup': 'dialog' });
            b.append(el('span', 'act-now-label', label), el('span', 'act-now-value', value));
            b.addEventListener('click', () => openOnline(k === 'temp' ? 'temp' : null, b));
            plot.appendChild(b);
        });
        const tr = el('div', 'act-now-row is-static act-now-transfers');
        tr.title = 'Uploads and downloads in progress through the web on this server, of the most allowed at once. SFTP transfers are not counted yet.';
        const limit = n && n.transfer_limit;
        tr.append(el('span', 'act-now-label', 'Web transfers'),
            el('span', 'act-now-value', unavailable ? '—' : `${nf(n.transfers_in_flight)}${limit ? ' / ' + nf(limit) : ''}`));
        plot.appendChild(tr);
        if (n && !unavailable && n.transfers_waiting > 0) {
            const w = el('div', 'act-now-row is-static act-now-wait');
            const lab = el('span', 'act-now-label');
            lab.append(icon('alert-triangle', 'act-warn-icon'), document.createTextNode(`${nf(n.transfers_waiting)} waiting`));
            w.appendChild(lab);
            plot.appendChild(w);
        }
        panel.insertBefore(plot, onlinePop && onlinePop.parentNode === panel ? onlinePop : null);
        const items = Array.from(plot.querySelectorAll('button'));
        setRoving(items, key);
        roving(plot, 'button', 'y');
        refocus(panel, key);
        if (onlinePop) renderOnlinePop();
    }

    async function loadNow() {
        if (S.blocked || !S.active || S.paused || document.hidden) return;
        const seq = ++S.nowSeq;
        try {
            const data = await get('/activity/now');
            if (seq !== S.nowSeq) return;
            S.now = data;
            S.nowError = false;
        } catch (err) {
            if (seq !== S.nowSeq || S.blocked) return;
            S.nowError = true;
        }
        renderNowPanel();
        renderTimeHead();
    }

    let onlinePop = null;
    let onlineFocus = null;

    function openOnline(sectionKey, from) {
        closePopovers();
        closeMenu();
        onlineFocus = from;
        onlinePop = el('div', 'act-pop act-online-pop');
        onlinePop.setAttribute('role', 'dialog');
        onlinePop.setAttribute('aria-label', 'Online now');
        onlinePop.tabIndex = -1;
        $('act-p-now').appendChild(onlinePop);
        renderOnlinePop();
        if (sectionKey === 'temp') {
            const t = onlinePop.querySelector('.act-online-temp');
            if (t) t.scrollIntoView({ block: 'nearest' });
        }
        onlinePop.focus({ preventScroll: true });
        loadNow();
    }

    function closeOnline(returnFocus) {
        if (!onlinePop) return false;
        onlinePop.remove();
        onlinePop = null;
        if (returnFocus && onlineFocus && onlineFocus.isConnected) onlineFocus.focus();
        return true;
    }

    function renderOnlinePop() {
        if (!onlinePop) return;
        const key = focusKeyIn(onlinePop);
        onlinePop.replaceChildren();
        const n = S.now || {};
        const head = el('div', 'act-pop-head');
        head.append(el('div', 'act-pop-title', 'Online now'), el('div', 'act-pop-sub', 'Active in the last hour'));
        onlinePop.appendChild(head);
        const people = n.online_people || [];
        const list = el('ul', 'act-pop-list');
        people.forEach((p) => {
            const li = el('li', 'act-pop-row');
            const text = el('div', 'act-pop-text');
            text.appendChild(el('div', 'act-pop-name', p.username));
            const last = toDate(p.last_active);
            const bits = [`${nf(p.sessions)} ${p.sessions === 1 ? 'session' : 'sessions'}`];
            if (last) bits.push(`active ${ago(last)}`);
            if (p.ip_address) bits.push(p.ip_address);
            text.appendChild(el('div', 'act-pop-meta', bits.join(' · ')));
            const show = button('act-link-btn', 'Show events', { 'data-fkey': 'pop-' + p.username });
            show.addEventListener('click', () => {
                closeOnline(false);
                setState({ f: { user: p.username, userMatch: 'exact', noAccount: false } });
            });
            li.append(text, show);
            list.appendChild(li);
        });
        if (!people.length) onlinePop.appendChild(el('p', 'act-pop-empty', 'No one is online right now.'));
        else onlinePop.appendChild(list);
        const temps = n.temp_in_use || [];
        if (temps.length) {
            const sec = el('div', 'act-online-temp');
            sec.appendChild(el('div', 'act-pop-title act-pop-sec', 'Temporary credentials in use'));
            const tl = el('ul', 'act-pop-list');
            temps.forEach((t) => {
                const li = el('li', 'act-pop-row');
                const text = el('div', 'act-pop-text');
                text.appendChild(el('div', 'act-pop-name', t.name));
                const last = toDate(t.last_active);
                text.appendChild(el('div', 'act-pop-meta', [t.owner, last ? `active ${ago(last)}` : null].filter(Boolean).join(' · ')));
                li.appendChild(text);
                tl.appendChild(li);
            });
            sec.appendChild(tl);
            onlinePop.appendChild(sec);
        }
        if (n.online_total > people.length) {
            onlinePop.appendChild(el('p', 'act-pop-foot', `Showing ${nf(people.length)} of ${nf(n.online_total)}.`));
        }
        refocus(onlinePop, key);
    }

    // ---- Events over time ----

    function niceCeil(max) {
        if (max <= 1) return 1;
        const e = Math.pow(10, Math.floor(Math.log10(max)));
        for (const m of [1, 2, 5, 10]) if (m * e >= max) return m * e;
        return 10 * e;
    }

    function colPath(x, y, w, h, roundTop) {
        const r = roundTop ? Math.min(2, w / 2, h) : 0;
        if (!r) return `M${x},${y}h${w}v${h}h${-w}Z`;
        return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
    }

    function bucketSeconds() { return (S.band && S.band.bucket_seconds) || 3600; }

    function bucketText(bk, forAria) {
        const a = toDate(bk.start), b = toDate(bk.end);
        if (!a || !b) return '';
        const size = bucketSeconds();
        const now = new Date();
        const endHm = b.getHours() === 0 && b.getMinutes() === 0 && !sameDay(a, b) && b - a <= 86400000 ? '24:00' : hmText(b);
        if (size < 86400) return forAria ? `${dayShort(a)} ${hmText(a)} to ${endHm}` : `${dayShort(a)}, ${hmText(a)}–${endHm}`;
        if (size === 86400) return dayShort(a);
        const end = new Date(b.getTime() - 1);
        const withYear = end.getFullYear() !== now.getFullYear() || a.getFullYear() !== end.getFullYear();
        return forAria ? `${dayMonth(a, withYear)} to ${dayMonth(end, withYear)}` : `${dayMonth(a, withYear)} – ${dayMonth(end, withYear)}`;
    }

    function unitName() {
        const size = bucketSeconds();
        if (size <= 3600) return 'hour';
        if (size <= 6 * 3600) return 'six hours';
        if (size === 86400) return 'day';
        if (size === 7 * 86400) return 'week';
        return `${Math.round(size / 86400)} days`;
    }

    function selectedBuckets() {
        const out = new Set();
        const t = S.f.time;
        if (!t || !S.band) return out;
        const a = Date.parse(t.from), b = Date.parse(t.to);
        (S.band.buckets || []).forEach((bk, i) => {
            if (Date.parse(bk.start) >= a && Date.parse(bk.end) <= b) out.add(i);
        });
        return out;
    }

    function pickBuckets(i, j) {
        const bs = (S.band && S.band.buckets) || [];
        const a = Math.max(0, Math.min(i, j)), b = Math.min(bs.length - 1, Math.max(i, j));
        if (!bs[a] || !bs[b]) return;
        setState({ f: { time: { from: bs[a].start, to: bs[b].end } } });
    }

    function chartAriaLabel() {
        const b = S.band;
        const busiest = (b.buckets || []).reduce((m, x) => (x.total > (m ? m.total : 0) ? x : m), null);
        let text = `Events, ${rangeName()}: ${nf(b.total)} in total, ${nf(b.failed)} failed or refused.`;
        if (busiest) text += ` Busiest: ${bucketText(busiest, true)}, ${plural(busiest.total, 'event', 'events')}.`;
        return text;
    }

    function renderTimeHead() {
        const panel = $('act-p-time');
        const old = panel && panel.querySelector('.act-ptitle');
        if (!old) return;
        old.replaceWith(timeHead());
        fitTimeKeys(panel);
    }

    function timeHead() {
        const head = panelHead('time', 'Events', 'time');
        const b = S.band;
        if (!b) return head;
        const keys = el('span', 'act-keys');
        const narrow = isNarrow();
        const all = button('act-key-btn', null, { title: 'Show every status', 'data-fkey': 'key-all' });
        all.append(el('span', 'act-key act-key-all'), keyText(nf(b.total), narrow ? (b.total === 1 ? ' event' : ' events') : ''));
        all.addEventListener('click', () => { if (S.f.status.length) setState({ f: { status: [] } }); });
        const failedOnly = S.f.status.length === 1 && S.f.status[0] === 'failed';
        const bad = button('act-key-btn', null, { 'aria-pressed': failedOnly ? 'true' : 'false', 'data-fkey': 'key-bad', title: 'Show only events that failed or were refused' });
        bad.append(el('span', 'act-key act-key-bad'), keyText(nf(b.failed), ' failed', narrow ? null : ' or refused'));
        bad.addEventListener('click', () => setState({ f: { status: failedOnly ? [] : ['failed'] } }));
        keys.append(all, bad);
        head.appendChild(keys);
        if (narrow && S.now && !S.nowError) {
            const on = button('act-key-btn act-head-online', `Online ${nf(S.now.people)}`, { 'aria-haspopup': 'dialog' });
            on.addEventListener('click', () => openOnline(null, on));
            head.appendChild(on);
        }
        return head;
    }

    // `more` is said only while it fits: the title row drops it before the title would be cut short.
    function keyText(num, words, more) {
        const t = el('span', 'act-key-text');
        t.append(el('span', 'act-num', num), document.createTextNode(words));
        if (more) t.appendChild(el('span', 'act-key-more', more));
        return t;
    }

    // At the narrowest one-row band "38 failed or refused" beside "EVENTS" and the total would cut the
    // title short: say "38 failed" there (the key's title says the rest).
    function fitTimeKeys(panel) {
        const more = panel.querySelector('.act-key-more');
        if (!more) return;
        more.hidden = false;
        const title = panel.querySelector('.act-ptitle-text');
        const head = panel.querySelector('.act-ptitle');
        if ((title && title.scrollWidth > title.clientWidth + 0.5) || (head && head.scrollWidth > head.clientWidth + 0.5)) {
            more.hidden = true;
        }
    }

    let chartUi = null;       // the drawn chart's geometry and state, for hover and drag

    function renderTimePanel() {
        const panel = $('act-p-time');
        const key = focusKeyIn(panel);
        panel.replaceChildren();
        panel.appendChild(timeHead());
        fitTimeKeys(panel);
        requestAnimationFrame(() => fitTimeKeys(panel));         // once the band around it is laid out
        const plot = el('div', 'act-plot act-time-plot');
        panel.appendChild(plot);
        if (!plotState(plot)) drawTimeChart(plot);
        refocus(panel, key);
        watchPlot(plot);
    }

    let plotObserver = null, plotWidth = 0;
    function watchPlot(plot) {
        if (typeof ResizeObserver !== 'function') return;
        if (plotObserver) plotObserver.disconnect();
        plotWidth = plot.clientWidth;
        plotObserver = new ResizeObserver(() => {
            fitTimeKeys($('act-p-time'));
            const w = plot.clientWidth;
            if (w && Math.abs(w - plotWidth) > 1 && S.band && !S.bandError) {
                plotWidth = w;
                const key = focusKeyIn(plot);
                plot.replaceChildren();
                drawTimeChart(plot);
                refocus(plot, key);
            }
        });
        plotObserver.observe(plot);
    }

    function drawTimeChart(host) {
        const b = S.band;
        const buckets = b.buckets || [];
        const W = host.clientWidth, H = host.clientHeight;
        if (!W || !H || !buckets.length) return;
        const narrow = isNarrow();
        const axisH = narrow ? 11 : (isConsole() ? 13 : 14);
        const top = narrow ? 2 : 12;
        const base = H - axisH;
        const area = Math.max(1, base - top);
        const peak = Math.max(0, ...buckets.map((x) => x.total || 0));
        const ceil = niceCeil(peak);
        const n = buckets.length;
        const pitch = W / n;
        const cw = Math.max(1, Math.min(pitch * 0.7, 14));
        const sel = selectedBuckets();
        const chart = el('div', 'act-chart' + (sel.size ? ' has-sel' : ''));
        const s = svg('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': chartAriaLabel() }, 'act-chart-svg');
        if (!narrow && peak > 0) {                                  // an empty chart has no scale to show
            s.appendChild(svg('line', { x1: 0, x2: W, y1: top + 0.5, y2: top + 0.5 }, 'act-grid'));
            const lab = svg('text', { x: 0, y: top - 3 }, 'act-axis act-grid-label');
            lab.textContent = nf(ceil);
            s.appendChild(lab);
        }
        s.appendChild(svg('line', { x1: 0, x2: W, y1: base + 0.5, y2: base + 0.5 }, 'act-grid'));
        const tops = [];
        buckets.forEach((bk, i) => {
            const g = svg('g', {}, 'act-col' + (sel.has(i) ? ' is-sel' : ''));
            g.setAttribute('data-i', String(i));
            const x = i * pitch + (pitch - cw) / 2;
            const total = bk.total || 0, bad = Math.min(total, bk.failed || 0), ok = total - bad;
            if (!total) {
                g.appendChild(svg('rect', { x, y: base + 1, width: cw, height: 2 }, 'act-tick'));
                tops.push(base);
            } else {
                const hT = Math.max(1, total / ceil * area);
                const hB = bad ? Math.max(1, bad / ceil * area) : 0;
                const gap = bad && ok ? 2 : 0;
                const hO = ok ? Math.max(1, hT - hB - gap) : 0;
                if (hB) g.appendChild(svg('path', { d: colPath(x, base - hB, cw, hB, !ok) }, 'act-bad'));
                if (hO) g.appendChild(svg('path', { d: colPath(x, base - hB - gap - hO, cw, hO, true) }, 'act-bar'));
                tops.push(base - hB - gap - hO);
            }
            if (sel.has(i)) g.appendChild(svg('rect', { x, y: base + 1, width: cw, height: 2 }, 'act-sel-mark'));
            s.appendChild(g);
        });
        axisLabels(s, buckets, pitch, H, narrow);
        chart.appendChild(s);

        const hits = el('div', 'act-hits');
        hits.setAttribute('role', 'group');
        hits.setAttribute('aria-label', `Events over time, one button per ${unitName()}`);
        const focusIndex = chartUi && chartUi.focusIndex != null && chartUi.focusIndex < n ? chartUi.focusIndex
            : (sel.size ? Math.min(...sel) : n - 1);
        buckets.forEach((bk, i) => {
            const aria = `${bucketText(bk, true)}: ${plural(bk.total || 0, 'event', 'events')}, ${nf(bk.failed || 0)} failed or refused`;
            const hb = button('act-hit', null, { 'aria-label': aria, 'aria-pressed': sel.has(i) ? 'true' : 'false', 'data-fkey': 'col-' + i });
            hb.dataset.i = String(i);
            hb.tabIndex = i === focusIndex ? 0 : -1;
            hb.style.setProperty('left', `${i * pitch}px`);
            hb.style.setProperty('width', `${pitch}px`);
            hits.appendChild(hb);
        });
        chart.appendChild(hits);
        const tip = el('div', 'act-tip');
        tip.hidden = true;
        tip.setAttribute('role', 'presentation');
        chart.appendChild(tip);
        host.appendChild(chart);
        chartUi = { chart, s, hits, tip, pitch, W, H, tops, n, focusIndex, anchor: chartUi ? chartUi.anchor : null, pinned: null };
        wireChart(chartUi, sel);
    }

    function axisLabels(s, buckets, pitch, H, narrow) {
        const kind = S.range.kind;
        const out = [];
        const live = rangeIsLive();
        const n = buckets.length;
        const size = bucketSeconds();
        if (!narrow) {
            const step = Math.max(1, Math.ceil(n / 5));
            buckets.forEach((bk, i) => {
                const d = toDate(bk.start);
                if (!d) return;
                let text = null;
                if (kind === '24h') { if (d.getHours() % 6 === 0 && d.getMinutes() === 0) text = hmText(d); }
                else if (kind === '7d') { if (d.getHours() === 0) text = d.toLocaleDateString(undefined, { weekday: 'short' }); }
                else if (kind === '30d') { if (i % 7 === 0) text = dayMonth(d); }
                else if (i % step === 0) {
                    if (size < 86400) text = sameDay(d, toDate(buckets[0].start)) || i === 0 ? hmText(d) : `${dayMonth(d)} ${hmText(d)}`;
                    else if (size >= 30 * 86400) text = d.toLocaleDateString(undefined, { month: 'short', year: '2-digit' });
                    else text = dayMonth(d);
                }
                if (text) out.push({ x: i * pitch + pitch / 2, text });
            });
        }
        const placed = [];
        let limit = Infinity;
        if (live) {
            const w = 3 * 6;
            placed.push({ x: n * pitch - w, text: 'now', anchor: 'end', x0: n * pitch - w, x1: n * pitch });
            limit = n * pitch - w - 6;
        }
        let right = -Infinity;
        out.forEach((l) => {
            const w = l.text.length * 6;
            let x0 = l.x - w / 2, anchor = 'middle';
            if (x0 < 0) { x0 = 0; anchor = 'start'; }
            const x1 = x0 + w;
            if (x0 < right + 6 || x1 > limit) return;
            placed.push({ x: anchor === 'start' ? 0 : l.x, text: l.text, anchor });
            right = x1;
        });
        placed.forEach((l) => {
            const t = svg('text', { x: l.anchor === 'end' ? l.x1 : l.x, y: H - 2, 'text-anchor': l.anchor }, 'act-axis');
            t.textContent = l.text;
            s.appendChild(t);
        });
    }

    function wireChart(ui, sel) {
        const { hits, chart } = ui;
        const idxAt = (clientX) => {
            const r = hits.getBoundingClientRect();
            return Math.max(0, Math.min(ui.n - 1, Math.floor((clientX - r.left) / ui.pitch)));
        };
        const hover = (i) => {
            chart.classList.toggle('has-hover', i != null);
            ui.s.querySelectorAll('.act-col').forEach((g) => g.classList.toggle('is-hover', Number(g.getAttribute('data-i')) === i));
            if (i == null) { if (ui.pinned == null) hideTip(ui); }
            else showTip(ui, i, false);
        };
        let drag = null;
        let suppress = false;
        hits.addEventListener('pointerover', (e) => {
            const b = e.target.closest('.act-hit');
            if (b && !isNarrow()) hover(Number(b.dataset.i));
        });
        hits.addEventListener('pointerleave', () => { if (!isNarrow()) hover(null); applyHeldBand(); });
        hits.addEventListener('focusin', (e) => {
            const b = e.target.closest('.act-hit');
            if (b) { ui.focusIndex = Number(b.dataset.i); hover(ui.focusIndex); }
        });
        hits.addEventListener('focusout', () => { if (ui.pinned == null) hover(null); setTimeout(applyHeldBand, 0); });
        hits.addEventListener('pointerdown', (e) => {
            if (isNarrow() || e.button !== 0) return;
            const b = e.target.closest('.act-hit');
            if (b) drag = { start: Number(b.dataset.i), at: Number(b.dataset.i) };
        });
        hits.addEventListener('pointermove', (e) => {
            if (!drag) return;
            const i = idxAt(e.clientX);
            if (i === drag.at) return;
            drag.at = i;
            const a = Math.min(drag.start, i), z = Math.max(drag.start, i);
            ui.chart.classList.add('has-sel');
            ui.s.querySelectorAll('.act-col').forEach((g) => {
                const j = Number(g.getAttribute('data-i'));
                g.classList.toggle('is-sel', j >= a && j <= z);
            });
        });
        const endDrag = () => {
            if (!drag) return;
            const d = drag;
            drag = null;
            if (d.at !== d.start) { suppress = true; ui.anchor = d.start; pickBuckets(d.start, d.at); }
        };
        hits.addEventListener('pointerup', endDrag);
        hits.addEventListener('pointercancel', () => { drag = null; });
        hits.addEventListener('click', (e) => {
            const b = e.target.closest('.act-hit');
            if (!b) return;
            if (suppress) { suppress = false; return; }
            const i = Number(b.dataset.i);
            ui.focusIndex = i;
            if (isNarrow()) { showTip(ui, i, true); return; }
            if (e.shiftKey && ui.anchor != null) { pickBuckets(ui.anchor, i); return; }
            ui.anchor = i;
            if (sel.size === 1 && sel.has(i)) setState({ f: { time: null } });
            else pickBuckets(i, i);
        });
        hits.addEventListener('keydown', (e) => {
            const b = e.target.closest('.act-hit');
            if (!b) return;
            let i = Number(b.dataset.i);
            if (e.key === '/') { e.preventDefault(); $('act-search').focus(); return; }
            if (e.key === 'Escape' && ui.pinned) { e.stopPropagation(); hideTip(ui); return; }
            const moves = { ArrowLeft: -1, ArrowRight: 1 };
            if (e.key in moves) i = Math.max(0, Math.min(ui.n - 1, i + moves[e.key]));
            else if (e.key === 'Home') i = 0;
            else if (e.key === 'End') i = ui.n - 1;
            else return;
            e.preventDefault();
            const buttons = hits.querySelectorAll('.act-hit');
            buttons.forEach((x, j) => { x.tabIndex = j === i ? 0 : -1; });
            ui.focusIndex = i;
            buttons[i].focus();
            if (e.shiftKey && (e.key in moves)) {
                if (ui.anchor == null) ui.anchor = Number(b.dataset.i);
                pickBuckets(ui.anchor, i);
            }
        });
    }

    function showTip(ui, i, pinned) {
        const bk = S.band && S.band.buckets[i];
        if (!bk) return;
        const tip = ui.tip;
        tip.replaceChildren();
        tip.appendChild(el('div', 'act-tip-value', plural(bk.total || 0, 'event', 'events')));
        const bad = el('div', 'act-tip-bad');
        bad.append(el('span', 'act-key act-key-line'), el('span', '', `${nf(bk.failed || 0)} failed or refused`));
        tip.appendChild(bad);
        tip.appendChild(el('div', 'act-tip-when', bucketText(bk, false)));
        ui.pinned = pinned ? i : null;
        if (pinned) {
            const go = button('btn btn-secondary btn-sm act-tip-go', 'Filter to this time');
            go.addEventListener('click', (e) => { e.stopPropagation(); hideTip(ui); pickBuckets(i, i); });
            tip.appendChild(go);
        }
        tip.hidden = false;
        const w = tip.offsetWidth;
        const x = i * ui.pitch + ui.pitch / 2;
        tip.style.setProperty('left', `${Math.max(0, Math.min(ui.W - w, x - w / 2))}px`);
        tip.style.setProperty('bottom', `${ui.H - (ui.tops[i] == null ? ui.H : ui.tops[i]) + 6}px`);
    }

    function hideTip(ui) {
        if (!ui) return false;
        const was = !ui.tip.hidden;
        ui.tip.hidden = true;
        ui.pinned = null;
        return was;
    }

    function focusChartSelection() {
        if (!chartUi) return;
        const sel = selectedBuckets();
        const i = sel.size ? Math.min(...sel) : chartUi.n - 1;
        const b = chartUi.hits.querySelectorAll('.act-hit')[i];
        if (b) b.focus();
    }

    // ---- By category ----

    function slots() { return isConsole() ? 5 : 6; }

    function renderCatPanel() {
        const panel = $('act-p-cat');
        const key = focusKeyIn(panel);
        panel.replaceChildren();
        panel.appendChild(panelHead('cat', 'By category', 'cat'));
        const plot = el('div', 'act-plot act-rank');
        panel.appendChild(plot);
        if (plotState(plot)) return;
        const order = S.catOrder;
        const cats = (S.band.categories || []).map((c) => ({ key: c.key, label: c.label || catLabel(c.key), count: c.count || 0, failed: c.failed || 0 }));
        cats.sort((a, b) => b.count - a.count || order.indexOf(a.key) - order.indexOf(b.key));
        const chosen = chosenCategories();
        chosen.forEach((k) => { if (!cats.some((c) => c.key === k)) cats.push({ key: k, label: catLabel(k), count: 0, failed: 0 }); });
        const pinned = cats.filter((c) => chosen.has(c.key));
        const ranked = cats.filter((c) => !chosen.has(c.key));
        const room = slots();
        const over = pinned.length + ranked.length > room;
        const rankedShown = ranked.slice(0, Math.max(0, room - pinned.length - (over ? 1 : 0)));
        const hidden = ranked.length - rankedShown.length;
        const shown = pinned.concat(rankedShown);
        const max = Math.max(1, ...shown.map((c) => c.count));
        plot.setAttribute('role', 'group');
        plot.setAttribute('aria-label', 'By category');
        if (!cats.length) { plot.appendChild(el('span', 'act-plot-note', 'No events.')); return; }
        const anyChosen = chosen.size > 0;
        shown.forEach((c, i) => {
            const pressed = chosen.has(c.key);
            const row = rankRow({
                key: 'cat-' + c.key, label: c.label, count: c.count, failed: c.failed, max, barWidth: 36,
                pressed, cls: (pressed ? 'is-sel' : (anyChosen ? 'is-dim' : '')) + (i === pinned.length - 1 && rankedShown.length ? ' is-pin-last' : ''),
                aria: `${c.label}, ${plural(c.count, 'event', 'events')}, ${nf(c.failed)} failed or refused`,
                title: `${c.label}: ${plural(c.count, 'event', 'events')}, ${nf(c.failed)} failed or refused. Click to filter.`,
                onClick: () => toggleCategory(c.key),
            });
            if (c.key === 'legacy') row.classList.add('is-legacy');
            plot.appendChild(row);
        });
        if (hidden > 0) {
            const more = button('act-link-btn act-rank-more', `+ ${nf(hidden)} more`, { 'data-fkey': 'cat-more' });
            more.addEventListener('click', () => openPanel('category'));
            plot.appendChild(more);
        }
        const items = Array.from(plot.querySelectorAll('button'));
        setRoving(items, key);
        roving(plot, 'button', 'y');
        refocus(panel, key);
    }

    // ---- Sign-ins ----

    function renderSignInPanel() {
        const panel = $('act-p-signin');
        const key = focusKeyIn(panel);
        panel.replaceChildren();
        const head = panelHead('signin', 'Sign-ins', 'signin');
        panel.appendChild(head);
        const plot = el('div', 'act-plot act-signin-plot');
        panel.appendChild(plot);
        if (plotState(plot)) return;
        const si = S.band.sign_ins || { succeeded: 0, failed: 0, locked: 0 };
        const attempts = (si.succeeded || 0) + (si.failed || 0);
        // Filtered, the title needs the room; the line under the meter still gives the attempts. Too
        // narrow for the word (four-digit counts, Classic's padding), the number stands alone.
        if (!head.classList.contains('is-filtered')) {
            const note = el('span', 'act-ptitle-note', plural(attempts, 'attempt', 'attempts'));
            head.appendChild(note);
            if (note.clientWidth && note.scrollWidth > note.clientWidth) { note.title = note.textContent; note.textContent = nf(attempts); }
        }
        const meter = svg('svg', { width: '100%', height: 6, viewBox: '0 0 100 6', preserveAspectRatio: 'none', role: 'img',
            'aria-label': attempts ? `${nf(si.failed)} of ${nf(attempts)} sign-in attempts failed` : 'No sign-in attempts' }, 'act-meter');
        meter.appendChild(svg('rect', { x: 0, y: 0, width: 100, height: 6 }, attempts ? 'act-bar' : 'act-track'));
        if (attempts && si.failed) meter.appendChild(svg('rect', { x: 0, y: 0, width: Math.max(1, si.failed / attempts * 100), height: 6 }, 'act-bad'));
        plot.appendChild(meter);
        const pct = attempts ? Math.round(si.failed / attempts * 100) : 0;
        plot.appendChild(el('div', 'act-meter-text', attempts ? `${nf(si.failed)} of ${nf(attempts)} failed (${pct}%)` : 'No sign-in attempts.'));
        const group = el('div', 'act-signin-rows');
        group.setAttribute('role', 'group');
        group.setAttribute('aria-label', 'Sign-ins');
        const rows = [
            ['succeeded', 'Signed in', si.succeeded, null, null],
            ['failed', 'Failed', si.failed, 'act-mark-bad', null],
            ['locked', 'Locked out', si.locked, 'act-mark-warn', 'Automatic lockouts after failed sign-ins, from one address or for the whole account.'],
        ];
        const anyChosen = rows.some(([k]) => outcomeChosen(k));
        rows.forEach(([k, label, count, mark, title]) => {
            const pressed = outcomeChosen(k);
            const b = button('act-signin-row' + (pressed ? ' is-sel' : (anyChosen ? ' is-dim' : '')), null, {
                'aria-pressed': pressed ? 'true' : 'false', 'data-fkey': 'si-' + k,
                'aria-label': `${label}, ${nf(count || 0)}`, title: title || `${label}: ${nf(count || 0)}. Click to filter.`,
            });
            const lab = el('span', 'act-signin-label');
            if (mark === 'act-mark-bad') lab.appendChild(el('span', 'act-key act-key-bad'));
            if (mark === 'act-mark-warn') lab.appendChild(icon('alert-triangle', 'act-warn-icon'));
            lab.appendChild(document.createTextNode(label));
            b.append(lab, el('span', 'act-rank-count', nf(count || 0)));
            b.disabled = !outcomeActions(k).length;
            b.addEventListener('click', () => toggleOutcome(k));
            group.appendChild(b);
        });
        plot.appendChild(group);
        setRoving(Array.from(group.querySelectorAll('button')), key);
        roving(group, 'button', 'y');
        refocus(panel, key);
    }

    // ---- Most active ----

    function mostActiveMode() { return storeGet('activity.mostActive') === 'addresses' ? 'addresses' : 'people'; }

    function renderActivePanel() {
        const panel = $('act-p-active');
        const key = focusKeyIn(panel);
        panel.replaceChildren();
        const head = panelHead('active', 'Most active', 'active', true);
        const mode = mostActiveMode();
        const toggle = el('span', 'act-toggle');
        toggle.setAttribute('role', 'radiogroup');
        toggle.setAttribute('aria-label', 'Most active by');
        [['people', 'People'], ['addresses', 'Addresses']].forEach(([m, label], i) => {
            if (i) toggle.appendChild(el('span', 'act-toggle-sep', '·'));
            const b = button('act-toggle-btn', label, { role: 'radio', 'aria-checked': m === mode ? 'true' : 'false', 'data-fkey': 'mode-' + m });
            b.tabIndex = m === mode ? 0 : -1;
            b.addEventListener('click', () => { storeSet('activity.mostActive', m); renderActivePanel(); const n = $('act-p-active').querySelector(`[data-fkey="mode-${m}"]`); if (n) n.focus(); });
            toggle.appendChild(b);
        });
        roving(toggle, 'button', 'x');
        head.appendChild(toggle);
        panel.appendChild(head);
        const plot = el('div', 'act-plot act-rank');
        panel.appendChild(plot);
        if (plotState(plot)) return;
        plot.setAttribute('role', 'group');
        plot.setAttribute('aria-label', mode === 'people' ? 'Most active people' : 'Most active addresses');
        let items;
        if (mode === 'people') {
            items = (S.band.top_users || []).map((u) => ({ kind: 'user', key: 'u-' + u.username, label: u.username, count: u.count, failed: u.failed,
                pressed: !S.f.noAccount && S.f.userMatch === 'exact' && S.f.user.toLowerCase() === String(u.username).toLowerCase() }));
            const na = S.band.no_account;
            if (na && na.total > 0) items.push({ kind: 'none', key: 'u-none', label: 'Names with no account', count: na.total, failed: na.failed, pressed: S.f.noAccount });
            items.sort((a, b) => b.count - a.count);
            if (S.f.user && S.f.userMatch === 'exact' && !S.f.noAccount && !items.some((x) => x.pressed)) {
                items.unshift({ kind: 'user', key: 'u-' + S.f.user, label: S.f.user, count: 0, failed: 0, pressed: true });
            }
        } else {
            items = (S.band.top_addresses || []).map((a) => ({ kind: 'ip', key: 'ip-' + a.ip_address, label: a.ip_address, count: a.count, failed: a.failed,
                pressed: S.f.ip === a.ip_address }));
            items.sort((a, b) => b.count - a.count);
            if (S.f.ip && !items.some((x) => x.pressed)) items.unshift({ kind: 'ip', key: 'ip-' + S.f.ip, label: S.f.ip, count: 0, failed: 0, pressed: true });
        }
        const pinned = items.filter((x) => x.pressed);
        const shown = pinned.concat(items.filter((x) => !x.pressed)).slice(0, slots());
        if (!shown.length) {
            // Under filters the panel is empty because nothing matches them, not because no one has come yet.
            const filtered = panelFiltered('active');
            const note = mode === 'people' ? (filtered ? 'No one matches.' : 'No one yet.') : (filtered ? 'No addresses match.' : 'No addresses yet.');
            plot.appendChild(el('span', 'act-plot-note', note));
            return;
        }
        const max = Math.max(1, ...shown.map((x) => x.count));
        const anyPressed = pinned.length > 0;
        shown.forEach((x) => {
            const label = x.kind === 'ip' ? midEllipsis(x.label, 17) : x.label;
            const row = rankRow({
                key: x.key, label, count: x.count, failed: x.failed, max, barWidth: 40, mono: x.kind === 'ip',
                pressed: x.pressed, cls: (x.pressed ? 'is-sel' : (anyPressed ? 'is-dim' : '')) + (x.kind === 'none' ? ' is-noaccount' : ''),
                aria: `${x.label}, ${plural(x.count, 'event', 'events')}, ${nf(x.failed)} failed or refused`,
                title: x.kind === 'none'
                    ? "Names typed at failed sign-ins, deleted accounts, and the server's operator (operator@host, for a change made from the host). They are counted together, not listed, because people sometimes type a password into the username box."
                    : `${x.label}: ${plural(x.count, 'event', 'events')}, ${nf(x.failed)} failed or refused. Click to filter.`,
                onClick: () => {
                    if (x.kind === 'none') setState({ f: { noAccount: !S.f.noAccount, user: '', userMatch: 'contains' } });
                    else if (x.kind === 'user') setState({ f: x.pressed ? { user: '', userMatch: 'contains' } : { user: x.label, userMatch: 'exact', noAccount: false } });
                    else setState({ f: { ip: x.pressed ? '' : x.label } });
                },
            });
            plot.appendChild(row);
        });
        setRoving(Array.from(plot.querySelectorAll('button')), key);
        roving(plot, 'button', 'y');
        refocus(panel, key);
    }

    function wireBand() {
        const band = $('act-band');
        band.addEventListener('pointerleave', () => applyHeldBand());
        band.addEventListener('focusout', () => setTimeout(applyHeldBand, 0));
        band.addEventListener('keydown', (e) => {
            if (e.key === '/' && !e.target.closest('input')) { e.preventDefault(); $('act-search').focus(); }
        });
        const more = $('act-more-charts');
        more.addEventListener('click', () => {
            const open = !band.classList.contains('show-more');
            storeSet('activity.moreCharts', open ? '1' : '0');
            renderBand();
        });
        document.addEventListener('click', (e) => {
            if (chartUi && chartUi.pinned != null && !chartUi.tip.contains(e.target) && !chartUi.hits.contains(e.target)) hideTip(chartUi);
            if (onlinePop && !onlinePop.contains(e.target) && !e.target.closest('.act-now-row, .act-head-online')) closeOnline(false);
        });
    }

    // ---- live --------------------------------------------------------------------------------------
    // The socket signals each committed row's id and category; the page fetches those rows through the
    // Events API with its filters (so the server decides what matches and names it for this viewer),
    // coalesced to one request a second. A slow poll for rows newer than the newest one held catches
    // any signal that was lost. None of these reads writes an audit row.

    // Rows in list order: newest first, by time then id, the way the server orders them.
    function rowKey(r) {
        const t = String(r.timestamp || '');
        const m = t.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?/);
        const stamp = m ? `${m[1]}.${(m[2] || '').padEnd(6, '0').slice(0, 6)}` : t;
        return `${stamp}|${r.id}`;
    }
    const newerFirst = (a, b) => (rowKey(a) < rowKey(b) ? 1 : rowKey(a) > rowKey(b) ? -1 : 0);

    function noteNewest(rows) {
        let best = null;
        rows.forEach((r) => { if (r.cursor && (!best || rowKey(r) > rowKey(best))) best = r; });
        if (!best) return;
        if (!S.newestRow || rowKey(best) > rowKey(S.newestRow)) { S.newestRow = best; S.newestCursor = best.cursor; }
    }

    function onSignal(e) {
        if (!S.active || S.blocked || !S.ready) return;
        const events = (e && e.detail && Array.isArray(e.detail.events)) ? e.detail.events : [];
        if (!events.length) return;
        noteBatch();
        if (events.some((x) => x && x.category === 'sign_in')) nowSoon();
        bandSoon();
        if (!rangeIsLive()) return;
        const allowed = signalCategories();
        const ids = events.filter((x) => x && x.id && (!allowed || allowed.has(x.category))).map((x) => String(x.id));
        if (!ids.length) return;
        if (S.paused || document.hidden) { keep(ids); return; }
        const now = Date.now();
        S.recent = S.recent.filter((r) => now - r.t < 1000);
        S.recent.push({ t: now, n: ids.length });
        if (S.recent.reduce((a, r) => a + r.n, 0) > LIVE_BURST) {
            S.burst = true;
            S.fetchQueue.clear();
        } else ids.forEach((id) => S.fetchQueue.add(id));
        scheduleFetch();
    }

    let fetchTimer = null, lastFetch = 0;
    function scheduleFetch() {
        if (fetchTimer) return;
        fetchTimer = setTimeout(runFetch, Math.max(0, lastFetch + 1000 - Date.now()));
    }

    async function runFetch() {
        fetchTimer = null;
        lastFetch = Date.now();
        if (!S.active || S.blocked || S.paused || document.hidden || !S.listLoaded) return;
        if (S.burst) { S.burst = false; S.fetchQueue.clear(); await onBurst(); return; }
        const ids = Array.from(S.fetchQueue);
        S.fetchQueue.clear();
        if (!ids.length) return;
        const seq = S.listSeq;
        const rows = [];
        try {
            for (let i = 0; i < ids.length; i += IDS_PER_FETCH) {
                const p = listParams();
                p.set('ids', ids.slice(i, i + IDS_PER_FETCH).join(','));
                const data = await get('/activity/events?' + p.toString());
                rows.push(...(data.events || []));
            }
        } catch (_) { return; /* the safety poll finds them */ }
        if (seq !== S.listSeq) return;           // the list was read again meanwhile
        arrive(rows);
    }

    // Rows newer than the newest one held, with two minutes before it for rows committed late.
    let pollTimer = null;
    function armPoll() {
        clearTimeout(pollTimer);
        pollTimer = null;
        if (!S.active || S.blocked) return;
        const ms = S.liveState === 'delayed' || S.liveState === 'connecting' ? 15000 : 60000;
        pollTimer = setTimeout(async () => { await safetyPoll(); armPoll(); }, ms);
    }

    async function safetyPoll() {
        if (!S.active || S.blocked || S.paused || document.hidden || !rangeIsLive() || !S.listLoaded || S.listError) return;
        const seq = S.listSeq;
        try {
            if (!S.newestCursor) {
                const head = listParams();
                head.set('limit', '1');
                const h = await get('/activity/events?' + head.toString());
                if (seq !== S.listSeq) return;
                noteNewest(h.events || []);
                if (!S.newestCursor) {
                    if (!S.rows.length && (h.events || []).length) reloadList({ keepDetail: true });
                    return;
                }
            }
            const p = listParams();
            p.set('after', S.newestCursor);
            p.set('overlap', '120');
            p.set('limit', '200');
            const data = await get('/activity/events?' + p.toString());
            if (seq !== S.listSeq) return;
            const rows = data.events || [];
            if (data.more && !rows.length) { reloadList({ keepDetail: true }); return; }   // its starting row is gone
            const before = S.newestCursor;
            arrive(rows, { fromPoll: true });
            // More than one read holds: read on from the newest row now held, or, when that did not
            // move, treat it as a burst.
            if (data.more) {
                if (S.newestCursor !== before) setTimeout(() => safetyPoll(), 1000);
                else await onBurst();
            }
        } catch (_) { /* the next poll tries again */ }
    }

    // What to do with rows that match and are new to the page: insert them, hold them behind the pill,
    // or only count them when they belong to a later page.
    function arrive(rows, opts) {
        if (!rows.length) return;
        const paged = S.pageSize !== 'all';
        const prevNewest = S.newestRow;
        noteNewest(rows);
        const have = new Set(S.rows.map((r) => r.id));
        S.held.forEach((r) => have.add(r.id));
        S.heldIds.forEach((id) => have.add(id));
        rows = rows.filter((r) => r && r.id && !have.has(r.id));
        // The poll reads two minutes back from the newest row held. A row it returns that is older than
        // that row and beyond the rows on screen was most likely counted already, so only a row newer
        // than the newest, or one that falls among the rows on screen (committed late), is new.
        if (opts && opts.fromPoll && prevNewest) {
            const last = S.rows[S.rows.length - 1];
            const onScreen = (r) => !(paged && S.page > 1) && last && rowKey(r) > rowKey(last);
            rows = rows.filter((r) => rowKey(r) > rowKey(prevNewest) || onScreen(r));
        }
        if (!rows.length) return;
        if (paged && S.page > 1) {
            rows.forEach((r) => S.heldIds.add(r.id));
            S.heldExtra += rows.length;
            if (S.total != null) S.total += rows.length;
            renderPill();
            renderCount();
            return;
        }
        const last = S.rows[S.rows.length - 1];
        const more = paged ? S.rows.length >= Number(S.pageSize) : !S.allDone;
        const fits = rows.filter((r) => !last || !more || rowKey(r) > rowKey(last));
        const later = rows.length - fits.length;
        if (S.total != null) S.total += rows.length;
        if (later) { renderCount(); renderPager(); }
        if (!fits.length) return;
        const limit = paged ? Number(S.pageSize) : 50;
        const hold = holdReason();
        if (fits.length > limit || S.heldBurst) {
            if (hold) {
                fits.forEach((r) => S.heldIds.add(r.id));
                S.heldBurst = true;
                S.heldExtra += fits.length;
                renderPill();
                renderCount();
            } else burstReload(fits.length);
            return;
        }
        if (hold) {
            S.held = S.held.concat(fits);
            renderPill();
            renderCount();
            watchHeld();
            return;
        }
        insertRows(fits);
    }

    // Why new rows wait behind the pill instead of going in: the detail is open, the top of the list is
    // out of view, or the pointer or the keys are busy on the list.
    function holdReason() {
        if (S.detailOpen) return 'detail';
        if (!firstRowInView()) return 'scroll';
        const now = Date.now();
        if (S.pointerDown) return 'pointer';
        if (S.lastPointer && now - S.lastPointer < 1500) return 'pointer';
        if (S.lastKey && now - S.lastKey < 3000 && focusInList()) return 'keys';
        return null;
    }

    function firstRowInView() {
        const first = rowNodes()[0];
        if (!first) return true;
        const r = first.getBoundingClientRect();
        const bar = $('act-toolbar').getBoundingClientRect();
        return r.bottom + r.height > bar.bottom;
    }

    // Put rows into the list in time order. Page 1 keeps its size: the last rows move to page 2. "All"
    // grows.
    function insertRows(rows, opts) {
        const o = opts || {};
        const paged = S.pageSize !== 'all';
        const ids = new Set(rows.map((r) => r.id));
        let merged = S.rows.concat(rows.filter((r) => !S.rows.some((x) => x.id === r.id))).sort(newerFirst);
        if (paged) {
            const size = Number(S.pageSize);
            if (merged.length > size) merged = merged.slice(0, size);
            if (S.total != null) S.pages = Math.max(1, Math.ceil(S.total / size));
        }
        S.rows = merged;
        if (S.detailOpen && S.selectedId && !S.rows.some((r) => r.id === S.selectedId) && S.detail) {
            S.detailWhere = paged ? 2 : 'later';
        }
        const light = o.highlight !== false && !S.highlightOff ? ids : null;
        renderList(light);
        if (S.detailOpen) renderDetail();
        announceNew(rows.length);
    }

    function burstReload(count) {
        const before = S.total;
        clearHeld();
        if (S.pageSize !== 'all') S.page = 1;
        writeHash();
        reloadList({ keepDetail: true }).then(() => {
            const n = count || (S.total != null && before != null ? S.total - before : 0);
            if (n > 0) announce(`${nf(n)} new ${n === 1 ? 'event' : 'events'}.`);
        });
    }

    async function onBurst() {
        const hold = holdReason() || (S.pageSize !== 'all' && S.page > 1);
        if (!hold) { burstReload(0); return; }
        try {
            const p = listParams();
            if (!S.newestCursor) return;
            p.set('after', S.newestCursor);
            p.set('count_only', 'true');
            const data = await get('/activity/events?' + p.toString());
            S.heldBurst = true;
            S.held = [];
            S.heldExtra = Math.max(S.heldExtra, data.count || 0);
            renderPill();
        } catch (_) { /* the next poll tries again */ }
    }

    function clearHeld() {
        S.held = [];
        S.heldExtra = 0;
        S.heldBurst = false;
        S.heldIds = new Set();
        renderPill();
    }

    function renderPill() {
        const pill = $('act-new-pill');
        if (!pill) return;
        const n = S.held.length + S.heldExtra;
        pill.hidden = !n;
        if (!n) return;
        if (S.pageSize !== 'all' && S.page > 1) pill.textContent = `${nf(n)} new ${n === 1 ? 'event' : 'events'} · Go to newest`;
        else pill.textContent = n === 1 ? '↑ 1 new event' : `↑ ${nf(n)} new events`;
    }

    // The pill: go to page 1 (or the top of "All"), put the held rows in and highlight them. The detail
    // stays open on its event.
    function takeHeld() {
        const list = $('act-list');
        if (list.getBoundingClientRect().top < 0) list.scrollIntoView({ block: 'start' });
        if ((S.pageSize !== 'all' && S.page > 1) || S.heldBurst) { burstReload(S.heldExtra + S.held.length); return; }
        const rows = S.held;
        clearHeld();
        if (rows.length) insertRows(rows, { counted: true });
    }

    // Held rows go in by themselves once nothing holds them: the pointer and the keys have been still,
    // the pointer left, the list is scrolled back to the top, or the detail closed.
    let heldTimer = null;
    function watchHeld() {
        if (heldTimer) return;
        heldTimer = setInterval(() => {
            if (!S.held.length || !S.active) { clearInterval(heldTimer); heldTimer = null; return; }
            flushHeldSoon();
        }, 500);
    }

    function flushHeldSoon() {
        if (!S.held.length || S.heldBurst || S.paused) return;
        if (S.pageSize !== 'all' && S.page > 1) return;
        if (holdReason()) return;
        const rows = S.held;
        S.held = [];
        renderPill();
        insertRows(rows, { counted: true });
    }

    // ---- the highlight on new rows ----

    let paintTimer = null;
    function markNew(ids) {
        const now = Date.now();
        ids.forEach((id) => S.newMarks.set(id, now));
        paintNew();
    }

    function paintNew() {
        clearTimeout(paintTimer);
        const now = Date.now();
        const reduce = reducedMotion();
        const endAt = reduce ? 10000 : 1800;
        let next = Infinity;
        S.newMarks.forEach((start, id) => {
            const age = now - start;
            const n = rowNode(id);
            if (age >= endAt) {
                S.newMarks.delete(id);
                if (n) n.classList.remove('is-new', 'is-fading');
                return;
            }
            if (!n) return;
            if (reduce || age < 600) {
                n.classList.add('is-new');
                n.classList.remove('is-fading');
                next = Math.min(next, (reduce ? 10000 : 600) - age);
            } else {
                n.classList.remove('is-new');
                n.classList.add('is-fading');
                next = Math.min(next, 1800 - age);
            }
        });
        if (next < Infinity) paintTimer = setTimeout(paintNew, next + 20);
    }

    // Under steady traffic (a batch every second for ten seconds) rows stop flashing until ten quiet
    // seconds pass.
    let quietTimer = null;
    function noteBatch() {
        const now = Date.now();
        S.batches = S.batches.filter((t) => now - t < 11000);
        S.batches.push(now);
        const seconds = new Set(S.batches.filter((t) => now - t < 10000).map((t) => Math.floor(t / 1000)));
        if (seconds.size >= 10) S.highlightOff = true;
        clearTimeout(quietTimer);
        quietTimer = setTimeout(() => { S.highlightOff = false; }, 10000);
    }

    let newTimer = null;
    function announceNew(n) {
        S.newPending += n;
        if (newTimer) return;
        const wait = Math.max(0, S.lastNewAnnounce + 30000 - Date.now());
        newTimer = setTimeout(() => {
            newTimer = null;
            const count = S.newPending;
            S.newPending = 0;
            if (!count || document.hidden || S.paused || !S.active) return;
            S.lastNewAnnounce = Date.now();
            const r = $('act-announce-new');
            if (r) { r.textContent = ''; setTimeout(() => { r.textContent = count === 1 ? '1 new event.' : `${nf(count)} new events.`; }, 30); }
        }, wait);
    }

    // ---- the band and Now on signals ----

    // The band's counts are shared between administrators for a few seconds, so a row written just
    // after they were counted is in the list's total and not yet in the band's. When the two disagree,
    // read the band again once the server counts afresh (it says when: fresh_seconds), once for each
    // pair of totals, so a lasting difference never becomes a loop. A time picked on the chart narrows
    // the list and not the band: the totals are not the same count then.
    let reconcileTimer = null, reconciledFor = null;
    function reconcileTotals() {
        const b = S.band;
        if (reconcileTimer || !b || !S.listLoaded || S.total == null || S.f.time || S.paused || !S.active) return;
        if (b.total === S.total) { reconciledFor = null; return; }
        const pair = `${b.total}|${S.total}`;
        if (pair === reconciledFor) return;
        reconciledFor = pair;
        const wait = Math.max(0, Number(b.fresh_seconds) || 0);
        reconcileTimer = setTimeout(() => { reconcileTimer = null; loadBand(true); }, wait * 1000 + 250);
    }

    let bandTimer = null, bandFirst = 0;
    function bandSoon() {
        if (S.paused || document.hidden) { S.bandDirty = true; return; }
        const now = Date.now();
        if (!bandFirst) bandFirst = now;
        clearTimeout(bandTimer);
        bandTimer = setTimeout(() => { bandTimer = null; bandFirst = 0; S.bandDirty = false; loadBand(true); },
            Math.min(10000, Math.max(0, bandFirst + 30000 - now)));
    }

    const nowSoon = debounce(() => loadNow(), 2000);

    // ---- kept ids: while the tab is hidden or the page is paused ----

    function keep(ids) {
        ids.forEach((id) => {
            if (S.kept.has(id)) return;
            if (S.kept.size < KEEP_IDS) S.kept.add(id);
            else S.keptOver = true;
        });
        if (S.paused) pausedCountSoon();
    }

    function clearKept() {
        S.kept = new Set();
        S.keptOver = false;
        S.keptCount = null;
        if (S.paused) renderLive();
    }

    let pausedTimer = null, pausedLast = 0;
    function pausedCountSoon() {
        if (pausedTimer) return;
        pausedTimer = setTimeout(async () => {
            pausedTimer = null;
            pausedLast = Date.now();
            if (!S.paused || S.blocked) return;
            if (S.keptOver) { S.keptCount = KEEP_IDS; renderLive(); return; }
            const ids = Array.from(S.kept);
            let count = 0;
            try {
                for (let i = 0; i < ids.length; i += 200) {
                    const p = listParams();
                    p.set('ids', ids.slice(i, i + 200).join(','));
                    p.set('count_only', 'true');
                    const data = await get('/activity/events?' + p.toString());
                    count += data.count || 0;
                }
            } catch (_) { return; }
            if (!S.paused) return;
            S.keptCount = count;
            renderLive();
        }, Math.max(0, pausedLast + 10000 - Date.now()));
    }

    // What was kept while hidden or paused is fetched like new signals, or past 500 ids page 1 is read
    // again.
    function catchUp() {
        const ids = Array.from(S.kept);
        const over = S.keptOver;
        S.kept = new Set();
        S.keptOver = false;
        S.keptCount = null;
        if (over) { S.burst = true; scheduleFetch(); }
        else if (ids.length) { ids.forEach((id) => S.fetchQueue.add(id)); scheduleFetch(); }
    }

    // ---- pause ----

    function setPaused(on) {
        S.paused = on;
        S.pausedAt = on ? new Date() : null;
        setPausedButton(on);
        if (on) {
            S.keptCount = 0;
            clearTimeout(bandTimer);
            bandTimer = null;
        } else {
            catchUp();
            loadBand(true);
            loadNow();
            flushHeldSoon();
        }
        renderLive();
    }

    // ---- the live state in the header ----

    function computeLive() {
        if (!rangeIsLive()) return 'notlive';
        if (navigator.onLine === false) return 'offline';
        if (S.paused) return 'paused';
        const st = window.dockvaultSocketState || S.socketState;
        if (st === 'open') return 'live';
        if (S.socketDownSince && Date.now() - S.socketDownSince >= 10000) return 'delayed';
        return 'connecting';
    }

    function renderLive() {
        const box = $('act-live');
        if (!box) return;
        const st = computeLive();
        const prev = S.liveState;
        S.liveState = st;
        let label, title;
        if (st === 'live') { label = 'Live'; title = 'New events appear as they happen.'; }
        else if (st === 'paused') {
            label = S.keptOver || (S.keptCount || 0) >= KEEP_IDS ? 'Paused · 500+ new' : (S.keptCount ? `Paused · ${nf(S.keptCount)} new` : 'Paused');
            title = `Paused at ${hmText(S.pausedAt || new Date())}. New events are counted, not shown.`;
        } else if (st === 'connecting') { label = 'Connecting…'; title = 'Connecting to the live updates.'; }
        else if (st === 'delayed') { label = 'Delayed'; title = 'The live connection is down. Checking for new events every 15 seconds.'; }
        else if (st === 'offline') { label = 'Offline'; title = `Your device is offline. Showing events up to ${hmText(S.lastRead || new Date())}.`; }
        else {
            const to = toDate(S.range.to);
            label = 'Not live';
            title = to ? `The time range ends on ${dayMonth(to)} at ${hmText(to)}, so no new events can match.` : 'The time range ends in the past, so no new events can match.';
        }
        box.dataset.state = st;
        box.title = title;
        const text = $('act-live-label');
        if (text) text.textContent = label;
        const dot = box.querySelector('.act-live-dot');
        if (dot) {
            dot.replaceChildren();
            if (st === 'paused') dot.appendChild(icon('pause'));
        }
        if (prev !== st) {
            if (st === 'delayed') announce('Live updates are delayed.');
            else if (st === 'offline') announce('You are offline.');
            else if (st === 'live' && (S.liveAnnounced === 'delayed' || S.liveAnnounced === 'offline')) announce('Live updates are back.');
            if (st === 'delayed' || st === 'offline' || st === 'live') S.liveAnnounced = st;
            if ((prev === 'live') !== (st === 'live')) armPoll();
            const nowDot = document.querySelector('#act-p-now .act-now-dot');
            if (nowDot) nowDot.classList.toggle('is-live', st === 'live');
        }
    }

    function onSocket(e) {
        const st = e && e.detail && e.detail.state;
        if (!st) return;
        S.socketState = st;
        if (st === 'open') S.socketDownSince = null;
        else if (!S.socketDownSince) {
            S.socketDownSince = Date.now();
            setTimeout(() => renderLive(), 10050);
        }
        renderLive();
        if (st === 'open' && S.active) safetyPoll();
    }

    // ---- the filter panel --------------------------------------------------------------------------
    // A popover under Filter from a tablet up, where each change applies at once; a full-screen dialog
    // on a phone, where changes are staged until "Show N events".

    const P = { open: false, staged: false, draft: null, built: false, openedAt: 0, customOpen: false, countSeq: 0, expanded: new Set() };

    function copyState(range, f) {
        return { range: Object.assign({}, range), f: JSON.parse(JSON.stringify(f)) };
    }

    function panelState() { return P.staged && P.draft ? P.draft : { range: S.range, f: S.f }; }

    // Change what the panel shows: at once on a wide screen, staged on a phone.
    function panelChange(fn) {
        if (P.staged) {
            fn(P.draft);
            renderPanelState();
            stagedCountSoon();
            return;
        }
        const d = copyState(S.range, S.f);
        const before = rangeKeyOf(d.range);
        fn(d);
        const patch = { f: d.f };
        if (rangeKeyOf(d.range) !== before) { patch.range = d.range; d.f.time = null; }
        setState(patch);
    }

    function rangeKeyOf(r) { return [r.kind, r.from || '', r.to || ''].join('|'); }

    // Whole categories and single events on a draft, kept apart as setCategory/actionsPatch keep them.
    function draftCategory(f, key, on) {
        f.act = f.act.filter((a) => actionCategory(a) !== key);
        f.cat = f.cat.filter((c) => c !== key);
        if (on) f.cat.push(key);
    }

    function draftAction(f, name, on) {
        const key = actionCategory(name);
        const all = actionsOf(key);
        if (on) {
            if (f.cat.includes(key) || f.act.includes(name)) return;
            f.act.push(name);
            if (all.length && all.every((a) => f.act.includes(a))) draftCategory(f, key, true);
        } else if (f.cat.includes(key)) {
            f.cat = f.cat.filter((c) => c !== key);
            f.act = f.act.concat(all.filter((a) => a !== name && !f.act.includes(a)));
        } else f.act = f.act.filter((a) => a !== name);
    }

    function fpSection(key, title) {
        const sec = el('section', 'act-fp-sec');
        sec.dataset.sec = key;
        const h = el('h3', 'act-fp-title', title);
        h.id = `act-fp-h-${key}`;
        sec.setAttribute('aria-labelledby', h.id);
        sec.appendChild(h);
        return sec;
    }

    function checkRow(name, value, label, hint) {
        const row = el('label', 'act-fp-check');
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.name = name;
        box.value = value;
        row.append(box, el('span', 'act-fp-check-label', label));
        if (hint) row.appendChild(el('span', 'act-fp-hint', hint));
        return { row, box };
    }

    function localInput(v) {
        const d = toDate(v);
        if (!d) return '';
        const pad = (n) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    function buildPanel() {
        const host = $('act-fp-content');
        host.replaceChildren();
        const body = el('div', 'act-fp-body');

        // Time range
        const time = fpSection('time', 'Time range');
        const radios = el('div', 'act-fp-radios');
        radios.setAttribute('role', 'radiogroup');
        radios.setAttribute('aria-labelledby', 'act-fp-h-time');
        [['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['all', 'All time'], ['custom', 'Custom']].forEach(([v, label]) => {
            const row = el('label', 'act-fp-check');
            const r = document.createElement('input');
            r.type = 'radio';
            r.name = 'act-fp-range';
            r.value = v;
            r.addEventListener('change', () => {
                if (v === 'custom') { P.customOpen = true; renderPanelState(); const from = $('act-fp-from'); if (from) from.focus(); return; }
                P.customOpen = false;
                panelChange((d) => { d.range = { kind: v, from: null, to: null }; });
            });
            row.append(r, el('span', 'act-fp-check-label', label));
            radios.appendChild(row);
        });
        time.appendChild(radios);
        const custom = el('div', 'act-fp-custom');
        [['act-fp-from', 'From'], ['act-fp-to', 'To']].forEach(([id, label]) => {
            const lab = el('label', 'act-fp-field');
            lab.appendChild(el('span', 'act-fp-field-label', label));
            const input = el('input', 'form-control');
            input.type = 'datetime-local';
            input.id = id;
            input.addEventListener('change', () => applyCustomRange());
            lab.appendChild(input);
            custom.appendChild(lab);
        });
        custom.appendChild(el('p', 'act-fp-help', 'An empty From means from the beginning; an empty To means now.'));
        time.appendChild(custom);
        body.appendChild(time);

        // Category, with each category's events behind a disclosure
        const cat = fpSection('category', 'Category');
        const tree = el('ul', 'act-fp-tree');
        (S.catalog ? S.catalog.categories : []).forEach((c) => {
            const li = el('li', 'act-fp-cat');
            li.dataset.key = c.key;
            const head = el('div', 'act-fp-cat-head');
            if (c.actions.length) {
                const dis = button('act-fp-disclose', null, { 'aria-expanded': 'false', 'aria-label': `Show the events of ${c.label}` });
                dis.appendChild(icon('chevron-right'));
                dis.addEventListener('click', () => {
                    if (P.expanded.has(c.key)) P.expanded.delete(c.key); else P.expanded.add(c.key);
                    renderPanelState();
                });
                head.appendChild(dis);
            } else head.appendChild(el('span', 'act-fp-disclose-gap'));
            const { row, box } = checkRow('act-fp-cat', c.key, c.label);
            box.addEventListener('change', () => panelChange((d) => draftCategory(d.f, c.key, box.checked)));
            row.appendChild(el('span', 'act-fp-count'));
            head.appendChild(row);
            li.appendChild(head);
            if (c.actions.length) {
                const sub = el('ul', 'act-fp-events');
                sub.hidden = true;
                c.actions.forEach((a) => {
                    const item = el('li');
                    const r = checkRow('act-fp-act', a.name, a.label);
                    r.box.addEventListener('change', () => panelChange((d) => draftAction(d.f, a.name, r.box.checked)));
                    item.appendChild(r.row);
                    sub.appendChild(item);
                });
                li.appendChild(sub);
            }
            tree.appendChild(li);
        });
        cat.appendChild(tree);
        const warn = el('p', 'act-fp-warn');
        warn.id = 'act-fp-cat-warn';
        warn.hidden = true;
        warn.textContent = 'That is more than 50 single events alongside whole categories; only the first 50 are matched. Choose whole categories, or fewer events.';
        cat.appendChild(warn);
        body.appendChild(cat);

        // Status
        const status = fpSection('status', 'Status');
        STATUS_CHOICES.forEach(([k, label]) => {
            const { row, box } = checkRow('act-fp-status', k, label, k === 'authorized' ? 'A download or preview that was permitted.' : null);
            box.addEventListener('change', () => panelChange((d) => {
                d.f.status = d.f.status.filter((s) => s !== k);
                if (box.checked) d.f.status.push(k);
            }));
            status.appendChild(row);
        });
        body.appendChild(status);

        // Channel
        const ch = fpSection('channel', 'Channel');
        CHANNELS.forEach((c) => {
            const { row, box } = checkRow('act-fp-ch', c, CHANNEL_LABELS[c], c === 'unknown' ? 'Events from before 0.33.0, and work the server does on its own.' : null);
            box.addEventListener('change', () => panelChange((d) => {
                d.f.ch = d.f.ch.filter((x) => x !== c);
                if (box.checked) d.f.ch.push(c);
            }));
            ch.appendChild(row);
        });
        body.appendChild(ch);

        // Person: accounts only are suggested; free text finds names that contain it.
        const person = fpSection('person', 'Person');
        const pWrap = el('div', 'act-ta');
        const pInput = el('input', 'form-control');
        pInput.type = 'search';
        pInput.id = 'act-fp-user';
        pInput.maxLength = 128;
        pInput.placeholder = 'A username';
        pInput.setAttribute('aria-labelledby', 'act-fp-h-person');
        pInput.autocomplete = 'off';
        pWrap.appendChild(pInput);
        person.appendChild(pWrap);
        typeahead(pInput, {
            min: 2,
            source: async (q) => {
                const d = await get(`/activity/usernames?q=${encodeURIComponent(q)}&limit=8`);
                return (d.usernames || []).filter((u) => u.account).slice(0, 8)
                    .map((u) => ({ value: u.username, label: u.username, sub: u.active === false ? 'Deactivated account' : 'Account' }));
            },
            onPick: (item) => panelChange((d) => { d.f.user = item.value; d.f.userMatch = 'exact'; d.f.noAccount = false; }),
            onFree: (text) => panelChange((d) => { d.f.user = text; d.f.userMatch = 'contains'; }),
            current: () => panelState().f.user,
        });
        const na = checkRow('act-fp-noaccount', '1', 'Only names with no account');
        na.box.id = 'act-fp-noaccount';
        na.box.addEventListener('change', () => panelChange((d) => { d.f.noAccount = na.box.checked; if (na.box.checked) { d.f.user = ''; d.f.userMatch = 'contains'; } }));
        person.appendChild(na.row);
        body.appendChild(person);

        // Address
        const addr = fpSection('address', 'Address');
        const aInput = el('input', 'form-control act-mono');
        aInput.type = 'search';
        aInput.id = 'act-fp-ip';
        aInput.maxLength = 64;
        aInput.placeholder = '203.0.113.7 or 203.0.113.0/24';
        aInput.setAttribute('aria-labelledby', 'act-fp-h-address');
        aInput.setAttribute('aria-describedby', 'act-fp-ip-error');
        const aErr = el('p', 'form-error act-fp-error');
        aErr.id = 'act-fp-ip-error';
        aErr.hidden = true;
        const applyIp = () => {
            const v = aInput.value.trim();
            if (v === panelState().f.ip) { aErr.hidden = true; aInput.removeAttribute('aria-invalid'); return; }
            if (v && !validAddress(v)) {
                aErr.textContent = 'Enter an address like 203.0.113.7 or a network like 203.0.113.0/24.';
                aErr.hidden = false;
                aInput.setAttribute('aria-invalid', 'true');
                return;
            }
            aErr.hidden = true;
            aInput.removeAttribute('aria-invalid');
            panelChange((d) => { d.f.ip = v; });
        };
        aInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); applyIp(); } });
        aInput.addEventListener('blur', applyIp);
        addr.append(aInput, aErr);
        body.appendChild(addr);

        // Temporary credential
        const tc = fpSection('tc', 'Temporary credential');
        const tWrap = el('div', 'act-ta');
        const tInput = el('input', 'form-control');
        tInput.type = 'search';
        tInput.id = 'act-fp-tc';
        tInput.maxLength = 128;
        tInput.placeholder = "A credential's name";
        tInput.setAttribute('aria-labelledby', 'act-fp-h-tc');
        tInput.autocomplete = 'off';
        tWrap.appendChild(tInput);
        tc.appendChild(tWrap);
        typeahead(tInput, {
            min: 2,
            source: async (q) => {
                const d = await get(`/activity/temp-credentials?q=${encodeURIComponent(q)}&limit=8`);
                return (d.temp_credentials || []).map((t) => {
                    const exp = toDate(t.expires_at);
                    let sub = 'Revoked';
                    if (t.state === 'active') sub = exp ? `Active · expires ${dayMonth(exp)}` : 'Active';
                    else if (t.state === 'expired') sub = exp ? `Expired ${dayMonth(exp)}` : 'Expired';
                    return { value: t.id, label: t.name, sub };
                });
            },
            onPick: (item) => panelChange((d) => { d.f.tcId = item.value; d.f.tcName = item.label; }),
            onFree: (text) => panelChange((d) => { d.f.tcId = ''; d.f.tcName = text; }),
            current: () => panelState().f.tcName,
        });
        body.appendChild(tc);

        // Vault: the vaults this administrator can open, named as the Vaults page names them.
        const vault = fpSection('vault', 'Vault');
        const vWrap = el('div', 'act-ta');
        const vInput = el('input', 'form-control');
        vInput.type = 'search';
        vInput.id = 'act-fp-vault';
        vInput.maxLength = 128;
        vInput.placeholder = 'A vault you can open';
        vInput.setAttribute('aria-labelledby', 'act-fp-h-vault');
        vInput.setAttribute('aria-describedby', 'act-fp-vault-help');
        vInput.autocomplete = 'off';
        vWrap.appendChild(vInput);
        vault.appendChild(vWrap);
        typeahead(vInput, {
            min: 1,
            source: async (q) => {
                const vaults = await vaultList();
                const needle = q.toLowerCase();
                return vaults.filter((v) => vaultDisplayName(v).toLowerCase().includes(needle)).slice(0, 8)
                    .map((v) => ({ value: String(v.id), label: vaultDisplayName(v), sub: v.type === 'zero_knowledge' ? 'Zero-knowledge vault' : 'Vault' }));
            },
            onPick: (item) => panelChange((d) => { d.f.vault = item.value; }),
            onFree: (text) => { if (!text) panelChange((d) => { d.f.vault = ''; }); else renderPanelState(); },
            current: () => (panelState().f.vault ? vaultChipName(panelState().f.vault) : ''),
        });
        const vHelp = el('p', 'act-fp-help', "Only vaults you can open are listed. To filter by another vault, use the link in an event's details.");
        vHelp.id = 'act-fp-vault-help';
        vault.appendChild(vHelp);
        body.appendChild(vault);

        host.appendChild(body);

        const foot = el('div', 'act-fp-foot');
        const clear = button('btn btn-ghost btn-sm act-fp-clear', 'Clear all');
        clear.addEventListener('click', () => panelChange((d) => { d.f = Object.assign(emptyFilters(), { q: d.f.q }); }));
        const done = button('btn btn-primary btn-sm act-fp-done', 'Done');
        done.id = 'act-fp-done';
        done.addEventListener('click', () => {
            if (P.staged) applyStaged();
            else closePanel(true);
        });
        foot.append(clear, done);
        host.appendChild(foot);
        P.built = true;
    }

    function applyCustomRange() {
        const from = toDate($('act-fp-from').value);
        const to = toDate($('act-fp-to').value);
        if (from && to && to <= from) return;
        panelChange((d) => {
            if (from) d.range = { kind: 'custom', from: iso(from), to: to ? iso(to) : null };
            else d.range = { kind: 'all', from: null, to: to ? iso(to) : null };
        });
    }

    // An IPv4 or IPv6 address, or a network in CIDR form. The server reads it again; this spares a
    // request that could only match nothing.
    function validAddress(v) {
        const m = v.match(/^([^/]+)(?:\/(\d{1,3}))?$/);
        if (!m) return false;
        const host = m[1], bits = m[2] == null ? null : Number(m[2]);
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
            if (!host.split('.').every((p) => Number(p) <= 255)) return false;
            return bits == null || bits <= 32;
        }
        if (host.includes(':') && /^[0-9a-fA-F:.]+$/.test(host)) {
            // Eight groups, or fewer around one "::"; an IPv4 tail counts as two. An empty group (":::",
            // or a single ":" at either end) is not an address.
            const halves = host.split('::');
            if (halves.length > 2) return false;
            const side = (s) => (s ? s.split(':') : []);
            const groups = side(halves[0]).concat(halves.length === 2 ? side(halves[1]) : []);
            let count = 0;
            for (let i = 0; i < groups.length; i++) {
                const g = groups[i];
                if (/^[0-9a-fA-F]{1,4}$/.test(g)) count += 1;
                else if (i === groups.length - 1 && /^\d{1,3}(\.\d{1,3}){3}$/.test(g) && g.split('.').every((p) => Number(p) <= 255)) count += 2;
                else return false;
            }
            if (halves.length === 2 ? count > 7 : count !== 8) return false;
            return bits == null || bits <= 128;
        }
        return false;
    }

    // This viewer's vaults. A list that comes back after a sign-out belongs to the person who asked, not
    // to whoever signed in since, so it is dropped.
    async function vaultList() {
        if (S.vaultList) return S.vaultList;
        const asked = S;
        let list = [];
        try {
            const all = await apiRequest('/vaults', { silent: true });
            const mine = (typeof state !== 'undefined' && state.allVaults) || [];
            list = (Array.isArray(all) ? all : []).filter((v) => !v.is_receiver)
                .map((v) => mine.find((m) => String(m.id) === String(v.id)) || v);
        } catch (_) { list = []; }
        if (asked !== S) return [];
        S.vaultList = list;
        return list;
    }

    // Draw the panel's controls from the state (or, on a phone, the staged draft).
    function renderPanelState() {
        if (!P.built || !P.open) return;
        const { range, f } = panelState();
        const counts = {};
        ((S.band && S.band.categories) || []).forEach((c) => { counts[c.key] = c.count; });
        const customKind = range.kind === 'custom' || (range.kind === 'all' && range.to);
        document.querySelectorAll('input[name="act-fp-range"]').forEach((r) => {
            r.checked = r.value === 'custom' ? (customKind || P.customOpen) : (!customKind && !P.customOpen && r.value === range.kind);
        });
        const custom = document.querySelector('#act-fp-content .act-fp-custom');
        if (custom) custom.hidden = !(customKind || P.customOpen);
        const from = $('act-fp-from'), to = $('act-fp-to');
        if (from && document.activeElement !== from) from.value = customKind ? localInput(range.from) : '';
        if (to && document.activeElement !== to) to.value = customKind ? localInput(range.to) : '';
        document.querySelectorAll('#act-fp-content .act-fp-cat').forEach((li) => {
            const key = li.dataset.key;
            const box = li.querySelector('input[name="act-fp-cat"]');
            const events = actionsOf(key);
            const some = events.some((a) => f.act.includes(a));
            box.checked = f.cat.includes(key);
            box.indeterminate = !box.checked && some;
            box.setAttribute('aria-checked', box.checked ? 'true' : (some ? 'mixed' : 'false'));
            const count = li.querySelector('.act-fp-count');
            if (count) count.textContent = counts[key] != null ? nf(counts[key]) : '';
            const dis = li.querySelector('.act-fp-disclose');
            const sub = li.querySelector('.act-fp-events');
            const open = P.expanded.has(key);
            if (dis) { dis.setAttribute('aria-expanded', open ? 'true' : 'false'); dis.classList.toggle('is-open', open); }
            if (sub) {
                sub.hidden = !open;
                sub.querySelectorAll('input[name="act-fp-act"]').forEach((b) => { b.checked = f.cat.includes(key) || f.act.includes(b.value); });
            }
        });
        const warn = $('act-fp-cat-warn');
        if (warn) {
            let names = f.act.length;
            if (f.cat.length && f.act.length) f.cat.forEach((c) => { names += actionsOf(c).length; });
            warn.hidden = !(f.cat.length && f.act.length && names > 50);
        }
        document.querySelectorAll('input[name="act-fp-status"]').forEach((b) => { b.checked = f.status.includes(b.value); });
        document.querySelectorAll('input[name="act-fp-ch"]').forEach((b) => { b.checked = f.ch.includes(b.value); });
        const user = $('act-fp-user');
        if (user && document.activeElement !== user) user.value = f.noAccount ? '' : f.user;
        if (user) user.disabled = f.noAccount;
        const na = $('act-fp-noaccount');
        if (na) na.checked = f.noAccount;
        const ip = $('act-fp-ip');
        if (ip && document.activeElement !== ip) ip.value = f.ip;
        const tc = $('act-fp-tc');
        if (tc && document.activeElement !== tc) tc.value = f.tcName || (f.tcId ? String(f.tcId).slice(0, 8) : '');
        const vault = $('act-fp-vault');
        if (vault && document.activeElement !== vault) vault.value = f.vault ? vaultChipName(f.vault) : '';
    }

    async function openPanel(sectionKey) {
        closeMenu();
        closeOnline(false);
        if (!S.catalog) { try { await loadCatalog(); } catch (_) { return; } }
        if (!P.built) buildPanel();
        P.staged = isNarrow();
        P.draft = copyState(S.range, S.f);
        P.customOpen = sectionKey === 'time';
        if (sectionKey === 'category') {
            chosenCategories().forEach((k) => { if (S.f.act.some((a) => actionCategory(a) === k)) P.expanded.add(k); });
        }
        P.open = true;
        P.openedAt = Date.now();
        const content = $('act-fp-content');
        const btn = $('act-filter-btn');
        if (P.staged) {
            $('act-filter-modal-body').appendChild(content);
            openModal('act-filter-modal');
            $('act-filter-modal').dataset.actOpen = '1';
            stagedCountSoon.now();
        } else {
            $('act-filter-panel').appendChild(content);
            $('act-filter-panel').hidden = false;
            btn.setAttribute('aria-expanded', 'true');
            fitOverlays();
        }
        renderPanelState();
        const done = $('act-fp-done');
        if (done) done.textContent = P.staged ? 'Show events' : 'Done';
        const sec = content.querySelector(`[data-sec="${sectionKey || 'time'}"]`);
        const target = sec && (sec.querySelector('input:not([disabled]):checked') || sec.querySelector('input:not([disabled]), button'));
        if (sec && sectionKey) sec.scrollIntoView({ block: 'nearest' });
        if (target) target.focus({ preventScroll: !!sectionKey });
    }

    function closePanel(returnFocus) {
        if (!P.open) return false;
        P.open = false;
        P.customOpen = false;
        P.draft = null;
        const panel = $('act-filter-panel');
        panel.hidden = true;
        $('act-filter-btn').setAttribute('aria-expanded', 'false');
        const modal = $('act-filter-modal');
        if (modal.classList.contains('active')) {
            delete modal.dataset.actOpen;
            modal.classList.remove('active');
        }
        panel.appendChild($('act-fp-content'));
        if (returnFocus) $('act-filter-btn').focus();
        return true;
    }

    function applyStaged() {
        const d = P.draft;
        if (!d) { closePanel(true); return; }
        const patch = { f: d.f };
        if (rangeKeyOf(d.range) !== rangeKey()) { patch.range = d.range; d.f.time = null; }
        closePanel(true);
        setState(patch, { now: true });
    }

    // On a phone the apply button says how many events the staged filters match.
    const stagedCountSoon = debounce(async () => {
        if (!P.open || !P.staged || !P.draft) return;
        const seq = ++P.countSeq;
        const done = $('act-fp-done');
        try {
            const p = listParamsFor(P.draft.range, P.draft.f);
            p.set('count_only', 'true');
            const data = await get('/activity/events?' + p.toString());
            if (seq !== P.countSeq || !P.open) return;
            const n = data.count || 0;
            done.textContent = n === 0 ? 'Show no events' : n === 1 ? 'Show 1 event' : `Show ${nf(n)} events`;
            done.disabled = n === 0;
        } catch (_) {
            if (seq === P.countSeq) { done.textContent = 'Show events'; done.disabled = false; }
        }
    }, 400);

    function wirePanel() {
        $('act-filter-btn').addEventListener('click', () => {
            if (P.open && !P.staged) closePanel(true);
            else openPanel(null);
        });
        const modal = $('act-filter-modal');
        modal.querySelector('.act-fm-close').addEventListener('click', () => closePanel(true));
        modal.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') { e.stopPropagation(); closePanel(true); }
            else if (e.key === 'Tab') trapFocus(modal, e);
        });
        new MutationObserver(() => {
            if (!modal.classList.contains('active') && modal.dataset.actOpen) { delete modal.dataset.actOpen; closePanel(false); }
        }).observe(modal, { attributes: true, attributeFilter: ['class'] });
        document.addEventListener('click', (e) => {
            if (!P.open || P.staged || Date.now() - P.openedAt < 60) return;
            if ($('act-filter-panel').contains(e.target) || $('act-filter-btn').contains(e.target)) return;
            if (e.target.closest && e.target.closest('.act-ta-list')) return;
            closePanel(false);
        });
    }

    // A text field with suggestions: Up and Down move through them, Enter picks one or takes the text as
    // typed, Escape closes the list.
    function typeahead(input, opts) {
        const list = el('ul', 'act-ta-list');
        list.id = input.id + '-list';
        list.setAttribute('role', 'listbox');
        list.hidden = true;
        input.parentNode.appendChild(list);
        input.setAttribute('role', 'combobox');
        input.setAttribute('aria-autocomplete', 'list');
        input.setAttribute('aria-expanded', 'false');
        input.setAttribute('aria-controls', list.id);
        let items = [], active = -1, seq = 0;
        const close = () => {
            list.hidden = true;
            list.replaceChildren();
            items = [];
            active = -1;
            input.setAttribute('aria-expanded', 'false');
            input.removeAttribute('aria-activedescendant');
        };
        const highlight = (i) => {
            active = i;
            Array.from(list.children).forEach((li, j) => li.setAttribute('aria-selected', j === i ? 'true' : 'false'));
            if (i >= 0 && list.children[i]) input.setAttribute('aria-activedescendant', list.children[i].id);
            else input.removeAttribute('aria-activedescendant');
        };
        const pick = (item) => { close(); input.value = item.label; opts.onPick(item); };
        const fetchSoon = debounce(async () => {
            const q = input.value.trim();
            if (q.length < opts.min) { close(); return; }
            const my = ++seq;
            let found = [];
            try { found = await opts.source(q); } catch (_) { found = []; }
            if (my !== seq || document.activeElement !== input) return;
            items = found;
            list.replaceChildren();
            items.forEach((item, i) => {
                const li = el('li', 'act-ta-item');
                li.id = `${list.id}-${i}`;
                li.setAttribute('role', 'option');
                li.setAttribute('aria-selected', 'false');
                li.appendChild(el('span', 'act-ta-label', item.label));
                if (item.sub) li.appendChild(el('span', 'act-ta-sub', item.sub));
                li.addEventListener('mousedown', (e) => { e.preventDefault(); pick(item); });
                list.appendChild(li);
            });
            list.hidden = !items.length;
            input.setAttribute('aria-expanded', items.length ? 'true' : 'false');
            highlight(-1);
        }, 200);
        input.addEventListener('input', () => fetchSoon());
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown' && items.length) { e.preventDefault(); highlight(Math.min(items.length - 1, active + 1)); }
            else if (e.key === 'ArrowUp' && items.length) { e.preventDefault(); highlight(Math.max(-1, active - 1)); }
            else if (e.key === 'Enter') {
                e.preventDefault();
                if (active >= 0 && items[active]) pick(items[active]);
                else { close(); const v = input.value.trim(); if (v !== (opts.current() || '')) opts.onFree(v); }
            } else if (e.key === 'Escape' && !list.hidden) { e.preventDefault(); e.stopPropagation(); close(); }
        });
        // Leaving the field takes what it holds, at once, so a click on Done or "Show N events" right
        // after typing applies it. A suggestion is picked on mousedown, which keeps the focus here.
        input.addEventListener('blur', () => {
            close();
            const v = input.value.trim();
            if (v !== (opts.current() || '')) opts.onFree(v);
        });
    }

    // ---- saved searches ----------------------------------------------------------------------------
    // Kept on the server for each administrator. A search holds the filters and the range; a vault by
    // its id only, never its name, and a picked time on the chart not at all.

    function savedFilters(range, f) {
        const out = {};
        if (f.cat.length) out.category = f.cat.slice();
        if (f.act.length) out.action = f.act.slice();
        if (f.status.length) out.status = f.status.slice();
        if (f.ch.length) out.channel = f.ch.slice();
        if (f.noAccount) out.no_account = true;
        else if (f.user) {
            out.user = f.user;
            if (f.userMatch === 'exact') out.user_match = 'exact';
        }
        if (f.ip) out.ip = f.ip;
        if (f.q) out.q = f.q;
        if (f.tcId) out.temp_credential_id = f.tcId;
        if (f.tcName) out.temp_credential = f.tcName;
        if (f.vault) out.vault_id = f.vault;
        if (range.kind === 'custom') {
            if (range.from) out.from_date = range.from;
            if (range.to) out.to_date = range.to;
        } else if (range.kind === 'all' && range.to) out.to_date = range.to;
        else out.range = range.kind;
        return out;
    }

    function stateFromSaved(s) {
        const f = emptyFilters();
        const lst = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
        f.cat = lst(s.category);
        f.act = lst(s.action);
        f.status = lst(s.status);
        f.ch = lst(s.channel);
        f.noAccount = s.no_account === true;
        if (!f.noAccount && s.user) { f.user = String(s.user); f.userMatch = s.user_match === 'exact' ? 'exact' : 'contains'; }
        f.ip = s.ip || '';
        f.q = s.q || '';
        f.tcId = s.temp_credential_id || '';
        f.tcName = s.temp_credential || '';
        f.vault = s.vault_id || '';
        let range = { kind: '7d', from: null, to: null };
        if (['24h', '7d', '30d', 'all'].includes(s.range)) range = { kind: s.range, from: null, to: null };
        else if (s.from_date) range = { kind: 'custom', from: s.from_date, to: s.to_date || null };
        else if (s.to_date) range = { kind: 'all', from: null, to: s.to_date };
        return { range, f };
    }

    const stable = (o) => JSON.stringify(Object.keys(o).sort().reduce((a, k) => { a[k] = Array.isArray(o[k]) ? o[k].slice().sort() : o[k]; return a; }, {}));

    function savedChanged() {
        return !!S.savedLoaded && stable(savedFilters(S.range, Object.assign({}, S.f, { time: null }))) !== stable(S.savedLoaded.filters || {});
    }

    // "Last 7 days · Failed or refused · Sign-in and sessions"
    function savedSummary(filters) {
        const { range, f } = stateFromSaved(filters);
        const bits = [];
        if (range.kind === 'custom' || (range.kind === 'all' && range.to)) {
            const keep = S.range;
            S.range = range;
            bits.push(customShort());
            S.range = keep;
        } else bits.push(RANGE_TITLES[range.kind]);
        chipList(f).forEach(([text]) => bits.push(text.replace(/^(Category|Event|Status|Channel): /, '')));
        if (f.q) bits.push(`"${f.q}"`);
        return bits.join(' · ');
    }

    // A name from the chips, never a vault's name.
    function suggestName() {
        const f = S.f;
        const bits = [];
        if (f.status.length) bits.push(STATUS_CHOICES.filter(([k]) => f.status.includes(k)).map(([, l]) => l).join(', '));
        if (f.act.length) bits.push(plusMore(f.act.map(actionLabel)));
        if (f.cat.length) bits.push(plusMore(f.cat.map(catLabel)));
        if (f.noAccount) bits.push('names with no account');
        else if (f.user) bits.push(f.user);
        if (f.ip) bits.push(f.ip);
        if (f.tcName) bits.push(f.tcName);
        if (f.vault) bits.push('one vault');
        if (f.ch.length) bits.push(f.ch.map(channelLabel).join(', '));
        if (f.q) bits.push(`"${f.q}"`);
        if (!bits.length) bits.push(S.range.kind === 'custom' ? customShort() : RANGE_TITLES[S.range.kind] || 'All events');
        return bits.join(' · ').slice(0, 80);
    }

    async function loadSaved() {
        try {
            S.saved = await get('/activity/saved-searches');
        } catch (_) {
            if (!S.saved) S.saved = { searches: [], limit: 50 };
        }
        if (S.savedLoaded && !S.saved.searches.some((s) => s.id === S.savedLoaded.id)) S.savedLoaded = null;
        renderSavedButton();
        renderChips();
    }

    function renderSavedButton() {
        const label = $('act-saved-label');
        if (!label) return;
        if (S.savedLoaded) {
            label.textContent = savedChanged() ? `${S.savedLoaded.name} (changed)` : S.savedLoaded.name;
            $('act-saved-btn').title = `Saved search: ${S.savedLoaded.name}`;
        } else {
            label.textContent = 'Saved';
            $('act-saved-btn').title = 'Saved searches';
        }
    }

    function renderSavedMenu() {
        const menu = $('act-saved-menu');
        menu.replaceChildren();
        const list = (S.saved && S.saved.searches) || [];
        if (!list.length) {
            menu.appendChild(el('p', 'act-menu-empty', 'No saved searches yet. Set the filters you use often, then choose Save current search.'));
        }
        list.forEach((s) => {
            const b = button('act-saved-item', null, { role: 'menuitem' });
            const name = el('span', 'act-saved-name', s.name);
            if (s.is_default) name.appendChild(el('span', 'act-saved-star', ' ★'));
            b.append(name, el('span', 'act-saved-sum', savedSummary(s.filters || {})));
            b.addEventListener('click', () => { closeMenu(true); applySaved(s); });
            menu.appendChild(b);
        });
        menu.appendChild(el('div', 'act-menu-divider'));
        const save = button('', 'Save current search…', { role: 'menuitem' });
        save.addEventListener('click', () => { closeMenu(); openSaveDialog(); });
        menu.appendChild(save);
        if (S.savedLoaded && savedChanged()) {
            const upd = button('', `Update "${S.savedLoaded.name}"`, { role: 'menuitem' });
            upd.addEventListener('click', () => { closeMenu(true); updateSaved(); });
            menu.appendChild(upd);
        }
        const manage = button('', 'Manage saved searches…', { role: 'menuitem' });
        manage.addEventListener('click', () => { closeMenu(); openManageDialog(); });
        menu.appendChild(manage);
    }

    function applySaved(s) {
        const st = stateFromSaved(s.filters || {});
        S.savedLoaded = { id: s.id, name: s.name, filters: s.filters || {} };
        $('act-search').value = st.f.q;
        setState({ range: st.range, f: st.f }, { keepPrefs: true });
    }

    function wireSaved() {
        const btn = $('act-saved-btn'), menu = $('act-saved-menu');
        btn.addEventListener('click', () => toggleMenu(btn, menu, renderSavedMenu));
        menuKeys(menu);

        const save = $('act-save-modal');
        $('act-save-cancel').addEventListener('click', () => closeDialog(save));
        save.querySelector('.act-dlg-close').addEventListener('click', () => closeDialog(save));
        $('act-save-form').addEventListener('submit', (e) => { e.preventDefault(); submitSave(); });
        const manage = $('act-manage-modal');
        manage.querySelector('.act-dlg-close').addEventListener('click', () => closeDialog(manage));
        $('act-manage-close').addEventListener('click', () => closeDialog(manage));
        [save, manage].forEach((m) => m.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') { e.stopPropagation(); closeDialog(m); }
            else if (e.key === 'Tab') trapFocus(m, e);
        }));
    }

    let dialogReturn = null;
    function openDialog(m, focus) {
        dialogReturn = $('act-saved-btn');
        openModal(m.id);
        setTimeout(() => { if (focus) focus.focus(); }, 0);
    }
    function closeDialog(m) {
        m.classList.remove('active');
        if (dialogReturn && dialogReturn.isConnected) dialogReturn.focus();
    }

    function openSaveDialog() {
        const m = $('act-save-modal');
        const name = $('act-save-name');
        name.value = suggestName();
        $('act-save-default').checked = false;
        setSaveError('');
        openDialog(m, name);
        name.select();
    }

    function setSaveError(text) {
        const err = $('act-save-error');
        err.textContent = text;
        err.hidden = !text;
        const name = $('act-save-name');
        if (text) name.setAttribute('aria-invalid', 'true'); else name.removeAttribute('aria-invalid');
    }

    async function submitSave() {
        const name = ($('act-save-name').value || '').replace(/\s+/g, ' ').trim();
        const list = (S.saved && S.saved.searches) || [];
        const limit = (S.saved && S.saved.limit) || 50;
        if (!name) { setSaveError('Enter a name.'); return; }
        if (list.some((s) => s.name.toLowerCase() === name.toLowerCase())) {
            setSaveError(`You already have a saved search called "${name}".`);
            return;
        }
        if (list.length >= limit) {
            setSaveError(`You have ${nf(limit)} saved searches, the most allowed. Delete one to save another.`);
            return;
        }
        const btn = $('act-save-submit');
        btn.disabled = true;
        try {
            const body = { name, filters: savedFilters(S.range, S.f), is_default: $('act-save-default').checked };
            const s = await apiRequest('/activity/saved-searches', { method: 'POST', body: JSON.stringify(body), silent: true });
            S.savedLoaded = { id: s.id, name: s.name, filters: s.filters || {} };
            closeDialog($('act-save-modal'));
            showSuccess(`Saved "${s.name}".`);
            await loadSaved();
        } catch (err) {
            const text = String(err.message || '');
            if (err.status === 409 && /already/i.test(text)) setSaveError(`You already have a saved search called "${name}".`);
            else if (err.status === 409 && /delete one/i.test(text)) setSaveError(`You have ${nf(limit)} saved searches, the most allowed. Delete one to save another.`);
            else setSaveError(text || 'The search could not be saved.');
        } finally {
            btn.disabled = false;
        }
    }

    async function updateSaved() {
        const cur = S.savedLoaded;
        if (!cur) return;
        try {
            const filters = savedFilters(S.range, S.f);
            const s = await apiRequest(`/activity/saved-searches/${encodeURIComponent(cur.id)}`,
                { method: 'PATCH', body: JSON.stringify({ filters }), silent: true });
            S.savedLoaded = { id: s.id, name: s.name, filters: s.filters || {} };
            showSuccess(`Updated "${s.name}".`);
            await loadSaved();
        } catch (err) {
            showError(`The search could not be updated: ${err.message}`);
        }
    }

    function openManageDialog() {
        renderManage();
        openDialog($('act-manage-modal'), $('act-manage-modal').querySelector('input, button'));
    }

    function renderManage() {
        const host = $('act-manage-body');
        host.replaceChildren();
        const list = (S.saved && S.saved.searches) || [];
        const fs = el('fieldset', 'act-manage-default');
        fs.appendChild(el('legend', 'act-fp-title', 'Open Activity with'));
        const opt = (value, label, checked) => {
            const row = el('label', 'act-fp-check');
            const r = document.createElement('input');
            r.type = 'radio';
            r.name = 'act-manage-default';
            r.value = value;
            r.checked = checked;
            r.addEventListener('change', () => setDefault(value));
            row.append(r, el('span', 'act-fp-check-label', label));
            fs.appendChild(row);
        };
        opt('', 'My last time range, no filters', !list.some((s) => s.is_default));
        list.forEach((s) => opt(s.id, s.name, s.is_default));
        host.appendChild(fs);
        if (!list.length) {
            host.appendChild(el('p', 'act-menu-empty', 'No saved searches yet. Set the filters you use often, then choose Save current search.'));
            return;
        }
        const ul = el('ul', 'act-manage-list');
        list.forEach((s) => ul.appendChild(manageRow(s)));
        host.appendChild(ul);
    }

    function manageRow(s) {
        const li = el('li', 'act-manage-row');
        const text = el('div', 'act-manage-text');
        text.append(el('div', 'act-saved-name', s.name), el('div', 'act-saved-sum', savedSummary(s.filters || {})));
        const actions = el('div', 'act-manage-actions');
        const rename = button('act-link-btn', 'Rename');
        const del = button('act-link-btn', 'Delete');
        actions.append(rename, del);
        li.append(text, actions);
        rename.addEventListener('click', () => {
            const input = el('input', 'form-control act-manage-input');
            input.value = s.name;
            input.maxLength = 80;
            input.setAttribute('aria-label', `New name for ${s.name}`);
            const err = el('p', 'form-error');
            err.hidden = true;
            const ok = button('btn btn-primary btn-sm', 'Save');
            const cancel = button('btn btn-ghost btn-sm', 'Cancel');
            text.replaceChildren(input, err);
            actions.replaceChildren(ok, cancel);
            input.focus();
            input.select();
            const submit = async () => {
                const name = input.value.replace(/\s+/g, ' ').trim();
                if (!name) { err.textContent = 'Enter a name.'; err.hidden = false; return; }
                const taken = ((S.saved && S.saved.searches) || []).some((x) => x.id !== s.id && x.name.toLowerCase() === name.toLowerCase());
                if (taken) { err.textContent = `You already have a saved search called "${name}".`; err.hidden = false; return; }
                try {
                    const out = await apiRequest(`/activity/saved-searches/${encodeURIComponent(s.id)}`,
                        { method: 'PATCH', body: JSON.stringify({ name }), silent: true });
                    if (S.savedLoaded && S.savedLoaded.id === s.id) S.savedLoaded.name = out.name;
                    showSuccess(`Renamed to "${out.name}".`);
                    await loadSaved();
                    renderManage();
                } catch (e) { err.textContent = e.message; err.hidden = false; }
            };
            ok.addEventListener('click', submit);
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') { e.preventDefault(); submit(); }
                else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); renderManage(); }
            });
            cancel.addEventListener('click', () => renderManage());
        });
        del.addEventListener('click', () => {
            const confirmBox = el('div', 'act-manage-confirm');
            confirmBox.appendChild(el('span', '', `Delete "${s.name}"?`));
            const yes = button('btn btn-danger btn-sm', 'Delete');
            const no = button('btn btn-ghost btn-sm', 'Cancel');
            confirmBox.append(yes, no);
            actions.replaceChildren(confirmBox);
            no.focus();
            no.addEventListener('click', () => renderManage());
            yes.addEventListener('click', async () => {
                try {
                    await apiRequest(`/activity/saved-searches/${encodeURIComponent(s.id)}`, { method: 'DELETE', silent: true });
                    if (S.savedLoaded && S.savedLoaded.id === s.id) S.savedLoaded = null;
                    showSuccess(`Deleted "${s.name}".`);
                    await loadSaved();
                    renderManage();
                } catch (e) { showError(`The search could not be deleted: ${e.message}`); }
            });
        });
        return li;
    }

    async function setDefault(id) {
        const list = (S.saved && S.saved.searches) || [];
        try {
            if (id) {
                S.saved = await apiRequest(`/activity/saved-searches/${encodeURIComponent(id)}/default`, { method: 'POST', silent: true });
            } else {
                const cur = list.find((s) => s.is_default);
                if (cur) S.saved = await apiRequest(`/activity/saved-searches/${encodeURIComponent(cur.id)}/default`, { method: 'DELETE', silent: true });
            }
        } catch (e) {
            showError(`The choice could not be saved: ${e.message}`);
            renderManage();
        }
    }

    // ---- who may see the page ----------------------------------------------------------------------
    // Administrators in their own session only. A temporary credential is refused by the server, which
    // records every refusal, so the page makes no request at all when it knows the session is one, and
    // after the first refusal it stops everything: no retry, no poll.

    function block(kind) {
        if (S.blocked === kind) return;
        S.blocked = kind;
        stopTimers();
        closePanel(false);
        closeMenu();
        closeOnline(false);
        if (S.detailOpen) closeDetail(false);
        const box = $('act-blocked');
        box.replaceChildren();
        box.appendChild(el('p', 'act-blocked-text', kind === 'temp'
            ? "Activity needs your own administrator sign-in. You're signed in with a temporary credential, which can't open the activity log."
            : 'Activity is for administrators. Ask an administrator if you need an event looked up.'));
        box.hidden = false;
        $('activity-section').classList.add('is-blocked');
        dropHash();
    }

    function unblock() {
        S.blocked = null;
        $('act-blocked').hidden = true;
        $('activity-section').classList.remove('is-blocked');
    }

    async function checkAccess() {
        if (S.blocked === 'temp') return false;
        const user = typeof currentUser !== 'undefined' ? currentUser : null;
        if (!user || user.role !== 'admin') { block('admin'); return false; }
        if (typeof isScopedTemp !== 'undefined' && isScopedTemp) { block('temp'); return false; }
        let info = typeof sessionAccess !== 'undefined' ? sessionAccess : null;
        if (!info) {
            try {
                const r = await fetch(`${API_BASE}/auth/session`, { headers: { Authorization: `Bearer ${authToken}` } });
                if (r.ok) info = await r.json();
            } catch (_) { info = null; }
        }
        if (info && (info.is_temp_session || info.is_scoped_temp)) { block('temp'); return false; }
        if (S.blocked) unblock();
        return true;
    }

    // ---- timers ------------------------------------------------------------------------------------

    let nowTimer = null, minuteTimer = null;

    function startTimers() {
        stopTimers();
        nowTimer = setInterval(() => loadNow(), 15000);
        minuteTimer = setInterval(minuteTick, 60000);
        armPoll();
    }

    function stopTimers() {
        clearInterval(nowTimer);
        clearInterval(minuteTimer);
        clearTimeout(pollTimer);
        clearTimeout(bandTimer);
        clearTimeout(fetchTimer);
        clearTimeout(pausedTimer);
        clearInterval(heldTimer);
        clearTimeout(reconcileTimer);
        nowTimer = minuteTimer = pollTimer = bandTimer = fetchTimer = pausedTimer = heldTimer = reconcileTimer = null;
        bandFirst = 0;
        reloadSoon.cancel();
        nowSoon.cancel();
        searchSoon.cancel();
        savePrefs.flush();
    }

    function minuteTick() {
        if (!S.active) return;
        renderLive();
        if (S.detailOpen && S.detail) {
            document.querySelectorAll('#act-detail .act-d-when, #activity-event-modal .act-d-when').forEach((n) => { n.textContent = whenLine(S.detail); });
        }
        if (onlinePop) renderOnlinePop();
    }

    // ---- layout ------------------------------------------------------------------------------------
    // The page lays out by its own width (a container query), so a collapsed sidebar or Classic's wider
    // margins do not change which layout it uses.

    // The detail pane and the filter popover are sized from where they start on the screen. Until the page
    // scrolls them under the toolbar they start below the band, and a height counted from the navbar ran
    // past the bottom of the window: the pane's footer and the popover's Done were cut off. The CSS takes
    // the smaller of this and the height they have once stuck under the toolbar.
    const FIT_GAP = 16, FIT_MIN = 240;
    function fitFrom(node) {
        const top = Math.max(0, Math.round(node.getBoundingClientRect().top));
        return `max(${FIT_MIN}px, calc(100dvh - ${top}px - ${FIT_GAP}px))`;
    }

    function fitOverlays() {
        const pane = $('act-detail');
        if (S.detailOpen && !isNarrow() && pane && !pane.hidden) {
            // The desktop pane is sticky itself; the tablet drawer's panel is the sticky part.
            const sticky = getComputedStyle(pane).position === 'sticky' ? pane : pane.querySelector('.act-detail-inner');
            if (sticky) pane.style.setProperty('--act-detail-fit', fitFrom(sticky));
        }
        const panel = $('act-filter-panel');
        if (P.open && !P.staged && panel && !panel.hidden) panel.style.setProperty('--act-fp-fit', fitFrom(panel));
    }

    let fitFrame = 0;
    function fitSoon() {
        if (fitFrame || !S.active) return;
        fitFrame = requestAnimationFrame(() => { fitFrame = 0; fitOverlays(); });
    }

    function layoutFor(width) {
        if (width >= WIDE_MIN) return 'wide';
        if (width >= MEDIUM_MIN) return 'medium';
        return 'narrow';
    }

    function watchLayout() {
        const section = $('activity-section');
        const toolbar = $('act-toolbar');
        if (typeof ResizeObserver !== 'function') return;
        new ResizeObserver((entries) => {
            const w = entries[0].contentRect.width;
            if (!w) return;
            fitDaySpans();
            fitSoon();
            const next = layoutFor(w);
            if (next === S.layout) return;
            const was = S.layout;
            S.layout = next;
            onLayoutChange(was);
        }).observe(section);
        new ResizeObserver(() => {
            section.style.setProperty('--act-toolbar-h', `${toolbar.offsetHeight}px`);
            fitSoon();
        }).observe(toolbar);
        // The band above the list changes height as it loads, moving where the pane starts.
        new ResizeObserver(() => fitSoon()).observe($('act-band'));
    }

    function onLayoutChange(was) {
        if (!S.ready) return;
        const narrowChanged = (was === 'narrow') !== (S.layout === 'narrow');
        if (P.open) closePanel(false);
        closeMenu();
        renderFilterButton();
        if (narrowChanged) renderList();
        if (S.detailOpen) {
            if (S.layout === 'narrow') { $('act-detail').hidden = true; openPhoneDetail(); }
            else closePhoneDetail(false);
            renderDetail();
        }
        renderBand();
    }

    // ---- wiring ------------------------------------------------------------------------------------

    function wire() {
        if (wired) return;
        wired = true;
        wireRange();
        wireExport();
        wireSearch();
        wireList();
        wirePane();
        wirePhoneDetail();
        wireBand();
        wirePanel();
        wireSaved();
        watchLayout();
        $('act-pause').addEventListener('click', () => setPaused(!S.paused));
        $('act-new-pill').addEventListener('click', () => takeHeld());
        window.addEventListener('dockvault:activity', onSignal);
        window.addEventListener('dockvault:socket', onSocket);
        window.addEventListener('online', () => { renderLive(); if (S.active) safetyPoll(); });
        window.addEventListener('offline', () => renderLive());
        window.addEventListener('scroll', () => {
            if (!S.active) return;
            if (S.held.length) flushHeldSoon();
            const bar = $('act-toolbar');
            const nav = document.querySelector('.navbar');
            const top = nav ? nav.getBoundingClientRect().bottom : 0;
            bar.classList.toggle('is-stuck', window.scrollY > 0 && bar.getBoundingClientRect().top <= top + 0.5);
            fitSoon();
        }, { passive: true });
        window.addEventListener('resize', () => fitSoon(), { passive: true });
        document.addEventListener('visibilitychange', () => {
            if (!S.active || S.blocked || !S.ready || document.hidden) return;
            if (!S.paused) {
                catchUp();
                if (S.bandDirty) { S.bandDirty = false; loadBand(true); }
            }
            loadNow();
        });
        document.addEventListener('click', (e) => {
            if (openMenu && !openMenu.menu.contains(e.target) && !openMenu.btn.contains(e.target)) closeMenu();
        });
        document.addEventListener('keydown', onEscape);
        // Leaving the page stops its timers and drops its hash.
        const section = $('activity-section');
        new MutationObserver(() => {
            const on = section.classList.contains('active');
            if (on || !S.active) return;
            S.active = false;
            stopTimers();
            closePanel(false);
            closeMenu();
            closeOnline(false);
            closePhoneDetail(false);
            if (location.hash.startsWith('#activity')) dropHash();
        }).observe(section, { attributes: true, attributeFilter: ['class'] });
    }

    // Escape closes the open popover, else the detail, else leaves the search box.
    function onEscape(e) {
        if (e.key !== 'Escape' || !S.active || e.defaultPrevented) return;
        const other = Array.from(document.querySelectorAll('.modal.active'));
        if (other.length) return;                           // a dialog handles its own Escape
        if (closeMenu(true)) { e.preventDefault(); return; }
        if (P.open && !P.staged) { e.preventDefault(); closePanel(true); return; }
        if (onlinePop) { e.preventDefault(); closeOnline(true); return; }
        if (chartUi && hideTip(chartUi)) { e.preventDefault(); return; }
        if (S.detailOpen) { e.preventDefault(); closeDetail(true); return; }
        if (document.activeElement === $('act-search')) $('act-search').blur();
    }

    function closePopovers() {
        closeOnline(false);
        if (chartUi) hideTip(chartUi);
    }

    async function loadCatalog() {
        if (S.catalog) return;
        const c = await get('/activity/catalog');
        S.catalog = c;
        S.catLabels = {};
        S.actionInfo = {};
        S.catOrder = [];
        (c.categories || []).forEach((cat) => {
            S.catLabels[cat.key] = cat.label;
            S.catOrder.push(cat.key);
            (cat.actions || []).forEach((a) => { S.actionInfo[a.name] = { label: a.label, category: cat.key }; });
        });
        S.outcomes = c.sign_in_outcomes || null;
        P.built = false;
    }

    // What the page opens with: a link's hash, else the default saved search, else the last range with
    // no filters.
    async function openingState() {
        const h = readHash(location.hash);
        if (h) {
            S.range = h.range;
            S.f = h.f;
            S.page = h.page;
            return h.ev;
        }
        await loadSaved();
        const def = S.saved && (S.saved.searches || []).find((s) => s.is_default);
        if (def) {
            const st = stateFromSaved(def.filters || {});
            S.range = st.range;
            S.f = st.f;
            S.savedLoaded = { id: def.id, name: def.name, filters: def.filters || {} };
            return null;
        }
        const r = pref('activity_range');
        if (['24h', '7d', '30d', 'all'].includes(r)) S.range = { kind: r, from: null, to: null };
        return null;
    }

    function showLoading() {
        S.listLoaded = false;
        renderList();
        renderBand();
    }

    window.initActivity = async function initActivity() {
        wire();
        const section = $('activity-section');
        if (!section.classList.contains('active')) return;
        S.active = true;
        if (!await checkAccess()) return;
        S.layout = layoutFor(section.clientWidth || 1200);
        S.socketState = window.dockvaultSocketState || 'connecting';
        if (S.socketState !== 'open' && !S.socketDownSince) {
            S.socketDownSince = Date.now();
            setTimeout(() => renderLive(), 10050);
        }
        if (!S.ready) {
            const size = pref('activity_page_size');
            S.pageSize = PAGE_SIZES.includes(size) ? size : '50';
            $('act-th-time').textContent = zoneShort() ? `Time (${zoneShort()})` : 'Time';
            showLoading();
            renderControls();
            try { await loadCatalog(); } catch (err) { if (S.blocked) return; }
            const ev = await openingState();
            if (S.blocked || !S.active) return;
            S.ready = true;
            $('act-search').value = S.f.q;
            renderControls();
            writeHash();
            startTimers();
            await Promise.all([reloadList(), loadBand(), loadNow(), S.saved ? null : loadSaved()]);
            if (ev && S.active && !S.blocked) await openLinkedEvent(ev);
            return;
        }
        // Back on the page: a hash names the state (a copied link opened in this tab); the rest is
        // read again.
        const h = readHash(location.hash);
        let ev = null;
        if (h) {
            S.range = h.range;
            S.f = h.f;
            S.page = h.page;
            ev = h.ev;
            $('act-search').value = S.f.q;
        }
        renderControls();
        writeHash();
        startTimers();
        clearKept();
        await Promise.all([reloadList({ keepDetail: !ev }), loadBand(), loadNow(), loadSaved()]);
        if (ev && S.active && !S.blocked) await openLinkedEvent(ev);
    };

    // Signing out forgets everything the page held: the next person on this tab starts afresh.
    window.resetActivity = function resetActivity() {
        stopTimers();
        closePanel(false);
        closeMenu();
        closeOnline(false);
        const m = $('activity-event-modal');
        if (m) { delete m.dataset.actOpen; m.classList.remove('active'); }
        phonePushed = false;
        S = freshState();
        P.open = false;
        P.draft = null;
        P.built = false;
        P.expanded = new Set();
        chartUi = null;
        if (!wired) return;
        ['activity-rows', 'activity-cards', 'act-chips', 'act-pager', 'act-empty', 'act-list-alert', 'act-detail',
            'act-p-now', 'act-p-time', 'act-p-cat', 'act-p-signin', 'act-p-active', 'act-fp-content'].forEach((id) => {
            const n = $(id);
            if (n) n.replaceChildren();
        });
        $('act-detail').hidden = true;
        $('act-body').classList.remove('has-detail');
        $('activity-summary').textContent = '';
        $('act-search').value = '';
        $('act-new-pill').hidden = true;
        unblock();
        setPausedButton(false);
    };

    function setPausedButton(on) {
        const b = $('act-pause');
        if (!b) return;
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
        b.setAttribute('aria-label', on ? 'Resume' : 'Pause');
        b.replaceChildren(icon(on ? 'play' : 'pause', 'icon-sm'), el('span', 'act-btn-text', on ? 'Resume' : 'Pause'));
    }
})();
