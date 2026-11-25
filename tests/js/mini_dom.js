'use strict';

// A small document for running the page's table and people helpers under Node: elements with
// children, attributes, classes, text, a handful of selectors (tag, .class, #id, [attr], [attr="v"],
// descendant and `:scope >` child combinators), tables' tHead/tBodies/rows/cells, selects' options,
// and click/keydown/input listeners. Enough to prove the library's behaviour; nothing is rendered.

class ClassList {
    constructor(el) { this.el = el; }
    get list() { return (this.el.attrs.class || '').split(/\s+/).filter(Boolean); }
    set list(v) { if (v.length) this.el.attrs.class = v.join(' '); else delete this.el.attrs.class; }
    add(...c) { const l = this.list; c.forEach((x) => { if (!l.includes(x)) l.push(x); }); this.list = l; }
    remove(...c) { this.list = this.list.filter((x) => !c.includes(x)); }
    contains(c) { return this.list.includes(c); }
    toggle(c, on) { const has = this.contains(c); const want = on === undefined ? !has : !!on; if (want) this.add(c); else this.remove(c); return want; }
    forEach(fn) { this.list.forEach(fn); }
}

let serial = 0;

class Node {
    constructor(doc, type, name, text) {
        this.ownerDocument = doc; this.nodeType = type; this.nodeName = name; this.parentNode = null;
        this.childNodes = []; this._text = text || ''; this.uid = ++serial;
    }
    get textContent() {
        if (this.nodeType === 3) return this._text;
        return this.childNodes.map((c) => c.textContent).join('');
    }
    set textContent(v) { this.childNodes.forEach((c) => { c.parentNode = null; }); this.childNodes = []; if (v !== '' && v != null) this.appendChild(this.ownerDocument.createTextNode(String(v))); }
}

const dataName = (k) => 'data-' + String(k).replace(/[A-Z]/g, (m) => '-' + m.toLowerCase());

class Element extends Node {
    constructor(doc, tag) {
        super(doc, 1, tag.toUpperCase());
        this.tagName = tag.toUpperCase(); this.localName = tag.toLowerCase();
        this.attrs = {}; this.listeners = {}; this.style = {}; this.hidden = false; this.classList = new ClassList(this);
        this.dataset = new Proxy({}, {
            get: (_, k) => (dataName(k) in this.attrs ? this.attrs[dataName(k)] : undefined),
            set: (_, k, v) => { this.attrs[dataName(k)] = String(v); return true; },
            has: (_, k) => dataName(k) in this.attrs,
        });
        if (this.localName === 'select') this.selectedIndex = -1;
    }
    get id() { return this.attrs.id || ''; } set id(v) { this.attrs.id = v; }
    get className() { return this.attrs.class || ''; } set className(v) { if (v) this.attrs.class = v; else delete this.attrs.class; }
    get title() { return this.attrs.title || ''; } set title(v) { this.attrs.title = v; }
    get type() { return this.attrs.type || ''; } set type(v) { this.attrs.type = v; }
    get value() { return this._value || ''; } set value(v) { this._value = String(v); }
    get placeholder() { return this.attrs.placeholder || ''; } set placeholder(v) { this.attrs.placeholder = v; }
    get autocomplete() { return this.attrs.autocomplete || ''; } set autocomplete(v) { this.attrs.autocomplete = v; }
    get children() { return this.childNodes.filter((c) => c.nodeType === 1); }
    get firstChild() { return this.childNodes[0] || null; }
    get firstElementChild() { return this.children[0] || null; }
    get nextElementSibling() { if (!this.parentNode) return null; const s = this.parentNode.children; return s[s.indexOf(this) + 1] || null; }
    get previousElementSibling() { if (!this.parentNode) return null; const s = this.parentNode.children; return s[s.indexOf(this) - 1] || null; }
    get options() { return this.children.filter((c) => c.localName === 'option'); }
    get rows() { return this.localName === 'table' ? this.querySelectorAll('tr') : this.children.filter((c) => c.localName === 'tr'); }
    get cells() { return this.children.filter((c) => c.localName === 'td' || c.localName === 'th'); }
    get tHead() { return this.children.find((c) => c.localName === 'thead') || null; }
    get tBodies() { return this.children.filter((c) => c.localName === 'tbody'); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    hasAttribute(k) { return k in this.attrs; }
    removeAttribute(k) { delete this.attrs[k]; }
    toggleAttribute(k, force) { const on = force === undefined ? !(k in this.attrs) : !!force; if (on) this.attrs[k] = ''; else delete this.attrs[k]; return on; }
    appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.childNodes.push(c); return c; }
    insertBefore(c, ref) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; const i = ref ? this.childNodes.indexOf(ref) : -1; if (i < 0) this.childNodes.push(c); else this.childNodes.splice(i, 0, c); return c; }
    removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); c.parentNode = null; return c; }
    remove() { if (this.parentNode) this.parentNode.removeChild(this); }
    replaceChildren(...nodes) { this.childNodes.forEach((c) => { c.parentNode = null; }); this.childNodes = []; nodes.forEach((n) => this.appendChild(n)); }
    replaceWith(n) { const p = this.parentNode; if (!p) return; p.insertBefore(n, this); p.removeChild(this); }
    append(...nodes) { nodes.forEach((n) => this.appendChild(typeof n === 'string' ? this.ownerDocument.createTextNode(n) : n)); }
    insertAdjacentElement(where, el) {
        const p = this.parentNode;
        if (where === 'beforebegin') p.insertBefore(el, this);
        else if (where === 'afterend') p.insertBefore(el, this.nextSibling());
        else if (where === 'afterbegin') this.insertBefore(el, this.firstChild);
        else this.appendChild(el);
        return el;
    }
    nextSibling() { if (!this.parentNode) return null; const s = this.parentNode.childNodes; return s[s.indexOf(this) + 1] || null; }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter((x) => x !== f); }
    dispatch(t, ev) { const e = Object.assign({ type: t, target: this, preventDefault() {}, stopPropagation() {} }, ev || {}); (this.listeners[t] || []).forEach((f) => f(e)); return e; }
    click() { return this.dispatch('click'); }
    focus() { this.ownerDocument.activeElement = this; }
    matches(sel) { return sel.split(',').some((part) => matchCompound(this, part.trim())); }
    closest(sel) { let n = this; while (n && n.nodeType === 1) { if (n.matches(sel)) return n; n = n.parentNode; } return null; }
    contains(other) { let n = other; while (n) { if (n === this) return true; n = n.parentNode; } return false; }
    querySelectorAll(sel) { return select(this, sel); }
    querySelector(sel) { return select(this, sel)[0] || null; }
    getBoundingClientRect() { return { left: 0, right: 0, top: 0, bottom: 0, width: 0, height: 0 }; }
}

// One compound selector (tag, classes, id, attributes, :not) against one element.
function matchCompound(el, compound) {
    if (!el || el.nodeType !== 1) return false;
    let rest = compound;
    const m = rest.match(/^[a-zA-Z][\w-]*|^\*/);
    if (m) { if (m[0] !== '*' && el.localName !== m[0].toLowerCase()) return false; rest = rest.slice(m[0].length); }
    let consumed = 0;
    for (const t of rest.matchAll(/\.([\w-]+)|#([\w-]+)|\[([\w-]+)(?:="([^"]*)")?\]|:not\(([^)]*)\)/g)) {
        if (t.index !== consumed) throw new Error('unsupported selector: ' + compound);
        consumed += t[0].length;
        if (t[1] !== undefined) { if (!el.classList.contains(t[1])) return false; }
        else if (t[2] !== undefined) { if (el.id !== t[2]) return false; }
        else if (t[3] !== undefined) { if (!el.hasAttribute(t[3])) return false; if (t[4] !== undefined && el.getAttribute(t[3]) !== t[4]) return false; }
        else if (t[5] !== undefined) { if (el.matches(t[5])) return false; }
    }
    if (consumed !== rest.length) throw new Error('unsupported selector: ' + compound);
    return true;
}

function descendants(root, out) {
    root.childNodes.forEach((c) => { if (c.nodeType === 1) { out.push(c); descendants(c, out); } });
    return out;
}

// Descendant and child combinators over compound selectors; `:scope > x` means a child of root.
function select(root, selector) {
    const found = [];
    selector.split(',').forEach((part) => {
        const tokens = part.trim().replace(/\s*>\s*/g, ' > ').split(/\s+/).filter(Boolean);
        let set = [root];
        let child = false;
        tokens.forEach((tok, i) => {
            if (tok === '>') { child = true; return; }
            if (tok === ':scope' && i === 0) { set = [root]; return; }
            const next = [];
            set.forEach((base) => {
                const pool = child ? base.children : descendants(base, []);
                pool.forEach((el) => { if (matchCompound(el, tok) && !next.includes(el)) next.push(el); });
            });
            set = next; child = false;
        });
        set.forEach((el) => { if (!found.includes(el)) found.push(el); });
    });
    return found.sort((a, b) => a.uid - b.uid);
}

class Document {
    constructor() {
        this.readyState = 'complete';
        this.documentElement = new Element(this, 'html');
        this.body = new Element(this, 'body');
        this.documentElement.appendChild(this.body);
        this.listeners = {};
        this.activeElement = this.body;
    }
    createElement(tag) { return new Element(this, tag); }
    createElementNS(_ns, tag) { return new Element(this, tag); }
    createTextNode(t) { return new Node(this, 3, '#text', t); }
    querySelectorAll(sel) { return select(this.documentElement, sel); }
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
    getElementById(id) { return this.querySelector('#' + id); }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
}

// Installs window, document, localStorage and a saveUserPreference spy as globals; returns them.
function install() {
    const document = new Document();
    const store = {};
    const localStorage = {
        getItem: (k) => (k in store ? store[k] : null),
        setItem: (k, v) => { store[k] = String(v); },
        removeItem: (k) => { delete store[k]; },
        clear: () => { Object.keys(store).forEach((k) => delete store[k]); },
    };
    const saved = [];
    global.document = document;
    global.localStorage = localStorage;
    global.window = global;
    global.saveUserPreference = (p) => saved.push(p);
    global.MutationObserver = class { observe() {} disconnect() {} };
    return { document, store, saved, localStorage };
}

// A table from a header list (strings, or {label, col}) and rows of cell contents (a string, or an element).
function table(document, headers, rows, options) {
    const o = options || {};
    const t = document.createElement('table');
    t.className = 'data-table';
    if (o.id) t.id = o.id;
    const thead = document.createElement('thead'); const hr = document.createElement('tr');
    headers.forEach((h) => {
        const th = document.createElement('th');
        if (typeof h === 'string') th.textContent = h;
        else { th.textContent = h.label; if (h.col) th.setAttribute('data-col', h.col); }
        hr.appendChild(th);
    });
    thead.appendChild(hr); t.appendChild(thead);
    const tbody = document.createElement('tbody');
    rows.forEach((cells) => {
        const tr = document.createElement('tr');
        cells.forEach((c) => {
            const td = document.createElement('td');
            if (c && c.nodeType) td.appendChild(c); else td.textContent = c == null ? '' : String(c);
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    t.appendChild(tbody);
    const host = document.createElement('div');
    host.appendChild(t);
    document.body.appendChild(host);
    return t;
}

// The visible rows' text in one column, top to bottom.
function column(t, index) {
    return t.tBodies[0].children.filter((r) => !r.hidden).map((r) => r.cells[index].textContent.trim());
}

module.exports = { install, table, column, Element, Document };
