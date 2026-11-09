'use strict';

// A very small document for running static/js/settings-help.js under Node: elements and text nodes built
// from a JSON tree ([tag, {attrs}, [children]] or a string), with classList, dataset, childNodes,
// children, textContent, appendChild, and querySelector(All)/closest/matches for the selectors that file
// uses (tag, .class, #id, compound tag.class, and descendant combinators). Nothing is rendered.

let serial = 0;

class Node {
    constructor(doc, type) {
        this.ownerDocument = doc; this.nodeType = type; this.parentNode = null; this.childNodes = []; this.uid = ++serial;
    }
}
Node.ELEMENT_NODE = 1;
Node.TEXT_NODE = 3;

class Text extends Node {
    constructor(doc, text) { super(doc, 3); this._text = String(text); }
    get textContent() { return this._text; }
    set textContent(v) { this._text = String(v); }
}

const dataName = (k) => 'data-' + String(k).replace(/[A-Z]/g, (m) => '-' + m.toLowerCase());

class Element extends Node {
    constructor(doc, tag) {
        super(doc, 1);
        this.localName = tag.toLowerCase(); this.tagName = tag.toUpperCase(); this.attrs = {};
        const el = this;
        this.classList = {
            contains: (c) => (el.attrs.class || '').split(/\s+/).includes(c),
        };
        this.dataset = new Proxy({}, {
            get: (_, k) => (dataName(k) in el.attrs ? el.attrs[dataName(k)] : undefined),
            set: (_, k, v) => { el.attrs[dataName(k)] = String(v); return true; },
        });
    }
    get id() { return this.attrs.id || ''; }
    get className() { return this.attrs.class || ''; }
    set className(v) { this.attrs.class = v; }
    get children() { return this.childNodes.filter((c) => c.nodeType === 1); }
    get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
    set textContent(v) {
        this.childNodes.forEach((c) => { c.parentNode = null; });
        this.childNodes = [];
        if (v !== '' && v != null) this.appendChild(new Text(this.ownerDocument, v));
    }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    appendChild(c) {
        if (c.parentNode) { const s = c.parentNode.childNodes; s.splice(s.indexOf(c), 1); }
        c.parentNode = this; this.childNodes.push(c); return c;
    }
    matches(sel) { return sel.split(',').some((part) => matchChain(this, part.trim().split(/\s+/))); }
    closest(sel) { let n = this; while (n && n.nodeType === 1) { if (n.matches(sel)) return n; n = n.parentNode; } return null; }
    querySelectorAll(sel) { const out = []; walk(this, (el) => { if (el.matches(sel)) out.push(el); }); return out; }
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

function walk(root, fn) { root.childNodes.forEach((c) => { if (c.nodeType === 1) { fn(c); walk(c, fn); } }); }

function matchCompound(el, compound) {
    let rest = compound;
    const tag = rest.match(/^[a-zA-Z][\w-]*/);
    if (tag) { if (el.localName !== tag[0].toLowerCase()) return false; rest = rest.slice(tag[0].length); }
    for (const t of rest.matchAll(/\.([\w-]+)|#([\w-]+)/g)) {
        if (t[1] !== undefined && !el.classList.contains(t[1])) return false;
        if (t[2] !== undefined && el.id !== t[2]) return false;
    }
    if (rest.replace(/\.([\w-]+)|#([\w-]+)/g, '') !== '') throw new Error('unsupported selector: ' + compound);
    return true;
}

// The last compound matches the element; each earlier one some ancestor, in order.
function matchChain(el, parts) {
    if (!matchCompound(el, parts[parts.length - 1])) return false;
    let i = parts.length - 2;
    let n = el.parentNode;
    while (i >= 0 && n && n.nodeType === 1) { if (matchCompound(n, parts[i])) i--; n = n.parentNode; }
    return i < 0;
}

class Document {
    constructor() { this.body = new Element(this, 'body'); }
    createElement(tag) { return new Element(this, tag); }
    createTextNode(text) { return new Text(this, text); }
    getElementById(id) { let found = null; walk(this.body, (el) => { if (!found && el.id === id) found = el; }); return found; }
    build(tree) {
        if (typeof tree === 'string') return this.createTextNode(tree);
        const [tag, attrs, kids] = tree;
        const el = this.createElement(tag);
        Object.entries(attrs || {}).forEach(([k, v]) => el.setAttribute(k, v == null ? '' : v));
        (kids || []).forEach((k) => el.appendChild(this.build(k)));
        return el;
    }
}

module.exports = { Document, Node };
