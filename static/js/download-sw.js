/**
 * A sink for decrypted downloads that never holds the file.
 *
 * The page decrypts a zero-knowledge object record by record. Handing the browser the result means
 * producing a Blob, and a Blob is the whole file — measured at about one copy of it, which is why
 * a file larger than the tab can hold cannot be downloaded at all today.
 *
 * This worker removes that ceiling. The page asks for a download slot, gets back a URL, and points
 * the browser at it; the worker answers that URL with a response whose body is a stream the page
 * writes into. The browser saves the bytes as they arrive, so nothing accumulates anywhere.
 *
 * WHAT THIS COSTS, stated here because it is the reason the whole thing is policy-gated: once the
 * browser starts saving, a failed transfer leaves a partial file in Downloads that neither this
 * worker nor the page can remove. There is no web API to delete it. The browser marks it failed;
 * that is the entire remedy available.
 *
 * Resuming makes that rarer than it sounds. The response stays open across a dropped connection —
 * the page re-requests the missing byte range and keeps writing into the SAME stream, so the
 * browser sees one continuous download. A partial only survives if the tab closes or the page
 * gives up.
 *
 * Scope: served from the origin root so it can intercept `/vaults/.../download`-adjacent paths.
 * A script under `/static/js/` would default to that directory as its scope and never see them.
 */
'use strict';

/** Slots handed out but not yet fetched, and slots currently streaming. */
const PENDING = new Map();

/** The path the page navigates to. Deliberately unlikely to collide with a real route. */
const SINK_PREFIX = '/__dv_sink__/';

/**
 * A slot expires if the page never navigates to it. Without this, a page that asks for a download
 * and then errors before triggering it leaks the slot — and with it the port, for as long as the
 * worker lives.
 */
const SLOT_TTL_MS = 60_000;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('message', event => {
    const data = event.data || {};
    if (data.type !== 'dv-sink-open') return;

    const id = data.id;
    const port = event.ports && event.ports[0];
    if (typeof id !== 'string' || !id || !port) return;

    // The filename is the page's, and it ends up in a header. Anything that could terminate the
    // header or escape the quoted string is dropped rather than escaped: this is a worker with no
    // view of what the name is supposed to be, so the conservative choice is the right one.
    const name = String(data.filename || 'download').replace(/[\r\n"\\]/g, '_').slice(0, 200);
    const size = Number.isSafeInteger(data.size) && data.size >= 0 ? data.size : null;
    const mime = /^[\w.+-]+\/[\w.+-]+$/.test(String(data.mime || ''))
        ? String(data.mime) : 'application/octet-stream';

    let controllerRef = null;
    const stream = new ReadableStream({
        start(controller) { controllerRef = controller; },
        cancel() {
            // The user cancelled the download, or the browser gave up. Tell the page so it stops
            // decrypting into a stream nobody is reading.
            try { port.postMessage({ type: 'dv-sink-cancelled' }); } catch (_) { /* gone */ }
            PENDING.delete(id);
        },
    });

    port.onmessage = messageEvent => {
        const message = messageEvent.data || {};
        if (!controllerRef) return;
        try {
            if (message.type === 'chunk' && message.bytes) {
                controllerRef.enqueue(new Uint8Array(message.bytes));
            } else if (message.type === 'done') {
                controllerRef.close();
                controllerRef = null;
                PENDING.delete(id);
            } else if (message.type === 'abort') {
                // The page failed in a way it cannot resume from. Erroring the stream is what
                // makes the browser mark the download failed rather than complete-but-short,
                // which is the difference between a visible failure and a silently truncated file.
                controllerRef.error(new Error(message.reason || 'aborted'));
                controllerRef = null;
                PENDING.delete(id);
            }
        } catch (_) {
            PENDING.delete(id);
        }
    };

    PENDING.set(id, { stream, name, size, mime, at: Date.now() });
    port.postMessage({ type: 'dv-sink-ready', url: SINK_PREFIX + id });
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (url.origin !== self.location.origin) return;
    if (!url.pathname.startsWith(SINK_PREFIX)) return;

    const id = url.pathname.slice(SINK_PREFIX.length);
    const slot = PENDING.get(id);

    // Expire anything stale before answering, so a long-lived worker does not accumulate slots
    // whose pages are gone.
    const now = Date.now();
    for (const [key, value] of PENDING) {
        if (value.stream && now - value.at > SLOT_TTL_MS && key !== id) PENDING.delete(key);
    }

    if (!slot) {
        // A reload of a finished download, or a slot that expired. 404 rather than a hang: the
        // browser shows a failed download, which is true, instead of waiting forever on a stream
        // nobody will ever write to.
        event.respondWith(new Response('no such download', { status: 404 }));
        return;
    }

    const headers = {
        'Content-Type': slot.mime,
        'Content-Disposition': `attachment; filename="${slot.name}"`,
        // The page knows the plaintext length before it starts, so the browser can show progress
        // and detect a short body. Omitted when it does not.
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    };
    if (slot.size !== null) headers['Content-Length'] = String(slot.size);

    event.respondWith(new Response(slot.stream, { headers }));
});
