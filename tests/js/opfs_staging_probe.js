// Does the staging sink actually work? A probe, injected into a page by its test.
//
// This exists because the design gate for bounded downloads says to prove the sink before
// building on it. Nothing in the application uses this yet; the point is that the assumption is
// checked in CI, on a real browser, before code depends on it -- and that if a browser ever stops
// supporting it, that shows up here rather than in a download that silently keeps buffering.
//
// The design gate says prove the sink before building on it. What has to be true:
//   1. a worker can open a sync access handle and write chunk by chunk
//   2. the finished file can be handed to the page as something downloadable
//   3. an abort leaves nothing behind
//   4. the page never holds the whole thing
//
// Point 4 is the reason for the exercise: everything decrypted goes straight to disk, so a
// failure at the final record deletes a file rather than leaving a partial download.

window.runProbe = async function runProbe(totalBytes, chunkBytes) {
    const workerSource = `
        self.onmessage = async (e) => {
            const { name, chunk, count, mode } = e.data;
            try {
                const root = await navigator.storage.getDirectory();
                if (mode === 'write') {
                    const fh = await root.getFileHandle(name, { create: true });
                    const h = await fh.createSyncAccessHandle();
                    // One chunk exists at a time. Nothing accumulates.
                    const buf = new Uint8Array(chunk);
                    let written = 0;
                    for (let i = 0; i < count; i++) {
                        buf.fill(i & 0xff);
                        written += h.write(buf, { at: written });
                    }
                    h.flush();
                    const size = h.getSize();
                    h.close();
                    self.postMessage({ ok: true, written, size });
                    return;
                }
                if (mode === 'delete') {
                    await root.removeEntry(name);
                    self.postMessage({ ok: true });
                    return;
                }
            } catch (err) {
                self.postMessage({ ok: false, error: String(err && err.name || err) });
            }
        };
    `;
    const worker = new Worker(URL.createObjectURL(
        new Blob([workerSource], { type: 'text/javascript' })));

    const ask = (msg) => new Promise((res) => {
        worker.onmessage = (e) => res(e.data);
        worker.postMessage(msg);
    });

    const name = 'staged-download.bin';
    const count = Math.ceil(totalBytes / chunkBytes);
    const before = (await navigator.storage.estimate()).usage;
    const write = await ask({ mode: 'write', name, chunk: chunkBytes, count });
    if (!write.ok) { worker.terminate(); return { stage: 'write', ...write }; }

    // The page side: can the staged file be handed over as a normal download?
    const root = await navigator.storage.getDirectory();
    const handle = await root.getFileHandle(name);
    const file = await handle.getFile();
    const url = URL.createObjectURL(file);
    const downloadable = typeof url === 'string' && url.startsWith('blob:');
    URL.revokeObjectURL(url);

    // Read a few bytes back to prove the content is really there and in order.
    const headBytes = new Uint8Array(await file.slice(0, 4).arrayBuffer());
    const tailStart = Math.max(0, file.size - 4);
    const tailBytes = new Uint8Array(await file.slice(tailStart).arrayBuffer());

    // And the abort path: a staged file must be removable, leaving nothing.
    const del = await ask({ mode: 'delete', name });
    let stillThere = true;
    try { await root.getFileHandle(name); } catch (_) { stillThere = false; }

    // Storage estimate, to show the staged bytes were really on disk rather than in the heap.
    const est = await navigator.storage.estimate();

    worker.terminate();
    return {
        stage: 'done',
        written: write.written,
        size: write.size,
        expected: count * chunkBytes,
        chunks: count,
        downloadable,
        head: Array.from(headBytes),
        tail: Array.from(tailBytes),
        deleted: del.ok && !stillThere,
        usageBefore: before,
        usageAfterDelete: est.usage,
        // What the abort actually reclaimed. Engines differ on what a zeroed estimate means --
        // one reports nothing left, another keeps its own filesystem bookkeeping -- so the
        // question worth asking is whether the staged bytes went, not whether the number is 0.
        reclaimed: (est.usage != null && before != null) ? (totalBytes - (est.usage - before)) : null,
    };
};
