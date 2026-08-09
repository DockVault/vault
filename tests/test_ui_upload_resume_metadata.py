"""What an interrupted zero-knowledge upload leaves on disk.

The bytes were always encrypted. The metadata was not: the ciphertext was persisted as a `File`
built from the plaintext name and MIME, and a `File` keeps `name`, `type` and `lastModified`
across the structured clone into IndexedDB. So an interrupted upload of a sensitively-named
document left that name in the clear on the user's disk -- beside a sealed copy of the very same
name, in the same record.

These run against real IndexedDB in a real browser, because that is the only place the question
can be settled. Node's `structuredClone` degrades a `File` to a `Blob` and reports `name` as
`undefined`, so a test written there would have declared the worst of the four leaks absent.
"""

import pytest
from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.ui, pytest.mark.crypto_compatibility]

# Distinctive enough that finding it anywhere in a serialized record is unambiguous.
SENTINEL_NAME = "quarterly-layoffs-2026-final-DO-NOT-SHARE.xlsx"
SENTINEL_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

_DB = "dockvault-zk-uploads"

# Shared page-side helpers. Written once here rather than repeated in every evaluate.
_HELPERS = """
// Every IndexedDB wait is BOUNDED. A page that holds a connection open without an
// onversionchange handler blocks other connections indefinitely -- which is one of the defects
// under test, so an unbounded wait here turns a failing assertion into a hung suite.
const bounded = (label, ms, build) => new Promise(res => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; res(v); } };
    setTimeout(() => finish({ __timedOut: label }), ms);
    try { build(finish); } catch (e) { finish({ __threw: String(e) }); }
});
const wipe = () => bounded('deleteDatabase', 5000, (done) => {
    const r = indexedDB.deleteDatabase('%(db)s');
    r.onsuccess = () => done('deleted');
    r.onerror = () => done('error');
    r.onblocked = () => done('blocked');
});
const rawRow = (id) => bounded('rawRow', 5000, (done) => {
    const r = indexedDB.open('%(db)s');
    r.onblocked = () => done(null);
    r.onsuccess = () => {
        const db = r.result;
        const rq = db.transaction('pending', 'readonly').objectStore('pending').get(id);
        rq.onsuccess = () => { const v = rq.result; db.close(); done(v); };
        rq.onerror = () => { db.close(); done(null); };
    };
    r.onerror = () => done(null);
});
const describe = (r) => (r && r.__timedOut) ? 'timed-out' : (r && !r.__threw) ? ({
    keys: Object.keys(r).sort(),
    blob_is_File: typeof File !== 'undefined' && r.blob instanceof File,
    blob_is_Blob: r.blob instanceof Blob,
    blob_name: r.blob && r.blob.name !== undefined ? r.blob.name : null,
    blob_type: r.blob ? r.blob.type : null,
    blob_size: r.blob ? r.blob.size : null,
    blob_lastModified: r.blob && r.blob.lastModified !== undefined ? 'present' : null,
}) : null;
""" % {"db": _DB}


def _login(page: Page, username: str, password: str) -> None:
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def signed_in(page: Page, admin_creds) -> Page:
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def test_nothing_written_carries_the_plaintext_name_or_mime(signed_in: Page) -> None:
    """The whole point, checked on the row as it sits on disk rather than on what `get` returns.

    The record goes in through the store's own `put`, so what is measured is the path the uploader
    uses, not a re-implementation of it here.
    """
    out = signed_in.evaluate(
        _HELPERS + """async ([name, mime]) => {
            await wipe();
            const src = new File([new Uint8Array([1,2,3,4])], name, { type: mime });
            const put = await zkUploadStore.put({
                sessionId: 'probe', vaultId: 'v', totalSize: 4, folderId: null, keyVersion: 1,
                totalChunks: 1, chunkSize: 4,
                blob: zkUploadStore.neutralBlob(src), schema: 2,
                encName: 'sealed-name', encMime: 'sealed-mime', nameBi: 'bi',
                clientFileId: 'obj-1', createdAt: Date.now(),
            });
            return { put_ok: !!(put && put.ok), stored: describe(await rawRow('probe')) };
        }""",
        [SENTINEL_NAME, SENTINEL_MIME],
    )
    assert out["put_ok"] is True
    stored = out["stored"]
    assert stored != "timed-out", "IndexedDB stalled; this is an environment problem, not a leak"
    assert stored is not None, "the record did not land at all"

    assert "fileName" not in stored["keys"], stored["keys"]
    assert "mimeType" not in stored["keys"], stored["keys"]
    assert stored["blob_is_File"] is False, "ciphertext stored as a File keeps its plaintext name"
    assert stored["blob_is_Blob"] is True
    assert stored["blob_name"] is None
    assert stored["blob_lastModified"] is None
    assert stored["blob_type"] == "application/octet-stream", stored["blob_type"]
    # The ciphertext must survive intact -- for an interrupted upload it is the only copy.
    assert stored["blob_size"] == 4


def test_the_sentinel_appears_nowhere_in_the_stored_record(signed_in: Page) -> None:
    """A field-by-field check can miss somewhere nobody thought to look, so walk the whole row."""
    found = signed_in.evaluate(
        _HELPERS + """async ([name, mime]) => {
            await wipe();
            const src = new File([new Uint8Array([1,2,3,4])], name, { type: mime });
            await zkUploadStore.put({
                sessionId: 'probe', vaultId: 'v', totalSize: 4,
                blob: zkUploadStore.neutralBlob(src), schema: 2,
                encName: 'sealed-name', encMime: 'sealed-mime', createdAt: Date.now(),
            });
            const raw = await rawRow('probe');
            const seen = [];
            const walk = (v, path) => {
                if (v == null) return;
                if (typeof v === 'string') { seen.push([path, v]); return; }
                if (v instanceof Blob) {
                    // `name` is not enumerable on a File, so ask for it directly.
                    for (const k of ['name', 'type']) {
                        if (typeof v[k] === 'string') seen.push([path + '.' + k, v[k]]);
                    }
                    return;
                }
                if (typeof v === 'object') {
                    for (const k of Object.keys(v)) walk(v[k], path + '.' + k);
                }
            };
            walk(raw, 'record');
            // Test the PATH as well as the value: a plaintext name used as an object key
            // lands in the path and would otherwise go unnoticed.
            return seen.filter(([p, v]) =>
                v.includes(name) || v.includes(mime) || p.includes(name) || p.includes(mime));
        }""",
        [SENTINEL_NAME, SENTINEL_MIME],
    )
    assert found == [], f"plaintext metadata reachable at rest: {found}"


def test_a_record_written_by_the_old_schema_is_migrated(signed_in: Page) -> None:
    """Upgrading must clean what v1 already put on disk, and must not cost the user the bytes."""
    out = signed_in.evaluate(
        _HELPERS + """async ([name, mime]) => {
            await wipe();
            // Recreate v1 exactly: version 1, plaintext fields, ciphertext wrapped in a File.
            const v1 = await new Promise(res => {
                const r = indexedDB.open('dockvault-zk-uploads', 1);
                r.onupgradeneeded = () => {
                    const os = r.result.createObjectStore('pending', { keyPath: 'sessionId' });
                    os.createIndex('vaultId', 'vaultId', { unique: false });
                    os.createIndex('createdAt', 'createdAt', { unique: false });
                };
                r.onsuccess = () => res(r.result);
            });
            await new Promise(res => {
                const tx = v1.transaction('pending', 'readwrite');
                tx.objectStore('pending').put({
                    sessionId: 'legacy-1', vaultId: 'v', fileName: name, mimeType: mime,
                    totalSize: 4, totalChunks: 1, chunkSize: 4,
                    blob: new File([new Uint8Array([9,9,9,9])], name, { type: mime }),
                    createdAt: Date.now(),
                });
                tx.oncomplete = res;
            });
            v1.close();

            // Reading through the store triggers the upgrade.
            const back = await zkUploadStore.get('legacy-1');
            return {
                on_disk: describe(await rawRow('legacy-1')),
                read_back_bytes: back && back.blob ? back.blob.size : null,
            };
        }""",
        [SENTINEL_NAME, SENTINEL_MIME],
    )
    disk = out["on_disk"]
    assert disk is not None, "migration lost the record entirely"
    assert "fileName" not in disk["keys"], disk["keys"]
    assert "mimeType" not in disk["keys"], disk["keys"]
    assert disk["blob_is_File"] is False
    assert disk["blob_name"] is None
    assert disk["blob_type"] == "application/octet-stream"
    # This phase's stop-condition: migration must never discard the only ciphertext copy.
    assert disk["blob_size"] == 4, "migration lost the ciphertext"
    assert out["read_back_bytes"] == 4


def test_an_unmigrated_row_is_stripped_on_the_way_out(signed_in: Page) -> None:
    """A row can reach a reader unmigrated -- a blocked upgrade, or one the cursor pass missed.
    Nothing downstream should ever be handed the plaintext, even while it is still on disk."""
    out = signed_in.evaluate(
        _HELPERS + """async ([name, mime]) => {
            await wipe();
            // Open at the CURRENT version so no upgrade runs, then write a v1-shaped row.
            const db = await new Promise(res => {
                const r = indexedDB.open('dockvault-zk-uploads', 2);
                r.onupgradeneeded = () => {
                    const os = r.result.createObjectStore('pending', { keyPath: 'sessionId' });
                    os.createIndex('vaultId', 'vaultId', { unique: false });
                    os.createIndex('createdAt', 'createdAt', { unique: false });
                };
                r.onsuccess = () => res(r.result);
            });
            await new Promise(res => {
                const tx = db.transaction('pending', 'readwrite');
                tx.objectStore('pending').put({
                    sessionId: 'stale-1', vaultId: 'v', fileName: name, mimeType: mime,
                    totalSize: 4, blob: new File([new Uint8Array([7,7,7,7])], name, { type: mime }),
                    createdAt: Date.now(),
                });
                tx.oncomplete = res;
            });
            db.close();
            const back = await zkUploadStore.get('stale-1');
            return describe(back);
        }""",
        [SENTINEL_NAME, SENTINEL_MIME],
    )
    assert out is not None
    assert "fileName" not in out["keys"], out["keys"]
    assert "mimeType" not in out["keys"], out["keys"]
    assert out["blob_is_File"] is False
    assert out["blob_name"] is None
    assert out["blob_size"] == 4, "the defensive strip must not cost the ciphertext"


def test_this_page_does_not_block_another_tabs_upgrade(signed_in: Page) -> None:
    """A tab holding the old schema open is the one case where plaintext legitimately stays on
    disk, so this page's connection must yield rather than be that tab."""
    out = signed_in.evaluate(
        _HELPERS + """async () => {
            await wipe();
            const put = await zkUploadStore.put({
                sessionId: 'held', vaultId: 'v', totalSize: 1,
                blob: zkUploadStore.neutralBlob(new Blob([new Uint8Array([1])])),
                createdAt: Date.now(),
            });
            // A future version arriving, as another tab would. Without an onversionchange handler
            // that closes, this open is BLOCKED and that tab stays on the old schema.
            const result = await new Promise(res => {
                const r = indexedDB.open('dockvault-zk-uploads', 3);
                let blocked = false;
                r.onblocked = () => { blocked = true; };
                r.onsuccess = () => { r.result.close(); res(blocked ? 'blocked' : 'upgraded'); };
                r.onerror = () => res('error');
                setTimeout(() => res(blocked ? 'blocked' : 'timeout'), 4000);
            });
            return { result, put_ok: !!(put && put.ok) };
        }"""
    )
    # Without this the test passes vacuously: if no connection was ever opened there is
    # nothing to block, and the upgrade trivially succeeds.
    assert out["put_ok"] is True, "no connection was held, so the test proved nothing"
    assert out["result"] == "upgraded", (
        "this page held its connection open and blocked another tab's upgrade; that tab would "
        f"stay on the old schema with plaintext metadata on disk (got {out['result']!r})"
    )
