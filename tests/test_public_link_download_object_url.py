"""A file saved from a public link is never handed to the browser under the type its uploader claimed.

A stored MIME type is whatever the uploading browser sent, and an object address (``blob:``) carries the
vault's origin. The public link page reads a file whole and saves it by pointing a link at such an
address. A browser that honours the link's ``download`` attribute saves it; one that does not opens it,
and under a page's type what it opens is a page of this origin. So the address is made under a type a
browser only saves, and the file keeps the name the link gives it.

The SHIPPED page script (static/js/public-link.js, run as is) is driven here under Node against a
stand-in page: a link is opened, each of its Download buttons is pressed, and what the script hands the
browser is read back. The last test holds the script to that one way of making an object address.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from _js_source import strip_comments

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "static" / "js" / "public-link.js"
BYTES = "application/octet-stream"
CONTENT = [60, 104, 49, 62]

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const SOURCE = fs.readFileSync(process.argv[2], 'utf8');
const CONTENT = JSON.parse(process.argv[4]);
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

const open = async (link) => {
    const made = [], events = [], asked = [], answered = [];
    const element = (tag) => {
        const listeners = {}, classes = new Set();
        const node = {
            tag, children: [], textContent: '', disabled: false, listeners,
            classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c),
                         contains: (c) => classes.has(c) },
            addEventListener: (type, fn) => { listeners[type] = fn; },
            setAttribute() {}, focus() {},
            appendChild: (child) => { node.children.push(child); if (tag === 'body') events.push('added'); return child; },
            remove: () => { events.push('removed'); },
            click: () => { events.push('clicked ' + node.href + ' saving ' + node.download); },
        };
        return node;
    };
    const byId = {};
    const document = {
        readyState: 'complete', body: element('body'), addEventListener() {},
        getElementById: (id) => byId[id] || (byId[id] = element(id)),
        createElement: element,
    };
    let grants = 0;
    const fetch = async (address, init) => {
        const grant = init.headers['X-Download-Grant'];
        asked.push(init.method + ' ' + address + (grant ? ' with ' + grant : '') + (init.body ? ' ' + init.body : ''));
        if (init.method === 'POST') {
            // Opening the link lists it; pressing Download asks again and is given a grant for one file.
            const peek = JSON.parse(init.body).peek === true;
            const listing = peek ? link.listing : { ...link.listing, grant: 'grant-' + (++grants) };
            return { status: 200, json: async () => listing };
        }
        // The server's answer: the file's bytes, under the type the file was stored with.
        const id = decodeURIComponent(address.split('/download/')[1]);
        const blob = new Blob([new Uint8Array(CONTENT)], { type: link.types[id] });
        answered.push(blob.type);
        return { status: 200, blob: async () => blob };
    };
    const page = {
        window: { location: { pathname: '/p/' + link.token } }, document, fetch, Blob, setTimeout,
        URL: {
            createObjectURL: (blob) => { made.push(blob); events.push('made'); return 'blob:https://vault.example/' + made.length; },
            revokeObjectURL: (address) => { events.push('revoked ' + address); },
        },
    };
    new vm.Script(SOURCE, { filename: 'public-link.js' }).runInNewContext(page);

    const listing = document.getElementById('listing');
    for (let i = 0; i < 200 && !listing.children.length; i++) await tick();
    const buttons = listing.children.map((row) => row.children.find((c) => c.tag === 'button')).filter(Boolean);
    const saved = [];
    for (const button of buttons) {
        const from = made.length;
        events.length = 0;
        button.listeners.click();
        const settled = () => button.disabled === false && events.some((e) => e.startsWith('revoked'));
        for (let i = 0; i < 100 && !settled(); i++) await tick();
        const mine = made.slice(from);
        saved.push({
            made: mine.map((blob) => blob.type),
            bytes: mine.length ? Array.from(new Uint8Array(await mine[0].arrayBuffer())) : null,
            events: [...events],
            pressable: button.disabled === false,
            refused: !document.getElementById('dl-error').classList.contains('hidden'),
        });
    }
    return { title: document.getElementById('title').textContent, saved, asked, answered };
};

(async () => {
    const out = [];
    for (const link of JSON.parse(process.argv[3])) out.push(await open(link));
    process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""


def _file(token: str, name, stored: str) -> dict:
    return {"token": token, "listing": {"kind": "file", "name": name, "file_id": "f1", "size": 4},
            "types": {"f1": stored}, "files": [("f1", name or "download", stored)]}


# What a link shows, and the type each of its files was stored with.
LINKS = [
    _file("page-as-picture", "holiday.png", "application/xhtml+xml"),
    _file("page", "page.html", "text/html"),
    _file("drawing", "drawing.svg", "image/svg+xml"),
    _file("script", "code.js", "text/javascript"),
    _file("contract", "contract.pdf", "application/pdf"),
    _file("picture", "holiday.png", "image/png"),
    _file("untyped", "notes", ""),
    _file("unnamed", None, "text/html"),
    {"token": "folder",
     "listing": {"kind": "folder", "name": "shared", "entries": [
         {"id": "a", "name": "page.html", "size": 4, "is_folder": False},
         {"id": "inner", "name": "inner", "is_folder": True},
         {"id": "b", "name": "clip.mp4", "size": 4, "is_folder": False}]},
     "types": {"a": "text/html", "b": "application/x-thing+xml"},
     "files": [("a", "page.html", "text/html"), ("b", "clip.mp4", "application/x-thing+xml")]},
]
SAVES = [(link, at) for link in range(len(LINKS)) for at in range(len(LINKS[link]["files"]))]


@pytest.fixture(scope="module")
def opened():
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    links = [{key: link[key] for key in ("token", "listing", "types")} for link in LINKS]
    done = subprocess.run([node, "-", str(PAGE), json.dumps(links), json.dumps(CONTENT)], input=HARNESS,
                          capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    got = json.loads(done.stdout)
    assert len(got) == len(LINKS)
    return got


@pytest.mark.parametrize("link", range(len(LINKS)), ids=[link["token"] for link in LINKS])
def test_the_stand_in_server_answers_under_the_type_each_file_was_stored_with(opened, link):
    """The control: the answer the page reads does carry the stored type, and every file is asked for with a
    grant of its own, so the test below cannot pass by the stand-in losing the type or the page saving nothing."""
    token, files = LINKS[link]["token"], LINKS[link]["files"]
    got = opened[link]
    assert got["answered"] == [stored for _id, _name, stored in files]
    asked = [f'POST /public-links/{token}/redeem {{"peek":true}}']
    for number, (file_id, _name, _stored) in enumerate(files, start=1):
        asked += [f"POST /public-links/{token}/redeem {{}}",
                  f"GET /public-links/{token}/download/{file_id} with grant-{number}"]
    assert got["asked"] == asked
    assert len(got["saved"]) == len(files)


@pytest.mark.parametrize("link,at", SAVES,
                         ids=[f'{LINKS[link]["token"]}-{LINKS[link]["files"][at][2] or "untyped"}' for link, at in SAVES])
def test_a_file_saved_from_a_public_link_is_handed_over_as_plain_bytes_under_its_own_name(opened, link, at):
    _id, name, _stored = LINKS[link]["files"][at]
    got = opened[link]["saved"][at]
    assert got["pressable"] and not got["refused"], got
    # One address, of a type a browser only saves, with every byte of the file behind it.
    assert got["made"] == [BYTES], got
    assert got["bytes"] == CONTENT
    # Made, clicked under the file's own name, taken off the page, and withdrawn.
    address = f"blob:https://vault.example/{at + 1}"
    assert got["events"] == ["made", "added", f"clicked {address} saving {name}", "removed",
                             f"revoked {address}"], got


def test_the_page_makes_an_object_address_in_that_one_way_only():
    code = strip_comments(PAGE.read_text(encoding="utf-8"))
    assert code.count("createObjectURL") == 1
    assert 'var url = URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));' in code
