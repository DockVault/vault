"""The count on a card in Shared with me, run as shipped.

``_sharedCard`` from ``static/js/app.js`` runs under Node against a small stand-in page. A capped share that can be
downloaded counts downloads. A capped view-only share whose recipient can view files counts previews (a preview is
what spends that share's allowance; the download count never moves for this recipient). A capped share that shows
names and sizes only counts nothing. The live counterpart is in tests/test_ui_view_only_preview.py.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _block(head: str, end: str) -> str:
    start = APP.index(head)
    return APP[start:APP.index(end, start) + len(end)]


LIFTED = "\n".join([
    _block("function _el(tag, cls, text) {", "\n}\n"),
    _block("const _SVGNS =", ";\n"),
    _block("function _svgIcon(name, cls) {", "\n}\n"),
    _block("function _sharedKindLabel(t) {", "}\n"),
    _block("function _sharedCard(it) {", "\n}\n"),
])

PAGE = r"""
class El {
    constructor(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.className = '';
                       this._text = ''; }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    appendChild(c) { this.children.push(c); return c; }
    addEventListener() {}
}
class Text { constructor(t) { this.textContent = t; this.children = []; } }
global.document = { createElement: (t) => new El(t), createElementNS: (ns, t) => new El(t),
                    createTextNode: (t) => new Text(t) };
const People = { chip: (u) => new Text(u.username), time: (t) => new Text(t) };
const openSharedItem = () => {}, claimPushedShare = () => {};
const spans = (el) => [...(el.className !== undefined && el.tagName === 'span' ? [el] : []),
                       ...(el.children || []).flatMap(spans)];
"""


def _cards(items):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (PAGE + LIFTED + "const out = " + json.dumps(items) + ".map((it) => {\n"
              "  const card = _sharedCard(it);\n"
              "  return { text: card.textContent,\n"
              "           spans: spans(card).map((s) => [s.className, s.textContent.trim()]) };\n"
              "});\nprocess.stdout.write(JSON.stringify(out));")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8",
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


BASE = {"share_id": "s1", "status": "active", "target_type": "file", "target_name": "report.txt",
        "vault_name": "Team", "max_downloads": 3}


def test_each_kind_of_capped_share_counts_what_its_recipient_spends():
    downloadable, viewable, names_only = _cards([
        {**BASE, "view_only": False, "view_only_preview": False, "download_count": 1, "preview_count": 2},
        {**BASE, "view_only": True, "view_only_preview": True, "download_count": 0, "preview_count": 2},
        {**BASE, "view_only": True, "view_only_preview": False, "download_count": 0, "preview_count": 0},
    ])
    # Downloads for a share that can be downloaded.
    assert ["", "1/3 downloads"] in downloadable["spans"], downloadable
    assert "previews" not in downloadable["text"], downloadable
    # Previews, from the preview count, for a view-only share whose recipient views files; never downloads.
    assert ["shared-previews", "2/3 previews"] in viewable["spans"], viewable
    assert "downloads" not in viewable["text"], viewable
    # Nothing counted for a share that shows names and sizes only.
    assert "/3" not in names_only["text"], names_only
    assert "View only (names and sizes only)" in names_only["text"], names_only


def test_an_uncapped_share_counts_nothing_and_an_unclaimed_viewable_one_starts_at_zero():
    uncapped, unclaimed = _cards([
        {**BASE, "max_downloads": None, "view_only": True, "view_only_preview": True, "preview_count": 2},
        {**BASE, "status": "available", "view_only": True, "view_only_preview": True},
    ])
    assert "/" not in uncapped["text"].replace("report.txt", ""), uncapped
    assert ["shared-previews", "0/3 previews"] in unclaimed["spans"], unclaimed
