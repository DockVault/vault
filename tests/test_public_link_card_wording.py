"""The owner's card for a public file link says what its uses delivered, run under Node.

Opening a link for a download spends a use, and a download that reaches its last byte counts once. A
used link that delivered nothing (the person opened it and the transfer never finished, or never
started) must read differently from one that delivered its file, from those two counts alone. The test
runs the SHIPPED functions, lifted out of ``static/js/app.js`` verbatim, against a stand-in for the few
DOM calls they make. tests/test_ui_public_link_card.py reads the same wording off the real dialog.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(name):
    head = f"\nfunction {name}("
    assert JS.count(head) == 1, name
    start = JS.index(head) + 1
    return JS[start:JS.index("\n}\n", start) + 3]


def _line(head):
    assert JS.count("\n" + head) == 1, head
    start = JS.index("\n" + head) + 1
    return JS[start:JS.index("\n", start) + 1]


HARNESS = """
const document = { createElement: (tag) => ({ tag, className: '', textContent: '', dataset: {}, children: [],
                                               appendChild(c) { this.children.push(c); return c; } }) };
""" + _function("_el") + _function("_pflDelivery") + _line("const _PFL_DELIVERY_CLASS") + _function("_pflUsesCell")


def _run(links):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    body = HARNESS + f"""
const out = {json.dumps(links)}.map((l) => {{
  const td = _pflUsesCell(l);
  const [count, line] = td.children;
  return {{ count: count.textContent, text: line.textContent, state: line.dataset.delivery,
           cls: line.className }};
}});
process.stdout.write(JSON.stringify(out));
"""
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8",
                          timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


# (use_count, download_count, max_uses, status) -> (count, wording, state)
STATES = [
    ((0, 0, 1, "active"), ("0/1", "Not used yet", "unused")),
    ((0, 0, 1, "expired"), ("0/1", "Never used", "unused")),
    ((1, 0, 1, "exhausted"), ("1/1", "Used, nothing downloaded", "nothing")),
    ((2, 0, None, "active"), ("2", "Used, nothing downloaded", "nothing")),
    ((1, 1, 1, "exhausted"), ("1/1", "Downloaded", "downloaded")),
    ((3, 3, 5, "active"), ("3/5", "Downloaded 3 times", "downloaded")),
    ((3, 2, 3, "exhausted"), ("3/3", "Used 3 times, 2 downloaded", "partly")),
]


def test_each_state_reads_as_what_the_link_delivered():
    links = [{"use_count": u, "download_count": d, "max_uses": m, "status": s} for (u, d, m, s), _ in STATES]
    got = _run(links)
    for (inputs, (count, text, state)), row in zip(STATES, got):
        assert (row["count"], row["text"], row["state"]) == (count, text, state), inputs


def test_used_with_nothing_downloaded_is_marked_apart_from_delivered():
    used, delivered = _run([{"use_count": 1, "download_count": 0, "max_uses": 1, "status": "exhausted"},
                            {"use_count": 1, "download_count": 1, "max_uses": 1, "status": "exhausted"}])
    assert used["text"] != delivered["text"]
    assert "text-warning" in used["cls"].split() and "text-success" in delivered["cls"].split()


def test_both_tables_show_the_uses_cell():
    # The owner's list and the administrators' oversight list draw the same cell under the same heading.
    for table in ("renderMyPublicLinks", "renderAdminPublicLinks"):
        body = _function(table)
        assert body.count("tr.appendChild(_pflUsesCell(l));") == 1, table
        assert "'Expires', 'Uses', ''" in body and "'Downloads'" not in body, table
