"""Settings help texts say one sentence, with the rest under "More": run under Node on the real markup.

The Settings section of ``static/index.html`` is read as it ships, handed to the shipped
``static/js/settings-help.js`` in a small stand-in document (``tests/js/help_dom.js``), and shortened the
way the page does it when Settings opens. Then every help-like text in Settings (a ``.form-help``, a
``p.text-secondary``, a ``<small>`` hint, an email hint) must show forty words or fewer before "More",
keep every link, code span and bold word it had, and stay as it is on a second pass. What the browser
draws is the UI lane (``test_ui_settings_pages.py``).
"""
import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class _Tree(HTMLParser):
    """The document as nested [tag, attrs, children] lists, text kept as strings."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = ["body", {}, []]
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        el = [tag, {k: (v if v is not None else "") for k, v in attrs}, []]
        self.stack[-1][2].append(el)
        if tag not in VOID:
            self.stack.append(el)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1][2].append([tag, {k: (v if v is not None else "") for k, v in attrs}, []])

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self.stack[-1][2].append(data)


def _find(node, element_id):
    if isinstance(node, str):
        return None
    if node[1].get("id") == element_id:
        return node
    for kid in node[2]:
        hit = _find(kid, element_id)
        if hit is not None:
            return hit
    return None


def _settings_tree():
    parser = _Tree()
    parser.feed(INDEX)
    section = _find(parser.root, "settings-section")
    assert section is not None, "the Settings section is not in index.html"
    return section


HARNESS = r"""
const { Document, Node } = require('./tests/js/help_dom.js');
const fs = require('fs');
const vm = require('vm');
global.document = new Document();
global.window = global;
global.Node = Node;
vm.runInThisContext(fs.readFileSync('static/js/settings-help.js', 'utf8'), { filename: 'settings-help.js' });
const tree = JSON.parse(fs.readFileSync(0, 'utf8'));
document.body.appendChild(document.build(tree));
const words = (t) => t.trim().split(/\s+/).filter(Boolean).length;
const SEL = SettingsHelp.HELP_SELECTOR;
const helps = () => document.getElementById('settings-section').querySelectorAll(SEL)
    .filter((el) => !el.closest('.help-more') && !el.querySelector(SEL));
// Visible text: everything but what waits under "More".
const shown = (el) => el.childNodes.filter((c) => !(c.nodeType === 1 && c.className === 'help-more'))
    .map((c) => c.textContent).join('');
const marks = (el) => el.querySelectorAll('a, code, strong, b, em').map((m) => m.localName + ':' + m.textContent.trim());
const flat = (t) => t.replace(/\s+/g, ' ').trim();
const before = helps().map((el) => ({ text: flat(el.textContent), marks: marks(el) }));
const changed = SettingsHelp.shorten();
const after = helps().map((el) => {
    const more = el.querySelector('.help-more');
    return {
        text: flat(shown(el) + ' ' + (more ? more.querySelector('.help-more-text').textContent : '')),
        shownWords: words(shown(el)), shown: flat(shown(el)).slice(0, 120),
        marks: marks(el), split: !!more,
        restText: more ? more.querySelector('.help-more-text').textContent : '',
    };
});
const again = SettingsHelp.shorten();
process.stdout.write(JSON.stringify({ before, after, changed, again,
    longBefore: before.filter((b) => words(b.text) > SettingsHelp.LONG_WORDS).length }));
"""


def _run():
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-e", HARNESS], input=json.dumps(_settings_tree()), capture_output=True, text=True,
                          encoding="utf-8", timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def result():
    return _run()


def test_settings_has_long_help_texts_and_the_page_shortens_each_one(result):
    """Not vacuous: the markup holds help texts over forty words, and every one of them is split."""
    assert result["longBefore"] >= 10, result["longBefore"]
    assert result["changed"] == result["longBefore"], (result["changed"], result["longBefore"])


def test_no_help_text_in_settings_shows_more_than_forty_words_before_more(result):
    too_long = [(a["shownWords"], a["shown"]) for a in result["after"] if a["shownWords"] > 40]
    assert too_long == [], too_long


def test_a_split_keeps_every_link_code_span_and_bold_word(result):
    assert len(result["before"]) == len(result["after"])
    for b, a in zip(result["before"], result["after"]):
        assert a["marks"] == b["marks"], (b["text"][:80], b["marks"], a["marks"])


def test_a_split_loses_no_words(result):
    for b, a in zip(result["before"], result["after"]):
        assert a["text"].split() == b["text"].split(), (b["text"][:80], a["text"][:80])
        if a["split"]:
            assert a["restText"].strip(), b["text"][:80]


def test_a_second_pass_changes_nothing(result):
    assert result["again"] == 0
