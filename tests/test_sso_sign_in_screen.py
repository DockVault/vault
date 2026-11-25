"""The sign-in screen's part of single sign-on (static/js/app.js with static/js/sso.js), and where its sentences point.

The page's own functions run in Node on the small document of tests/js/mini_dom.js, against stand-ins for the server
(the server's side has its own tests). What is proved here: the sentences that send a person to Your account name a
place the page has under that name.
"""
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "static" / "index.html"


class _ItemText(HTMLParser):
    """The text of the element with one id, and of every element inside it."""

    def __init__(self, element_id):
        super().__init__()
        self.element_id, self.depth, self.text = element_id, 0, []

    def handle_starttag(self, tag, attrs):
        if self.depth:
            self.depth += 1
        elif dict(attrs).get("id") == self.element_id:
            self.depth = 1

    def handle_endtag(self, tag):
        if self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if self.depth:
            self.text.append(data)


def _text_of(element_id: str) -> str:
    parser = _ItemText(element_id)
    parser.feed(INDEX.read_text(encoding="utf-8"))
    return " ".join("".join(parser.text).split())


def test_the_profile_menu_names_the_dialog_it_opens_as_the_sentences_name_it():
    """Sentences of the sign-in and of the account send people "under Your account". The profile menu's item that
    opens that dialog is called the same, and the dialog's title and its single sign-on section say so too."""
    assert _text_of("settings-btn") == "Your account"
    html = INDEX.read_text(encoding="utf-8")
    dialog = html[html.index('<div id="user-settings-modal"'):]
    assert re.search(r"<h3>[^<]*<svg[^>]*><use[^>]*/></svg>\s*Your account</h3>", dialog[:600]), dialog[:600]
    assert '<h4 class="us-section-title">Single sign-on</h4>' in dialog
