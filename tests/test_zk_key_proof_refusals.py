"""The refusal contract of the key-proof paths.

Every refusal is ``{"detail": <sentence>, "reason": <slug>}`` with a plain-string detail, and none is a
401. The wording is constrained by what clients already do with a detail: the web app signs a person out
on a 403 whose detail contains "inactive", "terminated" or "locked", and routes one containing "password",
"Password", "Unauthorized" or "401" to sign-in -- the same code runs in the older web app the desktop app
ships. A refusal that tripped either would sign an honest person out, or send them to the wrong screen,
for a key-proof problem. "locked" also rules out "unlocked", which contains it.
"""
import ast
import json
import re
from pathlib import Path

import pytest
from fastapi import FastAPI

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.services import zk_key_proof as kp  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"


def _forbidden(text: str) -> list:
    low = text.lower()
    return [word for word in kp.FORBIDDEN_IN_REFUSALS if word in low]


def test_the_forbidden_words_are_the_ones_the_web_app_acts_on():
    """Guards the guard: every word the web app's refusal handling tests for is on the list, and the list
    catches the word that hides one of them."""
    src = APP_JS.read_text(encoding="utf-8")
    refusals = src[src.index("if (response.status === 401) {"):src.index("// Handle 404 Not Found")]
    acted_on = set(re.findall(r"errorDetail\.includes\('([^']+)'\)", refusals))
    assert acted_on == {"inactive", "terminated", "locked", "password", "Password"}, acted_on
    misrouting = src[src.index("error.message.includes('password')"):][:300]
    acted_on |= set(re.findall(r"error\.message\.includes\('([^']+)'\)", misrouting))
    assert {"Unauthorized", "401"} <= acted_on, acted_on
    for word in acted_on:
        assert _forbidden(word), f"the web app acts on {word!r}, which the refusal check does not forbid"
    assert _forbidden("Your vault is unlocked") == ["locked"]
    assert _forbidden("Unauthorized") and _forbidden("error 401")


def test_the_table_is_the_designed_one():
    assert {slug: status for slug, (status, _) in kp.REFUSALS.items()} == {
        "zk-key-proof-required": 428,
        "zk-key-proof-setup-required": 428,
        "zk-key-proof-malformed": 400,
        "zk-key-proof-failed": 403,
        "zk-key-proof-interactive-only": 403,
        "zk-key-proof-stale": 409,
        "zk-key-proof-exists": 409,
        "zk-key-proof-verifier-unusable": 409,
    }
    assert kp.REFUSALS["zk-key-proof-failed"][1] == (
        "The proof that you hold this vault's key did not check out. Try again.")
    assert "Reload the page" in kp.REFUSALS["zk-key-proof-required"][1]


@pytest.mark.parametrize("slug", sorted(kp.REFUSALS))
def test_every_refusal_is_a_plain_sentence_without_a_word_a_client_acts_on(slug):
    status, sentence = kp.REFUSALS[slug]
    assert status != 401 and 400 <= status < 500
    assert isinstance(sentence, str) and sentence.endswith(".")
    assert not _forbidden(sentence), (slug, _forbidden(sentence))
    assert slug.startswith("zk-key-proof-") and re.fullmatch(r"[a-z-]+", slug)


def test_every_shape_message_is_clean_too():
    """The malformed refusal carries the specific shape message, so those messages are held to the
    same rule. Read from the source, so a message added later is covered without being listed here."""
    tree = ast.parse((ROOT / "app" / "services" / "zk_key_proof.py").read_text(encoding="utf-8"))
    messages = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("MalformedProof", "malformed") and node.args):
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                messages.append(arg.value)
            elif isinstance(arg, ast.JoinedStr):
                messages.append("".join(v.value for v in arg.values if isinstance(v, ast.Constant)))
    assert len(messages) >= 10, messages
    dirty = [m for m in messages if _forbidden(m)]
    assert dirty == []


def _app():
    app = FastAPI()
    app.add_exception_handler(kp.KeyProofRefusal, kp.refusal_handler)

    @app.post("/refuse/{slug}")
    async def refuse(slug: str):
        raise kp.KeyProofRefusal(slug)

    @app.post("/malformed")
    async def bad_shape():
        raise kp.malformed("sealed_private_key has the wrong length")

    return app


def _post(app, path):
    """One POST through the application, over raw ASGI (the suite has no HTTP test client)."""
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [], "http_version": "1.1", "scheme": "http", "server": ("test", 80),
             "client": ("127.0.0.1", 1), "root_path": ""}
    run_coroutine(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body)


@pytest.mark.parametrize("slug", sorted(kp.REFUSALS))
def test_the_handler_renders_detail_and_reason(slug):
    status, body = _post(_app(), f"/refuse/{slug}")
    assert status == kp.REFUSALS[slug][0]
    assert body == {"detail": kp.REFUSALS[slug][1], "reason": slug}


def test_the_malformed_refusal_says_what_was_wrong():
    status, body = _post(_app(), "/malformed")
    assert status == 400
    assert body == {"detail": "sealed_private_key has the wrong length", "reason": "zk-key-proof-malformed"}


def test_an_unknown_slug_is_a_programming_error():
    with pytest.raises(KeyError):
        kp.KeyProofRefusal("zk-key-proof-maybe")


def test_the_application_renders_the_refusal():
    from app.api import api_server as api
    assert api.app.exception_handlers.get(kp.KeyProofRefusal) is kp.refusal_handler
