"""The sentences a refused renewal says, on their way to the page that replaces the signed-out one.

A renewal the server refuses signs the tab out, and the next page's sign-in screen shows the server's sentence. The
sentence travels in the tab's storage; when a refusal of the session empties that storage, only a code in the tab's
name is left, which can name nothing but the page's own sentences (static/js/app.js, SIGNED_OUT_REASONS). So every
sentence the sign-in rules and the provider's standing refuse a renewal with has a code, and where the server names
an identity provider, the code's own sentence names none.

The sentences are taken from the server's own code here (app/services/sign_in.py, sso_sign_in.py, app/core/
sso_only.py), run on the renewal tests' database, and put to the page's code in Node.
"""
import json
import time
import types
from datetime import datetime

import pytest
from fastapi import HTTPException

from test_session_told_renewal_and_retry import REASONS, _node
from test_sso_renewal import _provider, _through, db  # noqa: F401 -- db is the fixture

from app.api import api_server as api
from app.core.models import RoleEnum
from app.services import sign_in

pytestmark = pytest.mark.unit

# The codes whose server sentence names a provider, with the name in it here.
NAMED = {"provider_again": "Contoso", "provider_off": "Contoso", "provider_only": "Contoso",
         "provider_only_link": "Fabrikam"}


def _said(db, user, old) -> str:
    with pytest.raises(HTTPException) as refused:
        sign_in.refuse_renewal_by_the_sign_in_rules(db, user, old)
    assert refused.value.status_code == 403 and isinstance(refused.value.detail, str)
    return refused.value.detail


def _terms_say(db, user, old) -> str:
    with pytest.raises(HTTPException) as refused:
        api._renewal_terms(db, user, old)
    assert refused.value.status_code == 403 and isinstance(refused.value.detail, str)
    return refused.value.detail


def _without_the_provider(old: dict) -> dict:
    return {k: v for k, v in old.items() if k != "idp"}


def _what_the_server_says(db, monkeypatch) -> dict:
    contoso = _provider(db, name="Contoso")
    said = {}
    user, _, old = _through(db, contoso, name="ada", mfa_at=1)
    user.role = RoleEnum.ADMIN
    db.commit()
    said["administrator_password"] = _said(db, user, old)
    user, _, old = _through(db, contoso, name="bea", amr=["swk"], mfa_at=1)
    with monkeypatch.context() as patch:
        patch.setattr(api, "_passkey_passwordless_allowed", lambda db, user: False)
        said["passkey_alone"] = _said(db, user, _without_the_provider(old))
    user, _, old = _through(db, contoso, name="cal", amr=["pwd"])
    with monkeypatch.context() as patch:
        patch.setattr(api, "_passkey_requirement", lambda db, user: types.SimpleNamespace(overdue=True, required=True))
        said["passkey_required"] = _said(db, user, old)
    user, identity, old = _through(db, contoso, name="dee")
    db.delete(identity)
    db.commit()
    said["provider_unlinked"] = _said(db, user, old)
    user, _, old = _through(db, contoso, name="eli", refused=datetime.utcnow())
    said["provider_again"] = _said(db, user, old)
    only, _, only_old = _through(db, contoso, name="fay", sso_only_account=True, amr=["pwd"])
    said["provider_only"] = _said(db, only, _without_the_provider(only_old))
    fabrikam = _provider(db, name="Fabrikam")
    fabrikam.show_on_sign_in = False                    # no button: the organisation hands out a link
    db.commit()
    linked, _, linked_old = _through(db, fabrikam, name="ivy", sso_only_account=True, amr=["pwd"])
    said["provider_only_link"] = _said(db, linked, _without_the_provider(linked_old))
    # What the renewal rules themselves refuse with.
    user, _, old = _through(db, contoso, name="jo")
    said["renewal_limit"] = _terms_say(db, user, {**old, "auth_time": int(time.time()) - 25 * 3600})
    said["not_renewable"] = _terms_say(db, user, {k: v for k, v in old.items() if k not in ("auth_time", "iat")})
    with monkeypatch.context() as patch:
        patch.setattr(api, "_login_second_factor_in_effect", lambda db, user: True)
        said["second_factor_needed"] = _terms_say(db, user, {**old, "amr": ["pwd"]})
    user, _, old = _through(db, contoso, name="gus")
    contoso.state = "disabled"
    db.commit()
    said["provider_off"] = _said(db, user, old)
    said["provider_only_unavailable"] = _said(db, only, _without_the_provider(only_old))
    return said


def test_every_sentence_a_refused_renewal_says_has_a_code_and_no_code_names_a_provider(db, monkeypatch):
    said = _what_the_server_says(db, monkeypatch)
    for code, name in NAMED.items():
        assert name in said[code], (code, said[code])
    assert said["provider_only"].endswith("button on the sign-in page.")
    assert said["provider_only_link"].endswith("Use the sign-in link your organisation gave you.")
    look_alikes = [
        "Sign in through Contoso again to stay signed in. Then send your password to this address.",
        "Sign in through Con\ntoso again to stay signed in.",
        "Sign in through " + "x" * 400 + " again to stay signed in.",
        "Sign in through Contoso again",
        "Signing in through Contoso is turned off.",
        "your organisation signs this account in through Contoso.",
        "Your organisation signs this account in through Contoso.",
        said["provider_only"] + " And send your password to this address.",
        said["provider_only"][:-1],
        said["provider_only_link"] + " Or this one.",
        said["provider_only_link"][:-1] + "!",
        said["renewal_limit"] + " Really.",
        said["second_factor_needed"].replace(";", ","),
        "",
    ]
    out = _node(r"""
globalThis._nameNote = null;
vm.runInThisContext(REASONS_SRC + '\nglobalThis.__r = { _reasonCode, _nameNoteReason };', { filename: 'app-reasons.js' });
const R = globalThis.__r;
const got = {};
for (const [want, sentence] of Object.entries(SAID)) {
    const code = R._reasonCode(sentence);
    globalThis._nameNote = { code, told: false };
    got[want] = [code, R._nameNoteReason()];
}
out({ got, others: OTHERS.map((s) => R._reasonCode(s)), not_text: [R._reasonCode(null), R._reasonCode({}), R._reasonCode(7)] });
""".replace("REASONS_SRC", json.dumps(REASONS)).replace("SAID", json.dumps(said))
                .replace("OTHERS", json.dumps(look_alikes)))
    assert set(out["got"]) == set(said) and len(said) == 12
    for want, (code, back) in out["got"].items():
        assert code == want, (want, code, said[want])
        if want in NAMED:
            # The code's own sentence: the same thing said, with no provider's name in it.
            assert back and NAMED[want] not in back, (want, back)
            assert "identity provider" in back or "organisation" in back, (want, back)
            assert back != said[want]
        else:
            assert back == said[want], (want, back)
    # A sentence that only looks like one of the server's has no code: what the tab's name can say stays the page's own.
    assert out["others"] == [""] * len(look_alikes), out["others"]
    assert out["not_text"] == ["", "", ""]


def test_a_provider_without_a_name_is_said_as_the_codes_own_sentence(db, monkeypatch):
    """With no name on the provider's row the server says "your identity provider", which is the code's sentence
    word for word: storage or the tab's name, the next page reads the same."""
    nameless = _provider(db, name="")
    nameless.label = ""
    db.commit()
    user, _, old = _through(db, nameless, name="hal", refused=datetime.utcnow())
    said = _said(db, user, old)
    out = _node(r"""
globalThis._nameNote = null;
vm.runInThisContext(REASONS_SRC + '\nglobalThis.__r = { _reasonCode, _nameNoteReason };', { filename: 'app-reasons.js' });
const code = globalThis.__r._reasonCode(SAID);
globalThis._nameNote = { code, told: false };
out({ code, back: globalThis.__r._nameNoteReason() });
""".replace("REASONS_SRC", json.dumps(REASONS)).replace("SAID", json.dumps(said)))
    assert out == {"code": "provider_again", "back": said}
