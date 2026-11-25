"""Offline unit tests for the built-in default email templates.

Each automated-email action ships with a polished default template (subject + HTML body). These are
seeded as real rows and pre-bound at boot, are the send-time fallback, and are the "Load From →
defaults" source. This file pins the catalog itself (no DB / no live instance): every action has a
default, the bodies survive sanitization with their tokens intact, and the payload the editor loads is
byte-identical to what would be stored.
"""
import re
from pathlib import Path

import pytest

from app.core import email_actions as ea
from app.core import email_sanitize as es

pytestmark = pytest.mark.unit

_ACTION_KEYS = {a["key"] for a in ea.ACTION_CATALOG}
# Which required dynamic token each SYSTEM security action's body must carry.
_REQUIRED_TOKEN = {"email_change": "action.code",
                   "email_confirm": "action.code",
                   "password_reset": "action.link",
                   "account_invite": "action.link",
                   "account_changed_by_admin": "action.change",
                   "sign_in_method_changed": "action.change",
                   "administrator_added": "action.change",
                   "ssh_keys_adder_left": "action.link",
                   "retention_change": "action.change",
                   "sign_in_policy_change": "action.change",
                   "auditor_right": "action.change",
                   "recorded_values_removal": "action.change"}
# The actions whose body needs more than one of them, each kept or the built-in body is used.
_ALSO_REQUIRED = {"ssh_keys_adder_left": ("action.change",)}


def test_every_action_has_a_default_template():
    assert set(ea.DEFAULT_TEMPLATES) == _ACTION_KEYS
    for key, spec in ea.DEFAULT_TEMPLATES.items():
        assert spec["name"].strip(), key
        assert spec["subject"].strip(), key
        assert spec["body_html"].strip(), key


def test_catalog_defaults_are_derived_from_the_template_catalog():
    # ACTION_CATALOG's default_subject/body/name come from DEFAULT_TEMPLATES — one source of truth, so
    # the seeded row, the send-time fallback, and Load-From can never drift.
    for a in ea.ACTION_CATALOG:
        spec = ea.DEFAULT_TEMPLATES[a["key"]]
        assert a["default_subject"] == spec["subject"]
        assert a["default_body_html"] == spec["body_html"]
        assert a["default_template_name"] == spec["name"]


@pytest.mark.parametrize("key,token", list(_REQUIRED_TOKEN.items()))
def test_system_security_bodies_carry_their_required_token(key, token):
    # Raw body and the sanitized (stored) body both keep the token — a substituted value, not a tag,
    # so nh3 never strips it.
    raw = ea.DEFAULT_TEMPLATES[key]["body_html"]
    assert token in raw
    assert token in es.sanitize_email_html(raw)


@pytest.mark.parametrize("key,token", list(_REQUIRED_TOKEN.items()))
def test_system_failsafe_restores_default_when_body_is_empty(key, token):
    # An admin who clears a SYSTEM template's body (but keeps a subject) must NOT ship a code/link-less
    # email: the fail-safe treats an empty body as the missing-token case and substitutes the built-in
    # default (which carries the required token). Would regress if the guard short-circuited on `not body`.
    spec = ea.SPEC_BY_KEY[key]
    for empty in ("", None, "   "):
        out = ea._fallback_body_if_missing_required_token(ea.SYSTEM, empty, spec)
        assert token in out, f"{key}: empty body did not fall back to the token-bearing default"
    # a body that DROPS the token also falls back; one that KEEPS it is returned unchanged
    assert token in ea._fallback_body_if_missing_required_token(ea.SYSTEM, "<p>no token here</p>", spec)
    kept = "".join(f"<p>{{{{{t}}}}}</p>" for t in (token,) + _ALSO_REQUIRED.get(key, ()))
    assert ea._fallback_body_if_missing_required_token(ea.SYSTEM, kept, spec) == kept


def test_public_base_url_is_the_configured_address_and_takes_no_request(monkeypatch):
    # Every emailed link is built on the configured public address (ALLOWED_HOSTS, through vault_url), never on
    # a request's Host header, which is whatever the request's sender wrote: the helper is not even given the
    # request. With no address configured it is empty, and the callers send no tokened link by email.
    import inspect
    assert list(inspect.signature(ea.public_base_url).parameters) == []
    monkeypatch.setattr(ea, "vault_url", lambda: "https://vault.example.com/")
    assert ea.public_base_url() == "https://vault.example.com"
    monkeypatch.setattr(ea, "vault_url", lambda: "")
    assert ea.public_base_url() == ""


def test_no_emailed_link_is_built_from_the_request():
    # Pins every caller. The server builds no URL from a request's base_url or Host header anywhere, and every
    # link base comes from _public_base_url(), called with nothing.
    import ast
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "base_url":
            raise AssertionError(f"a URL built from the request at line {node.lineno}: {ast.unparse(node)}")
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_public_base_url":
            assert not node.args and not node.keywords, f"line {node.lineno}: {ast.unparse(node)}"
        # A request's Host header, read as headers.get("host") or headers["host"].
        read = (node.args[0] if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get" and node.args else
                node.slice if isinstance(node, ast.Subscript) else None)
        holder = node.func.value if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else (
            node.value if isinstance(node, ast.Subscript) else None)
        if (isinstance(holder, ast.Attribute) and holder.attr == "headers" and isinstance(read, ast.Constant)
                and str(read.value).lower() in ("host", "x-forwarded-host")):
            raise AssertionError(f"a Host header read at line {node.lineno}: {ast.unparse(node)}")
    # Nor from the request's URL: its host, port and whole address are the Host header too. The one read allowed is the
    # download sink's, which asks only whether the page is on a secure context (localhost counts), and builds no link.
    owner = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                owner.setdefault(id(n), fn.name)
    allowed = {("hostname", "_resolved_download_sink")}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr in ("netloc", "hostname", "port")
                and isinstance(node.value, ast.Attribute) and node.value.attr == "url"):
            assert (node.attr, owner.get(id(node))) in allowed, f"line {node.lineno}: {ast.unparse(node)}"
        if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "str" and node.args
                and isinstance(node.args[0], ast.Attribute) and node.args[0].attr == "url"):
            raise AssertionError(f"the request's whole URL at line {node.lineno}: {ast.unparse(node)}")
    callers = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_public_base_url"]
    # invitation create and resend, self-service reset, an administrator's reset link, the promotion reset, the
    # SSH-key notice, the share notice, the expiry reminder and the upload notice
    assert len(callers) >= 9, len(callers)
    norm = re.sub(r"\s+", " ", src)
    assert "/?reset=" in norm and "/?invite=" in norm


def test_optional_action_has_no_failsafe_fallback():
    # Only SYSTEM security actions get the token fail-safe; an optional action's (possibly empty) body
    # is returned as-is (normalized to a string), never replaced with a default.
    spec = ea.SPEC_BY_KEY["share_created"]
    assert ea._fallback_body_if_missing_required_token(ea.OPTIONAL, "", spec) == ""
    assert ea._fallback_body_if_missing_required_token(ea.OPTIONAL, None, spec) == ""
    assert ea._fallback_body_if_missing_required_token(ea.OPTIONAL, "<p>hi</p>", spec) == "<p>hi</p>"


def test_default_bodies_sanitize_without_loss_of_structure():
    # The bodies use only allowlisted tags, so sanitizing them is (near) idempotent — nothing an admin
    # sees in the default is silently dropped the moment they save it.
    for key, spec in ea.DEFAULT_TEMPLATES.items():
        clean = es.sanitize_email_html(spec["body_html"])
        assert "<script" not in clean.lower(), key
        # headings + paragraphs survive
        assert "<p>" in clean, key
        # sanitizing the already-sanitized body is a fixed point
        assert es.sanitize_email_html(clean) == clean, key


def test_default_bodies_declare_no_unknown_tokens():
    # Every {{token}} used in a default is one the renderer actually knows — a typo'd token would ship
    # a literal {{...}} to real recipients.
    for key, spec in ea.DEFAULT_TEMPLATES.items():
        unknown = es.unknown_tokens(spec["body_html"]) + es.unknown_tokens(spec["subject"])
        assert not unknown, f"{key}: unknown tokens {unknown}"


def test_default_template_payloads_match_the_catalog():
    payloads = ea.default_template_payloads()
    # catalog order; a locked action, whose wording is fixed and which has no seeded row, is not offered
    assert [p["key"] for p in payloads] == [a["key"] for a in ea.ACTION_CATALOG if a["category"] != ea.LOCKED]
    assert [p["key"] for p in payloads] == _seeded_keys()
    for p in payloads:
        spec = ea.DEFAULT_TEMPLATES[p["key"]]
        assert p["name"] == spec["name"]
        assert p["subject"] == spec["subject"]
        # payload body is the sanitized default — exactly what seed_default_templates stores
        assert p["body_html"] == es.sanitize_email_html(spec["body_html"])
        assert "<script" not in p["body_html"].lower()


# ------------------------------------------------------------------------------------------------
# seed_default_templates binding logic — exercised offline against a minimal fake session so the
# rules (create-if-missing, bind-only-when-unbound, never-recreate) are pinned without a live DB.
# ------------------------------------------------------------------------------------------------
class _FakeAction:
    def __init__(self, key, template_id=None, category=None):
        self.key = key
        self.template_id = template_id
        # Real category drives the self-heal (SYSTEM actions bind to their default when unbound).
        self.category = category if category is not None else ea.SPEC_BY_KEY.get(key, {}).get("category", ea.OPTIONAL)


class _FakeQuery:
    def __init__(self, store):
        self._store = store
        self._key = None

    def filter(self, expr):
        # expr is `EmailTemplate.default_key == <key>` — pull the bound value out.
        self._key = getattr(getattr(expr, "right", None), "value", None)
        return self

    def first(self):
        return self._store.get(self._key)


class _FakeNested:
    """A no-op stand-in for db.begin_nested() (SAVEPOINT); exceptions propagate to the caller."""
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    """Just enough of a SQLAlchemy Session for seed_default_templates: query/add/flush/begin_nested/
    get/commit. add() STAGES; flush() commits staged rows into the store (and raises IntegrityError for
    a `fail_keys` default_key, so the savepoint-conflict branch is exercised without a real DB)."""
    def __init__(self, existing_templates=None, actions=None, fail_keys=None):
        self.templates = dict(existing_templates or {})   # default_key -> EmailTemplate
        self.actions = dict(actions or {})                # key -> _FakeAction
        self.commits = 0
        self._fail = set(fail_keys or [])
        self._staged = []

    def query(self, _model):
        return _FakeQuery(self.templates)

    def add(self, obj):
        import uuid
        obj.id = uuid.uuid4()
        self._staged.append(obj)

    def flush(self):
        from sqlalchemy.exc import IntegrityError
        staged, self._staged = self._staged, []
        for obj in staged:
            dk = getattr(obj, "default_key", None)
            if dk in self._fail:
                raise IntegrityError("INSERT", {}, Exception("duplicate default_key"))
            if dk:
                self.templates[dk] = obj

    def begin_nested(self):
        return _FakeNested()

    def get(self, _model, key):
        return self.actions.get(key)

    def commit(self):
        self.commits += 1


def _all_actions_unbound():
    return {k: _FakeAction(k) for k in ea.DEFAULT_TEMPLATES}


def _seeded_keys():
    """The actions a default template row is made for: every one but a locked one, whose wording is fixed."""
    return [k for k in ea.DEFAULT_TEMPLATES if ea.SPEC_BY_KEY[k]["category"] != ea.LOCKED]


def test_seed_creates_all_defaults_and_binds_unbound_actions():
    sess = _FakeSession(actions=_all_actions_unbound())
    n = ea.seed_default_templates(sess)
    assert n == len(_seeded_keys())                             # one default row per action but a locked one
    locked = [k for k in ea.DEFAULT_TEMPLATES if k not in _seeded_keys()]
    assert locked == ["sso_freshness_warning", "compliance_access_notice", "vault_access_notice",
                      "encryption_key_release_code", "encryption_key_notice"]
    for key in locked:
        assert key not in sess.templates and sess.actions[key].template_id is None
    for key in _seeded_keys():
        tpl = sess.templates[key]
        assert tpl.default_key == key
        assert tpl.body_html == es.sanitize_email_html(ea.DEFAULT_TEMPLATES[key]["body_html"])
        assert sess.actions[key].template_id == tpl.id         # pre-bound to its default


def test_seed_is_idempotent_when_defaults_already_exist():
    # Existing default rows for every key -> nothing CREATED. Unbound SYSTEM actions are self-healed
    # (bound to their existing default); OPTIONAL actions keep their "none".
    existing = {k: _FakeTemplate(default_key=k) for k in ea.DEFAULT_TEMPLATES}
    sess = _FakeSession(existing_templates=existing, actions=_all_actions_unbound())
    n = ea.seed_default_templates(sess)
    assert n == 0                                                     # no new rows
    for key in ea.DEFAULT_TEMPLATES:
        if ea.SPEC_BY_KEY[key]["category"] == ea.SYSTEM:
            assert sess.actions[key].template_id == existing[key].id  # SYSTEM: self-healed
        else:
            assert sess.actions[key].template_id is None             # OPTIONAL: untouched


def test_seed_self_heals_only_unbound_system_actions_when_defaults_exist():
    # The reported bug: default rows exist but the actions were never bound (created before the action
    # rows). A re-seed must bind the SYSTEM actions so editing their default template actually applies,
    # while leaving an OPTIONAL action's explicit "none" alone.
    existing = {k: _FakeTemplate(default_key=k) for k in ea.DEFAULT_TEMPLATES}
    sess = _FakeSession(existing_templates=existing, actions=_all_actions_unbound())
    ea.seed_default_templates(sess)
    for sys_key in ("password_reset", "account_invite", "email_change"):
        assert sess.actions[sys_key].template_id == existing[sys_key].id
    for opt_key in ("login_alert", "share_created", "account_welcome"):
        assert sess.actions[opt_key].template_id is None


def test_seed_self_heal_does_not_override_admin_custom_system_binding():
    # A SYSTEM action the admin bound to their OWN template is left alone (not reset to the default).
    import uuid
    existing = {k: _FakeTemplate(default_key=k) for k in ea.DEFAULT_TEMPLATES}
    actions = _all_actions_unbound()
    chosen = uuid.uuid4()
    actions["password_reset"].template_id = chosen
    sess = _FakeSession(existing_templates=existing, actions=actions)
    ea.seed_default_templates(sess)
    assert sess.actions["password_reset"].template_id == chosen       # admin's choice respected


def test_seed_never_rebinds_an_action_the_admin_already_set():
    # Fresh deploy but the admin already chose a template for one action before defaults seed.
    import uuid
    chosen = uuid.uuid4()
    actions = _all_actions_unbound()
    actions["login_alert"].template_id = chosen
    sess = _FakeSession(actions=actions)
    ea.seed_default_templates(sess)
    assert sess.actions["login_alert"].template_id == chosen           # admin choice respected
    # every other action but a locked one was bound to its freshly-created default
    for key in _seeded_keys():
        if key == "login_alert":
            continue
        assert sess.actions[key].template_id == sess.templates[key].id


def test_seed_skips_a_conflicting_default_without_double_binding():
    # Simulate a concurrent boot winning the partial-unique race on one key: our insert conflicts, so we
    # skip it (the winner binds that action) and still create+bind every other default.
    sess = _FakeSession(actions=_all_actions_unbound(), fail_keys={"share_created"})
    n = ea.seed_default_templates(sess)
    assert n == len(_seeded_keys()) - 1                             # the conflicting one wasn't created here
    assert sess.actions["share_created"].template_id is None        # not bound by us — no double-bind
    for key in _seeded_keys():
        if key == "share_created":
            continue
        assert sess.actions[key].template_id == sess.templates[key].id


class _FakeTemplate:
    def __init__(self, default_key=None):
        import uuid
        self.id = uuid.uuid4()
        self.default_key = default_key


def test_the_sign_in_method_email_is_described_by_everything_it_is_sent_for():
    """The administrator who reads the list of emails sees what this one tells a user of: it is sent for a
    passkey added or removed, an authenticator app set up, and a change to how the account signs in through a
    provider. A description that names only the first hides the others from the one who edits its template."""
    described = ea.SPEC_BY_KEY["sign_in_method_changed"]["description"]
    for sent_for in ("a passkey is added to or removed from", "an authenticator app is set up",
                     "single sign-on provider", "an identity linked or unlinked"):
        assert sent_for in described, sent_for
