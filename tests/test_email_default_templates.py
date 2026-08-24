"""Offline unit tests for the built-in default email templates.

Each automated-email action ships with a polished default template (subject + HTML body). These are
seeded as real rows and pre-bound at boot, are the send-time fallback, and are the "Load From →
defaults" source. This file pins the catalog itself (no DB / no live instance): every action has a
default, the bodies survive sanitization with their tokens intact, and the payload the editor loads is
byte-identical to what would be stored.
"""
import pytest

from app.core import email_actions as ea
from app.core import email_sanitize as es

pytestmark = pytest.mark.unit

_ACTION_KEYS = {a["key"] for a in ea.ACTION_CATALOG}
# Which required dynamic token each SYSTEM security action's body must carry.
_REQUIRED_TOKEN = {"email_change": "action.code",
                   "password_reset": "action.link",
                   "account_invite": "action.link"}


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
    assert [p["key"] for p in payloads] == [a["key"] for a in ea.ACTION_CATALOG]  # catalog order
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
    def __init__(self, key, template_id=None):
        self.key = key
        self.template_id = template_id


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


def test_seed_creates_all_defaults_and_binds_unbound_actions():
    sess = _FakeSession(actions=_all_actions_unbound())
    n = ea.seed_default_templates(sess)
    assert n == len(ea.DEFAULT_TEMPLATES)                       # one default row per action
    for key in ea.DEFAULT_TEMPLATES:
        tpl = sess.templates[key]
        assert tpl.default_key == key
        assert tpl.body_html == es.sanitize_email_html(ea.DEFAULT_TEMPLATES[key]["body_html"])
        assert sess.actions[key].template_id == tpl.id         # pre-bound to its default


def test_seed_is_idempotent_when_defaults_already_exist():
    # Existing default rows for every key -> nothing created, nothing re-bound.
    existing = {k: _FakeTemplate(default_key=k) for k in ea.DEFAULT_TEMPLATES}
    sess = _FakeSession(existing_templates=existing, actions=_all_actions_unbound())
    n = ea.seed_default_templates(sess)
    assert n == 0
    assert all(a.template_id is None for a in sess.actions.values())   # untouched on a re-seed


def test_seed_never_rebinds_an_action_the_admin_already_set():
    # Fresh deploy but the admin already chose a template for one action before defaults seed.
    import uuid
    chosen = uuid.uuid4()
    actions = _all_actions_unbound()
    actions["login_alert"].template_id = chosen
    sess = _FakeSession(actions=actions)
    ea.seed_default_templates(sess)
    assert sess.actions["login_alert"].template_id == chosen           # admin choice respected
    # every other action was bound to its freshly-created default
    for key in ea.DEFAULT_TEMPLATES:
        if key == "login_alert":
            continue
        assert sess.actions[key].template_id == sess.templates[key].id


def test_seed_skips_a_conflicting_default_without_double_binding():
    # Simulate a concurrent boot winning the partial-unique race on one key: our insert conflicts, so we
    # skip it (the winner binds that action) and still create+bind every other default.
    sess = _FakeSession(actions=_all_actions_unbound(), fail_keys={"share_created"})
    n = ea.seed_default_templates(sess)
    assert n == len(ea.DEFAULT_TEMPLATES) - 1                       # the conflicting one wasn't created here
    assert sess.actions["share_created"].template_id is None        # not bound by us — no double-bind
    for key in ea.DEFAULT_TEMPLATES:
        if key == "share_created":
            continue
        assert sess.actions[key].template_id == sess.templates[key].id


class _FakeTemplate:
    def __init__(self, default_key=None):
        import uuid
        self.id = uuid.uuid4()
        self.default_key = default_key
