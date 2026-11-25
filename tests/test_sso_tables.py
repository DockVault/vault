"""The single sign-on stores: the provider row, the identity link, the provider session, the group mapping, the
held administrator request, and the account's sso_only flag; their shapes, their boot statement, and that the
inventory, the recording notice and the per-person erase know them. Offline."""
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _models():
    set_bare_api_env()
    from app.core import models
    return models


def _fk(column):
    (fk,) = column.foreign_keys
    return fk.target_fullname, fk.ondelete


def test_the_provider_row_can_exist_before_it_is_configured_and_never_returns_its_secret_in_the_clear():
    m = _models()
    t = m.SsoProvider.__table__
    assert t.name == "sso_providers"
    assert t.c.state.default.arg == "draft" and t.c.kind.nullable is False and t.c.name.unique
    # Everything the wizard fills in later may be empty on the draft row.
    for name in ("label", "icon", "issuer", "discovery_url", "client_id", "client_secret_enc", "claims", "policy",
                 "last_test", "created_by", "created_by_name"):
        assert t.c[name].nullable, name
    assert t.c.client_secret_enc.name.endswith("_enc")           # encrypted at rest, by name
    assert t.c.token_auth.default.arg == "client_secret_basic" and t.c.scopes.default.arg == "openid profile email"
    assert t.c.private_network.default.arg is False and t.c.show_on_sign_in.default.arg is False
    # The SAML columns exist on the same row and are all optional (NULL for an OpenID Connect provider).
    saml = [c.name for c in t.columns if c.name.startswith("saml_")]
    assert set(saml) == {"saml_idp_entity_id", "saml_sso_url", "saml_idp_certs", "saml_name_id_format",
                         "saml_identity_source", "saml_attr_username", "saml_attr_email", "saml_attr_name",
                         "saml_attr_groups", "saml_sign_authn_request", "saml_want_assertions_encrypted",
                         "saml_require_signed_response", "saml_idp_initiated", "saml_clock_skew_seconds",
                         "saml_metadata_url"}
    assert all(t.c[name].nullable for name in saml)
    assert _fk(t.c.created_by) == ("users.id", "SET NULL")


def test_one_account_per_subject_and_one_subject_per_account_at_a_provider():
    m = _models()
    t = m.ExternalIdentity.__table__
    assert t.name == "external_identities"
    assert _fk(t.c.user_id) == ("users.id", "CASCADE") and _fk(t.c.provider_id) == ("sso_providers.id", "CASCADE")
    assert t.c.subject.type.python_type is str and getattr(t.c.subject.type, "length", None) is None   # TEXT
    assert not t.c.subject_source.nullable and t.c.subject_source.type.length == 120
    uniques = {tuple(c.name for c in u.columns) for u in t.constraints if u.__class__.__name__ == "UniqueConstraint"}
    assert ("provider_id", "subject") in uniques and ("provider_id", "user_id") in uniques
    for name in ("tenant_id", "email_at_link", "display_name", "last_sign_in_at"):
        assert t.c[name].nullable, name
    assert not t.c.linked_by.nullable and not t.c.issuer.nullable


def test_a_provider_session_goes_with_the_session_and_holds_the_token_only_when_asked():
    m = _models()
    t = m.SsoSession.__table__
    assert t.name == "sso_sessions"
    assert t.c.session_id.primary_key and _fk(t.c.session_id) == ("active_sessions.id", "CASCADE")
    assert _fk(t.c.provider_id) == ("sso_providers.id", "CASCADE")
    for name in ("idp_sid", "idp_sub", "auth_time", "id_token_enc"):
        assert t.c[name].nullable, name
    indexed = {tuple(c.name for c in ix.columns) for ix in t.indexes}
    assert ("provider_id", "idp_sid") in indexed and ("provider_id", "idp_sub") in indexed


def test_group_mappings_and_administrator_requests():
    m = _models()
    g = m.SsoGroupMapping.__table__
    assert g.name == "sso_group_mappings"
    assert _fk(g.c.provider_id) == ("sso_providers.id", "CASCADE") and _fk(g.c.department_id) == ("groups.id", "CASCADE")
    assert g.c.department_id.nullable and g.c.role.nullable and not g.c.provider_group.nullable
    uniques = {tuple(c.name for c in u.columns) for u in g.constraints if u.__class__.__name__ == "UniqueConstraint"}
    assert ("provider_id", "provider_group") in uniques
    r = m.SsoAdminRequest.__table__
    assert r.name == "sso_admin_requests"
    assert _fk(r.c.user_id) == ("users.id", "CASCADE") and _fk(r.c.provider_id) == ("sso_providers.id", "CASCADE")
    assert _fk(r.c.decided_by) == ("users.id", "SET NULL") and r.c.decided_by_name.nullable
    assert r.c.state.default.arg == "held" and not r.c.expires_at.nullable


def test_the_sso_only_flag_is_nullable_and_added_at_start_up():
    m = _models()
    col = m.User.__table__.c.sso_only
    assert col.nullable and col.type.python_type is bool
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = src[src.index("def _run_lightweight_migrations"):]
    body = body[:body.index("\ndef ", 1)]
    assert body.count('"ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_only BOOLEAN"') == 1


def test_the_inventory_the_notice_and_the_erase_know_the_stores():
    set_bare_api_env()
    from app.core import person_erase as pe, recording_notice as rn
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    for table in ("sso_providers", "external_identities", "sso_sessions", "sso_group_mappings", "sso_admin_requests"):
        assert any(line.startswith(f"| `{table}`") for line in text.splitlines()), table
    assert "`users.sso_only`" in text.split("## What 0.36.0 added")[1]
    notice = {s.key for s in rn.STORES}
    assert {"external_identities", "sso_sessions", "sso_providers", "sso_admin_requests"} <= notice
    assert "encrypted" in next(s for s in rn.STORES if s.key == "sso_sessions").what
    # The last test's summary names people: who ran it, and the account a sign-in of their identity would reach.
    providers = next(s for s in rn.STORES if s.key == "sso_providers").what
    assert ("the summary of its last test sign-in (the tester's username, and the account a sign-in of the tester's "
            "identity would link or create)") in providers
    # The usernames kept after an account is deleted are replaced by a per-person erase.
    assert "sso_providers" in pe.STORE_KEYS and "sso_admin_requests" in pe.STORE_KEYS
