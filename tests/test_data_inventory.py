"""docs/data-inventory.md stays a complete list an operator can put in a record of processing.

It says, for every store of personal data, which fields, why, for how long and how it is erased. An
inventory that silently misses the table a release adds is worse than none, because an operator
relies on it being whole. So every table the models declare must be named in it (the ones that hold
no personal data are named too, under "Other tables"), every setting it tells an operator to use must
be a real one, and the README and the security policy must point to it.
"""
import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "data-inventory.md"


def _text():
    return INVENTORY.read_text(encoding="utf-8")


def _entries(text):
    """The tables the inventory gives an entry: the first cell of a row in one of its tables, or the
    'Other tables' paragraph. A name mentioned in passing elsewhere (the release summary) is not one."""
    named = set()
    for line in text.splitlines():
        if line.startswith("| `"):
            named.update(re.findall(r"`([a-z_]+)`", line.split("|")[1]))
    assert text.count("\n### Other tables\n") == 1
    others = text.split("\n### Other tables\n", 1)[1].split("\n### ", 1)[0]
    named.update(re.findall(r"`([a-z_]+)`", others))
    return named


def test_every_table_the_models_declare_is_in_the_inventory():
    from app.core.models import Base

    tables = sorted(Base.metadata.tables)
    assert len(tables) > 50                     # the whole model, not a partial import
    entries = _entries(_text())
    missing = [t for t in tables if t not in entries]
    assert not missing, ("tables with no entry in docs/data-inventory.md; say what personal data "
                         f"each holds, or list it under 'Other tables': {missing}")


def test_every_setting_the_inventory_names_exists():
    text = _text()
    config = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", text)))
    assert "AUDIT_LOG_RETENTION_DAYS" in names and len(names) >= 8
    unknown = [n for n in names
               if not re.search(rf"^\s*{n.lower()}\s*:", config, re.M)
               and not re.search(rf"^#?\s*{n}=", example, re.M)]
    assert not unknown, f"the inventory names settings that do not exist: {unknown}"


def test_the_readme_and_the_security_policy_point_to_it():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    policy = (ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8")
    assert "](docs/data-inventory.md)" in readme
    assert "](../docs/data-inventory.md)" in policy
    assert (ROOT / "README.md").parent.joinpath("docs/data-inventory.md").is_file()
    assert (ROOT / ".github").joinpath("../docs/data-inventory.md").resolve().is_file()


def test_the_users_row_names_the_columns_added_to_accounts_since_0_33():
    # Columns a release added to `users` are named in its row by their column names, so an operator can
    # find them in the database; each name the row gives is a real column of the table.
    from app.core.models import User

    rows = [line for line in _text().splitlines() if line.startswith("| `users` |")]
    assert len(rows) == 1
    named = re.findall(r"`([a-z_]+)`", rows[0].split("|", 2)[2])
    for column in ("second_factor_reset_at", "permission_defaults_revision", "password_set_by",
                   "password_set_by_other_at", "privacy_seen_version"):
        assert column in named, f"the users row does not name {column}"
    unknown = [n for n in named if n not in User.__table__.c]
    assert not unknown, f"the users row names columns the table does not have: {unknown}"


def _cache_keys():
    """The first cell of every row of the Cache (Redis) table, as one string."""
    text = _text()
    assert text.count("\n## Cache (Redis)\n") == 1
    cache = text.split("\n## Cache (Redis)\n", 1)[1].split("\n## ", 1)[0]
    return " ".join(line.split("|")[1] for line in cache.splitlines() if line.startswith("| `"))


def test_the_cache_table_names_every_key_an_anonymous_link_keeps():
    # Found from the code that writes them: a link's download grant and its wrong-secret counters (a
    # helper that returns the key), and the throttles on opening a link and on downloading through one
    # (the prefix given to the rate limiter). A new one fails here until the table says what it holds.
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    keys = _cache_keys()
    built = re.findall(r'return f"([a-z_]+:[a-z_]+:)\{', source)
    throttles = re.findall(r'prefix="((?:publiclink|notelink|receiver)_[a-z_]+)"', source)
    assert "publiclink:grant:" in built and "notelink:fail:" in built and len(built) >= 4, built
    assert "publiclink_download_ip" in throttles and len(throttles) >= 7, throttles
    missing = [k for k in built if f"`{k}<" not in keys] + [t for t in throttles if f"`{t}:<" not in keys]
    assert not missing, f"keys the links keep in Redis that the Cache table does not name: {missing}"


def test_the_grant_row_says_what_a_grant_holds_and_for_how_long():
    # What the code stores (link id, address, mint time) and for how long (_PUBLINK_GRANT_TTL) is pinned
    # in tests/test_public_link_grant.py; this holds the row to the same three parts and the same time.
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert re.findall(r"^_PUBLINK_GRANT_TTL = (\d+)\b", source, re.M) == ["60"]
    rows = [line for line in _text().splitlines() if line.startswith("| `publiclink:grant:")]
    assert len(rows) == 1
    _, _key, holds, lifetime, _ = rows[0].split("|")
    for part in ("the link's id", "the address that redeemed it", "when it was minted"):
        assert part in holds, part
    assert lifetime.strip().startswith("60 seconds"), lifetime


@pytest.mark.parametrize("row,added", [
    ("| `shares`, `share_claims` |", ["share_claims.preview_count"]),
    ("| `receivers` |", ["message", "token_enc", "token_enc_for"]),
    ("| `public_links` |", ["message"]),
    ("| `note_public_links` |", ["message"]),
    ("| `publiclink_redeem:", ["receiver_page:<address>"]),
])
def test_what_0_35_0_adds_to_a_row_is_marked_as_new_in_it(row, added):
    # One label, the same in every row, so an operator who reads the inventory for an upgrade finds each
    # addition by the same words.
    rows = [line for line in _text().splitlines() if line.startswith(row)]
    assert len(rows) == 1, row
    assert rows[0].count("**New in 0.35.0:**") == 1, rows[0]
    new_part = rows[0].split("**New in 0.35.0:**", 1)[1]
    for name in added:
        assert f"`{name}`" in new_part, f"{row} does not mark {name} as new in 0.35.0"


def test_no_row_says_from_0_35_0_in_other_words():
    assert not [line for line in _text().splitlines() if line.startswith("| ") and "from 0.35.0" in line]


# The columns a row describes in words rather than by name, with the words its first column (what is kept) uses for
# each. A table's primary key is the row itself. A key ending in "_" stands for every column that begins with it.
_IN_WORDS = {
    "users": {
        "username": "Username", "email": "email (optional)", "password_hash": "password hash", "role": "role",
        "is_active": "active and locked state", "is_locked": "active and locked state",
        "locked_until": "active and locked state", "failed_login_attempts": "failed sign-in count",
        "last_login": "last sign-in", "created_at": "creation time and creator",
        "created_by": "creation time and creator", "updated_at": "time of the last change",
        "storage_quota_bytes": "storage quota", "sftp_enabled": "SFTP settings", "sftp_password_auth": "SFTP settings",
    },
    "webauthn_credentials": {
        "user_id": "Each passkey the person registered", "credential_id": "its id as the authenticator made them",
        "public_key_cose": "its public key", "cose_alg": "the signature algorithm", "sign_count": "the sign count",
        "transports": "how it connects", "aaguid": "the authenticator make's identifier",
        "backup_eligible": "whether the key is synced between devices",
        "backup_state": "whether the key is synced between devices",
        "uv_initialized": "whether the person was verified when it was made",
        "label": "the name the person gave it", "created_at": "when it was made and last used",
        "last_used_at": "when it was made and last used", "created_by_session": "a hash of the session that made it",
        "provisional_until": "whether it was made within 14 days after an administrator changed",
        "retired_at": "retired it",
    },
    "sso_providers": {
        "state": "whether it is on", "kind": "its kind", "name": "name, label and icon",
        "label": "name, label and icon", "icon": "name, label and icon",
        "sort_order": "where its button stands on the sign-in page", "show_on_sign_in": "whether it shows there",
        "issuer": "its addresses", "discovery_url": "its addresses",
        "private_network": "whether it may be reached on a private network", "client_id": "client id",
        "client_secret_enc": "its client secret (encrypted", "token_auth": "how the vault proves itself to it",
        "scopes": "the scopes it asks for", "claims": "the claim or attribute names it maps",
        "policy": "its per-provider policy", "saml_": "its SAML settings",
        "saml_idp_certs": "the provider's signing certificates", "created_at": "when it was made and last changed",
        "updated_at": "when it was made and last changed", "created_by": "who made it (the administrator's id",
        "created_by_name": "(the administrator's id and username)",
        "last_test": "the summary of its last test sign-in",
    },
    "external_identities": {
        "user_id": "For each account linked to a provider", "provider_id": "the provider, the issuer",
        "issuer": "the provider, the issuer", "subject": "the provider's identifier for the person",
        "subject_source": "where it came from", "tenant_id": "the tenant",
        "email_at_link": "the email address and display name the provider sent",
        "display_name": "the email address and display name the provider sent",
        "linked_by": "how the link was made", "linked_at": "when, and when the person last signed in",
        "last_sign_in_at": "when the person last signed in through it",
    },
    "sso_sessions": {
        "provider_id": "the provider,", "idp_sid": "the provider's session identifier",
        "idp_sub": "its identifier for the person", "auth_time": "when the provider signed them in",
        "id_token_enc": "the provider's ID token, encrypted",
    },
    "sso_group_mappings": {
        "provider_id": "A provider's group", "provider_group": "group identifier or name",
        "department_id": "a department", "role": "a role",
    },
    "sso_admin_requests": {
        "user_id": "the account", "provider_id": "the provider and group", "provider_group": "the provider and group",
        "requested_at": "when it was asked", "expires_at": "when it expires", "state": "its state",
        "decided_by": "who decided it (the administrator's id", "decided_by_name": "(the administrator's id and username)",
        "decided_at": "(the administrator's id and username) and when",
    },
}


def _row_of(table):
    (row,) = [line for line in _text().splitlines() if re.match(rf"\| `{table}`( \*\*New in [0-9.]+\*\*)? \|", line)]
    return row


def _undescribed(table):
    """The columns of ``table`` in the model that its row neither names nor describes in the words given above."""
    from app.core.models import Base

    kept = _row_of(table).split("|")[2]
    named = set(re.findall(r"`([a-z_]+)`", kept))
    words = _IN_WORDS.get(table, {})
    model = Base.metadata.tables[table]

    def described(column):
        said = words.get(column) or next((w for k, w in words.items() if k.endswith("_") and column.startswith(k)), None)
        return said is not None and said in kept

    keys = {c.name for c in model.primary_key.columns}
    return [c.name for c in model.c if c.name not in keys and c.name not in named and not described(c.name)]


def _new_in_0_36_0():
    return re.findall(r"^\| `([a-z_]+)` \*\*New in 0\.36\.0\*\* \|", _text(), re.M)


def test_every_column_of_users_is_in_its_row():
    # Compared with the model itself, not with a list kept by hand: a column a release adds to `users` fails here
    # until the row names it (or says it in words, as for the columns the row began with).
    missing = _undescribed("users")
    assert not missing, f"the users row says nothing of these columns of the model: {missing}"


def test_every_column_of_each_table_new_in_0_36_0_is_in_its_row():
    # A table the release adds is described by its row as a whole; each of its columns is named there, or said in
    # the words given above, so a column added to it later fails here until the row says what it keeps.
    tables = _new_in_0_36_0()
    assert set(tables) >= {"webauthn_credentials", "sso_providers", "external_identities", "sso_sessions",
                           "sso_group_mappings", "sso_admin_requests"}, tables
    missing = {table: _undescribed(table) for table in tables}
    assert not any(missing.values()), f"these rows say nothing of these columns of the model: {missing}"


def test_the_check_finds_a_column_a_row_leaves_out(monkeypatch):
    # The check itself, on the inventory with one name taken out of a row: that column, and only that one, is found.
    text = _text()
    row = _row_of("external_identities")
    assert row.count("`refused_at`") == 1
    monkeypatch.setattr(sys.modules[__name__], "_text",
                        lambda: text.replace(row, row.replace("`refused_at`", "the date")))
    assert _undescribed("external_identities") == ["refused_at"]


def test_the_words_given_for_a_column_are_for_a_column_there_is():
    from app.core.models import Base

    for table, words in _IN_WORDS.items():
        columns = [c.name for c in Base.metadata.tables[table].c]
        gone = [k for k in words if not (k in columns or (k.endswith("_") and any(c.startswith(k) for c in columns)))]
        assert not gone, f"{table}: a column described in words is gone: {gone}"
        kept = _row_of(table).split("|")[2]
        unsaid = [k for k, said in words.items() if said not in kept]
        assert not unsaid, f"{table}: the row no longer says these in the words given: {unsaid}"


def test_what_0_36_0_adds_to_the_users_row_is_marked_as_new_in_it():
    (row,) = [line for line in _text().splitlines() if line.startswith("| `users` |")]
    assert row.count("**New in 0.36.0:**") == 1
    new_part = row.split("**New in 0.36.0:**", 1)[1].split("|", 1)[0]
    for name in ("email_confirmed_at", "email_confirmed_for", "passkey_required_since",
                 "passkey_requirement_cleared_at", "sso_only", "password_nobody_knows", "sessions_ended"):
        assert f"`{name}`" in new_part, f"the users row does not mark {name} as new in 0.36.0"
    # And the release's own list names each of them too.
    release = _text().split("\n## What 0.36.0 added\n", 1)[1].split("\n## ", 1)[0]
    for name in ("email_confirmed_at", "email_confirmed_for", "passkey_required_since",
                 "passkey_requirement_cleared_at", "sso_only", "password_nobody_knows", "sessions_ended"):
        assert f"`users.{name}`" in release, name


def _release_headings(text):
    return re.findall(r"^## What (\d+\.\d+\.\d+) added$", text, re.M)


def test_the_opening_names_the_release_the_inventory_ends_with():
    # The opening says which version the inventory describes and which releases its marks run over; both end at the
    # release whose list closes the file, so a release that adds its list and forgets the opening fails here.
    text = _text()
    releases = _release_headings(text)
    assert releases and releases[0] == "0.33.0", releases
    described = re.findall(r"It describes\s+version (\d+\.\d+\.\d+)\.", text)
    assert described == [releases[-1]], (described, releases[-1])
    marked_range = re.findall(r"\*\*New in\*\* a release\s+\((\d+\.\d+\.\d+) to (\d+\.\d+\.\d+)\)", text)
    assert marked_range == [(releases[0], releases[-1])], marked_range
    # Each release an entry is marked with has its own list at the end.
    marked = set(re.findall(r"\b(?:new|changed) in (\d+\.\d+\.\d+)\b", text, re.I))
    assert marked and not marked - set(releases), sorted(marked - set(releases))


def test_each_release_list_is_headed_in_the_same_words():
    # "What <release> added", in the past, for every release: an operator looks one up by the same words.
    assert not re.findall(r"^## What [0-9.]+ adds$", _text(), re.M)
    assert len(_release_headings(_text())) >= 7


# The emails 0.35.2 could send, by their keys in the catalog: a key the catalog has beyond these is one 0.36.0 added.
_EMAILS_IN_0_35_2 = frozenset({
    "email_change", "password_reset", "account_invite", "account_welcome", "login_alert", "share_created",
    "receiver_upload_received", "expiry_reminder", "vault_member_added", "temp_credential_issued",
    "account_changed_by_admin", "administrator_added", "ssh_keys_adder_left", "auditor_right",
    "compliance_access_notice", "vault_access_notice", "retention_change", "recorded_values_removal",
    "encryption_key_release_code", "encryption_key_notice",
})


def _email_rows():
    """The first cell of each row of the Email table, by the row."""
    text = _text()
    assert text.count("\n## Email\n") == 1
    section = text.split("\n## Email\n", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| ") and not line.startswith("| Email |")]
    return [line.split("|")[1].strip() for line in rows if not set(line) <= set("|- ")]


def test_each_email_0_36_0_added_has_its_row_marked_new_in_it():
    # Read from the catalog itself, so an email a later change adds to the release fails here until the table says
    # whom it goes to and what it holds.
    from app.core.email_actions import ACTION_CATALOG

    added = [a for a in ACTION_CATALOG if a["key"] not in _EMAILS_IN_0_35_2]
    assert {a["key"] for a in added} >= {"email_confirm", "sign_in_method_changed", "sso_freshness_warning"}, added
    firsts = _email_rows()
    unmarked = [a["name"] for a in added if f"{a['name']} **New in 0.36.0**" not in firsts]
    assert not unmarked, f"emails 0.36.0 added with no row marked New in 0.36.0 in the Email table: {unmarked}"
    # And the release's own list names each of them too.
    release = _text().split("\n## What 0.36.0 added\n", 1)[1].split("\n## ", 1)[0]
    unlisted = [a["name"] for a in added if f'"{a["name"]}"' not in release]
    assert not unlisted, f"emails 0.36.0 added that its list at the end does not name: {unlisted}"


def test_the_rows_0_36_0_widened_say_so():
    rows = _text().split("\n## Email\n", 1)[1].split("\n## ", 1)[0].splitlines()
    (changed,) = [line for line in rows if line.startswith("| Account changed by an administrator ")]
    assert changed.count("**New in 0.36.0:**") == 1 and "passkey" in changed.split("**New in 0.36.0:**")[1]
    (notices,) = [line for line in _text().splitlines() if line.startswith("| `notifications` |")]
    assert notices.count("**New in 0.36.0:**") == 1 and "single sign-on" in notices.split("**New in 0.36.0:**")[1]


def test_the_providers_row_says_whom_the_last_test_can_name_and_what_an_erase_does_there():
    # The summary of a test sign-in names who ran it, and its "would" line can name the account a sign-in of the
    # tested identity would link or create: an erase replaces such a username with its placeholder, as elsewhere, and
    # leaves the rest of the summary.
    row = _row_of("sso_providers")
    assert "own account only" not in row
    assert "which can name the account a sign-in of the tested identity would link or create" in row
    assert "replaced by the erase's placeholder" in row and "when the tester is erased" not in row
