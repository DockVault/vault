"""The upgrade matrix's conditions of 0.36.0: their ids in the order the edge lists them (CONDITIONS), the edge they
go on (SOURCE -> INTO, with its kind and flags), their detect queries (DETECT), their texts (SUMMARY) and what each
query reads (READS). The release commit writes them on the edge 0.35.2 -> 0.36.0 of docs/upgrade-matrix.json; until
then they live here, so the tests can check each query against the models and against the code it describes, and
check the release commit's matrix against this file (tests/test_release_conditions_0_36.py).

The conditions about going back are checked on the upgraded database, with 0.36.0's tables (ON_UPGRADED). Those
about coming back to 0.36 are checked on the database being upgraded, a 0.35.2 one, so their queries read only what
0.35.2 has, or the system catalog. None blocks a rollback: 0.36.0 records no data an earlier release refuses to
start on (app/core/data_requirements.py is 0.35.2's), so the edge is reversible.
"""
import copy
import datetime

INTO = "0.36.0"
SOURCE = "0.35.2"
# The edge's own fields: a direct step that can be taken back, with no backup asked for, since the schema change is
# new tables and nullable or defaulted columns, added at the first start, and 0.35.2 ignores what they hold.
EDGE = {"from": SOURCE, "to": INTO, "kind": "direct", "reversible": True, "requires_backup": False}

DETECT = {
    # An account held to its provider's sign-in (users.sso_only, app/core/sso_only.py), and whether a person may
    # ask for a reset link: the account policy's password_reset_enabled, in the 'global' row of system_settings
    # (app/core/account_policy.py), off when unset.
    "provider-only-accounts": (
        "SELECT * FROM (SELECT (SELECT count(*) FROM users WHERE sso_only) AS provider_only, COALESCE((SELECT "
        "value->>'password_reset_enabled' FROM system_settings WHERE key = 'global'), 'false') AS "
        "self_service_reset) t WHERE provider_only > 0"),
    # The mark of a password nobody can type is the SHA-256 hex digest of the stored hash as text, so it counts only
    # while that hash is unchanged (app/core/password_origin.py, mark_nobody_knows). The accounts held to their
    # provider are the condition above.
    "passwords-nobody-knows": (
        "SELECT count(*) FROM users WHERE NOT COALESCE(sso_only, false) AND password_nobody_knows = "
        "encode(sha256(convert_to(password_hash, 'UTF8')), 'hex')"),
    # Accounts without an active authenticator app that have a passkey not retired, or an identity on a provider
    # that is on and whose second factor counts (sso_trust_idp_mfa, off by default, app/core/sso_policy.py).
    "second-factors-an-earlier-release-does-not-know": (
        "SELECT count(*) FROM users u WHERE NOT EXISTS (SELECT 1 FROM second_factor_enrollments s WHERE s.user_id = "
        "u.id AND s.status = 'active') AND (EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id AND "
        "w.retired_at IS NULL) OR EXISTS (SELECT 1 FROM external_identities e JOIN sso_providers p ON p.id = "
        "e.provider_id WHERE e.user_id = u.id AND p.state = 'enabled' AND p.policy->>'sso_trust_idp_mfa' = 'true'))"),
    # A refusal still in force (app/services/sso_freshness.py, refusal_in_force), or days that have run out: from
    # the last sign-in through the provider, else from the link, the provider's sso_freshness_days (30 by default,
    # 0 is off) later (deadline_of, lapsed). The days count while a provider is off too, so every provider is read.
    "people-a-provider-no-longer-admits": (
        "SELECT count(*) FROM external_identities e JOIN sso_providers p ON p.id = e.provider_id WHERE "
        "(e.refused_at IS NOT NULL AND (e.last_sign_in_at IS NULL OR e.refused_at >= e.last_sign_in_at)) OR "
        "(COALESCE((p.policy->>'sso_freshness_days')::int, 30) > 0 AND COALESCE(e.last_sign_in_at, e.linked_at) + "
        "make_interval(days => COALESCE((p.policy->>'sso_freshness_days')::int, 30)) <= (now() AT TIME ZONE 'utc'))"),
    # The passkey mode and the roles that must hold one, which only the settings store (managed_settings, a json
    # column) holds: neither has a deployment value (app/core/webauthn_settings.py).
    "role-must-hold-a-passkey": (
        "SELECT 1 FROM managed_settings m WHERE m.key = 'webauthn_mode' AND m.value #>> '{}' = 'required_for_roles' "
        "AND EXISTS (SELECT 1 FROM managed_settings r WHERE r.key = 'webauthn_required_roles' AND CASE WHEN "
        "json_typeof(r.value) = 'array' THEN json_array_length(r.value) ELSE 0 END > 0)"),
    # A confirmation of an address waiting for another administrator: a held credential change of the email kind
    # whose payload carries confirm, which 0.35.2 applies as a change of address to the address it names.
    "held-address-confirmations": (
        "SELECT count(*) FROM credential_changes WHERE status = 'held' AND payload->>'confirm' = 'true'"),
    # A database that was on 0.36 keeps the tables it made there.
    "back-on-0-36-after-an-earlier-release": (
        "SELECT 1 FROM pg_class WHERE relname IN ('webauthn_credentials', 'external_identities') AND relkind = 'r' "
        "LIMIT 1"),
    # The audit rows the start of 0.36.0 writes for each privileged account it gives its password sign-in back.
    "privileged-accounts-keep-a-password": (
        "SELECT timestamp, resource_id FROM audit_logs WHERE action = 'sso_password_sign_in_restored'"),
}

# The text of every condition, for the release commit to copy with the query.
SUMMARY = {
    "passkeys-on-by-default": (
        "From 0.36.0 passkeys are on as an option (Settings, Sign-in methods): anyone may add one under Your "
        "account, and for the roles user and external a passkey that verifies the person signs in by itself; an "
        "administrator always types the password too. A passkey works only at the address it was made at, the first "
        "ALLOWED_HOSTS entry, which must be an https host name; otherwise passkeys stay hidden, and dockvault.py "
        "status says why. Single sign-on stays off until an administrator adds a provider. A sign-in waiting for "
        "its second step during the upgrade starts again."),
    "provider-only-accounts": (
        "Going back: an earlier release holds no account to its provider. An account that signs in only through one "
        "(the first column) can then sign in with any password it is given: a reset link it asks for where "
        "self-service reset is on (the second column), a person the provider no longer admits included, or an "
        "administrator's link or password. First disable the accounts of people who left, or turn self-service "
        "reset off, and sign these accounts out: an earlier release renews their sessions without asking the "
        "provider."),
    "passwords-nobody-knows": (
        "Going back: an account whose password nobody knows, such as one made through a provider or given password "
        "sign-in back, needs a reset link on an earlier release before a password works."),
    "second-factors-an-earlier-release-does-not-know": (
        "Going back: an earlier release counts neither a passkey nor a provider's trusted second factor. An account "
        "without an authenticator app then signs in with its password alone, and where a second factor is required, "
        "whoever knows the password sets one up: have each add an authenticator app first."),
    "people-a-provider-no-longer-admits": (
        "Going back: an earlier release does not hold back people a provider refused, or whose days without a "
        "sign-in there have run out: their password, SSH keys, temporary credentials and devices work again, and "
        "their sessions are renewed without asking the provider. Disable those accounts first."),
    "role-must-hold-a-passkey": (
        "Going back: an earlier release does not ask for the passkey a role must hold."),
    "held-address-confirmations": (
        "Going back: first deny or withdraw the held confirmations of an address. An earlier release applies one as "
        "a change of address, writing the address it names over the one the account holds by then."),
    "back-on-0-36-after-an-earlier-release": (
        "Coming back to 0.36 after a time on an earlier release: passkeys and provider links made before are back "
        "as they were. A second-factor reset made there by another administrator or the server's operator retires, "
        "at the first start, the passkeys made before it, for at least 14 days after the reset; an older reset only "
        "while the account has not answered it, and only where the account had an authenticator app. Nothing else "
        "done there (a password reset, a sign-out everywhere, a factor an account turned off itself) ended a link "
        "or a passkey: for each account acted on there for a security reason, remove its passkeys and unlink its "
        "identities. The days there count: linked people who did not sign in through their provider within its "
        "window may be held to it until they do, and a role's time to set a passkey up may have run out."),
    "privileged-accounts-keep-a-password": (
        "Coming back to 0.36: an account that signs in only through a provider and was made an administrator, or "
        "given the auditor right, on the earlier release gets its password sign-in back at the first start. It "
        "keeps the password it has, it and the administrators are told, and where it has none it sets one with a "
        "reset link. Nothing to do."),
}

# Every condition of 0.36.0, in the order the release commit writes them on the edge.
CONDITIONS = (
    "passkeys-on-by-default",
    "provider-only-accounts",
    "passwords-nobody-knows",
    "second-factors-an-earlier-release-does-not-know",
    "people-a-provider-no-longer-admits",
    "role-must-hold-a-passkey",
    "held-address-confirmations",
    "back-on-0-36-after-an-earlier-release",
    "privileged-accounts-keep-a-password",
)
# Conditions that have no query: what they say cannot be read from the database.
WITHOUT_DETECT = ("passkeys-on-by-default",)
# Checked on the upgraded database: going back.
ON_UPGRADED = {"provider-only-accounts", "passwords-nobody-knows", "second-factors-an-earlier-release-does-not-know",
               "people-a-provider-no-longer-admits", "role-must-hold-a-passkey", "held-address-confirmations"}
# The system catalog's tables and columns a query may read on any database.
CATALOG = {"pg_class": {"relname", "relkind"}}
# The tables each query reads, and the columns of each it names.
READS = {
    "provider-only-accounts": {"users": {"sso_only"}, "system_settings": {"key", "value"}},
    "passwords-nobody-knows": {"users": {"sso_only", "password_nobody_knows", "password_hash"}},
    "second-factors-an-earlier-release-does-not-know": {
        "users": {"id"}, "second_factor_enrollments": {"user_id", "status"},
        "webauthn_credentials": {"user_id", "retired_at"}, "external_identities": {"user_id", "provider_id"},
        "sso_providers": {"id", "state", "policy"}},
    "people-a-provider-no-longer-admits": {
        "external_identities": {"provider_id", "refused_at", "last_sign_in_at", "linked_at"},
        "sso_providers": {"id", "policy"}},
    "role-must-hold-a-passkey": {"managed_settings": {"key", "value"}},
    "held-address-confirmations": {"credential_changes": {"status", "payload"}},
    "back-on-0-36-after-an-earlier-release": {"pg_class": {"relname", "relkind"}},
    "privileged-accounts-keep-a-password": {"audit_logs": {"timestamp", "resource_id", "action"}},
}


def _version_key(version: str) -> tuple:
    return tuple(int(part) for part in version.split("."))


def condition(cid: str) -> dict:
    """The condition ``cid`` as the release commit writes it on the edge: the text kept here and the query."""
    out = {"id": cid, "summary": SUMMARY[cid]}
    if cid in DETECT:
        out["detect"] = DETECT[cid]
    return out


def edge() -> dict:
    """The edge into INTO as the release commit writes it."""
    return dict(EDGE, conditions=[condition(cid) for cid in CONDITIONS])


def edge_problems(matrix: dict) -> list:
    """What the edges into INTO of an upgrade matrix (docs/upgrade-matrix.json, as loaded) lack, as a list of
    sentences; empty when the matrix does not declare INTO, or when the one edge into it is EDGE carrying exactly
    CONDITIONS, in that order, as kept here."""
    if INTO not in matrix.get("versions", {}):
        return []
    edges = [e for e in matrix.get("edges", []) if e.get("to") == INTO]
    if [e.get("from") for e in edges] != [SOURCE]:
        return [f"the edges into {INTO} leave from {[e.get('from') for e in edges]}, not from {SOURCE} alone"]
    (found,) = edges
    where = f"the edge {SOURCE} -> {INTO}"
    problems = [f"{where} has {key} {found.get(key)!r}, not {value!r}"
                for key, value in EDGE.items() if found.get(key) != value]
    have = [c.get("id") for c in found.get("conditions", [])]
    if have != list(CONDITIONS):
        problems.append(f"{where} lists the conditions {have}, not {list(CONDITIONS)}")
    for kept in found.get("conditions", []):
        cid = kept.get("id")
        if cid not in SUMMARY:
            continue
        if kept != condition(cid):
            problems.append(f"{where} gives {cid} another text, query or flag than the one kept here")
    return problems


def before_the_release(matrix: dict) -> dict:
    """A copy of ``matrix`` without INTO: every release from INTO on, every edge to or from one, and every line from
    INTO's on taken out. The same matrix whether or not ``matrix`` already declares INTO, apart from the other lines'
    dates, which with_the_release sets."""
    out = copy.deepcopy(matrix)
    floor = _version_key(INTO)
    out["versions"] = {v: entry for v, entry in out["versions"].items() if _version_key(v) < floor}
    out["edges"] = [e for e in out["edges"] if _version_key(e["from"]) < floor and _version_key(e["to"]) < floor]
    out["lines"] = {line: dict(entry) for line, entry in out.get("lines", {}).items()
                    if _version_key(line + ".0") < floor}
    return out


def with_the_release(matrix: dict) -> dict:
    """``matrix`` as the release commit makes it from this file: the releases below INTO, then INTO declared, no
    earlier than any release below it, secure and not end-of-life, with every earlier line ending 30 days after it
    and its own line the newest, and the one edge into it from SOURCE with every condition."""
    data = before_the_release(matrix)
    released = max(entry["released"] for entry in data["versions"].values())
    data["versions"][INTO] = {"released": released, "notes": "The release.", "support": {"eol": False,
                                                                                       "secure": True}}
    ends = (datetime.date.fromisoformat(released) + datetime.timedelta(days=30)).isoformat()
    data["lines"] = {**{line: {"security_fixes_until": ends} for line in data["lines"]},
                     ".".join(INTO.split(".")[:2]): {"security_fixes_until": None}}
    data["edges"].append(edge())
    return data
