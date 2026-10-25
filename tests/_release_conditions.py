"""The detect queries of the upgrade matrix's conditions on the 0.33.2 -> 0.34.0 edge that come with how long
records are kept, the audit log's archive and the working records, and with the hold on a zero-knowledge key's
envelope. The release commit copies each, with the condition's text, into docs/upgrade-matrix.json; until then they
live here, so the tests can run every one against a database. A text kept here (SUMMARY) is checked against the
code it describes (tests/test_release_conditions.py).

A query finds rows only where its condition applies: an aggregate is given HAVING, so an install it does not
concern gets no row. A condition that blocks a rollback is checked on the upgraded database (0.34.0's tables); the
others on the database being upgraded, so they read only tables and columns 0.33.2 already has.
"""

DETECT = {
    # What archiving moves when it starts, with the default windows: it starts AUDIT_ARCHIVE_START_AFTER_DAYS (14)
    # after the upgrade and moves each UTC day before the day AUDIT_HOT_DAYS (90) ago, so the rows of the days before
    # the day 76 days ago now (app/core/audit_archive.py takes days before the date of now less the hot days).
    "audit-history-compressed-after-90-days": (
        "SELECT count(*) AS rows_to_archive, min(timestamp) AS oldest FROM audit_logs "
        "WHERE timestamp < date_trunc('day', (now() AT TIME ZONE 'utc') - interval '76 days') HAVING count(*) > 0"),
    "audit-retention-runs-on-a-timer": (
        "SELECT count(*) AS audit_rows, min(timestamp) AS oldest FROM audit_logs HAVING count(*) > 0"),
    "alert-names-and-addresses-cleared-after-30-days": (
        "SELECT count(*) AS alerts FROM security_alerts "
        "WHERE timestamp < (now() AT TIME ZONE 'utc') - interval '30 days' "
        "AND (username IS NOT NULL OR ip_address IS NOT NULL) HAVING count(*) > 0"),
    "ended-invitations-and-codes-deleted-after-30-days": (
        "SELECT * FROM (SELECT "
        "(SELECT count(*) FROM account_invitations WHERE accepted_at < (now() AT TIME ZONE 'utc') - interval '30 days' "
        "OR revoked_at < (now() AT TIME ZONE 'utc') - interval '30 days' "
        "OR expires_at < (now() AT TIME ZONE 'utc') - interval '30 days') AS invitations, "
        "(SELECT count(*) FROM password_reset_tokens WHERE consumed_at < (now() AT TIME ZONE 'utc') - interval '30 days' "
        "OR expires_at < (now() AT TIME ZONE 'utc') - interval '30 days') AS reset_links, "
        "(SELECT count(*) FROM otp_codes WHERE consumed_at < (now() AT TIME ZONE 'utc') - interval '30 days' "
        "OR expires_at < (now() AT TIME ZONE 'utc') - interval '30 days') AS codes, "
        "(SELECT count(*) FROM email_change_codes WHERE consumed_at < (now() AT TIME ZONE 'utc') - interval '30 days' "
        "OR expires_at < (now() AT TIME ZONE 'utc') - interval '30 days') AS email_codes) t "
        "WHERE invitations + reset_links + codes + email_codes > 0"),
    "archived-audit-history-hidden": (
        "SELECT count(DISTINCT day) AS days, sum(row_count) AS rows, min(day) AS first_day, max(day) AS last_day "
        "FROM audit_archive_blocks HAVING count(*) > 0"),
    # A value cleared in the panel is stored as JSON null, not as SQL NULL.
    "panel-retention-not-read": (
        "SELECT key, value FROM managed_settings WHERE value IS NOT NULL AND value::text <> 'null' ORDER BY key"),
    # The accounts with an encryption key whose sign-in details were changed in the 14 days before the upgrade: the
    # hold covers them at once (app/core/envelope_hold.py). Of each, the earliest of those changes decides where the
    # code goes; only an email change recorded before 0.34.0 kept the address it replaced, so for any other the
    # server's operator alone can release the account.
    "zk-envelope-held-after-admin-reset": (
        "SELECT count(*) AS held_accounts, count(*) FILTER (WHERE kind <> 'email') AS released_only_by_the_host "
        "FROM (SELECT DISTINCT ON (c.target_user_id) c.target_user_id, c.kind FROM credential_changes c "
        "JOIN user_keypairs k ON k.user_id = c.target_user_id WHERE c.status IN ('made', 'approved') "
        "AND c.applied_at > (now() AT TIME ZONE 'utc') - interval '14 days' "
        "ORDER BY c.target_user_id, c.applied_at) t HAVING count(*) > 0"),
}

# The texts of the conditions whose text is written already, for the release commit to copy with the query.
SUMMARY = {
    "zk-envelope-held-after-admin-reset": (
        "From 0.34.0, for ZK_ENVELOPE_HOLD_DAYS days (14 by default) after an administrator or the server's "
        "operator changed an account's sign-in details, the account's zero-knowledge encryption key is given to a "
        "browser only after it enters a code sent by email to the address the account had before the first of "
        "those changes. Changes made before the upgrade count: an account with an encryption key whose sign-in "
        "details were changed in the 14 days before the upgrade is held from the first start (opening the key "
        "answers 403 zk-envelope-hold). Only an email change recorded before 0.34.0 kept the address it replaced, "
        "so for an account whose first such change was of another kind, or on a deployment without mail, no code "
        "can be sent (409 zk-envelope-hold-no-mail): the server's operator releases it with python dockvault.py "
        "accounts --action release-key-hold, or the hold ends ZK_ENVELOPE_HOLD_DAYS days after the last change. The "
        "check below counts the accounts held and those only the server's operator can release. "
        "ZK_ENVELOPE_HOLD_DAYS=0 in .env before the upgrade turns the hold off. Going back to an earlier release "
        "lifts the hold."),
}

# The one whose rows stop the upgraded deployment going back across the edge.
BLOCKS_ROLLBACK = {"archived-audit-history-hidden"}
# Checked on the upgraded database: a rollback's conditions.
ON_UPGRADED = {"archived-audit-history-hidden", "panel-retention-not-read"}
# Conditions of the same work that have no query: what they say cannot be read from the database.
WITHOUT_DETECT = ("audit-protected-minimum-365-days", "container-output-rotates")
# The tables each query reads.
TABLES = {
    "audit-history-compressed-after-90-days": {"audit_logs"},
    "audit-retention-runs-on-a-timer": {"audit_logs"},
    "alert-names-and-addresses-cleared-after-30-days": {"security_alerts"},
    "ended-invitations-and-codes-deleted-after-30-days": {"account_invitations", "password_reset_tokens", "otp_codes",
                                                          "email_change_codes"},
    "archived-audit-history-hidden": {"audit_archive_blocks"},
    "panel-retention-not-read": {"managed_settings"},
    "zk-envelope-held-after-admin-reset": {"credential_changes", "user_keypairs"},
}
# The tables and columns 0.33.2 has that the queries on the database being upgraded read (from its models).
OLDER_SCHEMA = {
    "audit_logs": {"timestamp"},
    "security_alerts": {"timestamp", "username", "ip_address"},
    "account_invitations": {"accepted_at", "revoked_at", "expires_at"},
    "password_reset_tokens": {"consumed_at", "expires_at"},
    "otp_codes": {"consumed_at", "expires_at"},
    "email_change_codes": {"consumed_at", "expires_at"},
    "credential_changes": {"target_user_id", "kind", "status", "applied_at"},
    "user_keypairs": {"user_id"},
}
