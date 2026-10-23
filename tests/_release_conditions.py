"""The detect queries of the upgrade matrix's conditions on the 0.33.2 -> 0.34.0 edge that come with how long
records are kept, the audit log's archive and the working records. The release commit copies each, with the
condition's text, into docs/upgrade-matrix.json; until then they live here, so the tests can run every one
against a database.

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
}
# The tables and columns 0.33.2 has that the queries on the database being upgraded read (from its models).
OLDER_SCHEMA = {
    "audit_logs": {"timestamp"},
    "security_alerts": {"timestamp", "username", "ip_address"},
    "account_invitations": {"accepted_at", "revoked_at", "expires_at"},
    "password_reset_tokens": {"consumed_at", "expires_at"},
    "otp_codes": {"consumed_at", "expires_at"},
    "email_change_codes": {"consumed_at", "expires_at"},
}
