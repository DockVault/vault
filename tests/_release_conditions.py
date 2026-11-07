"""The upgrade matrix's conditions of 0.34.0: their ids (CONDITIONS), the edges they go on (INTO, SOURCE_FLOOR),
their detect queries (DETECT) and their texts (SUMMARY). The release commit copies each, with the
condition's text, onto every edge into 0.34.0 in docs/upgrade-matrix.json; until then they live here, so the tests
can run every query against a database, check each text kept here against the code it describes, and check the
release commit's matrix against this file (tests/test_release_conditions.py).

A query finds rows only where its condition applies: an aggregate is given HAVING, so an install it does not
concern gets no row. A condition that blocks a rollback is checked on the upgraded database (0.34.0's tables); the
others on the database being upgraded, so they read only tables and columns 0.33.2 already has (every edge into
0.34.0 leaves from 0.33.6 or later, whose tables have them all).

The tests build the matrix the release commit makes (with_the_release) from the releases before 0.34.0
(before_the_release), so they give the same answers before that commit and after it, when docs/upgrade-matrix.json
declares 0.34.0 itself.
"""
import copy

# The edges every condition below goes on: each edge into INTO. None of them leaves from a release below
# SOURCE_FLOOR, the only release of the line before that no advisory affects: such an edge would let an upgrade skip
# it, and a rollback across it go back to a release with a known vulnerability. An edge marked blocked, which nobody
# takes, carries none of this. An edge that skips INTO (0.33.6 -> 0.34.1, say) carries every condition of the route it
# replaces, which the matrix's own check requires (.github/scripts/upgrade_matrix.py).
INTO = "0.34.0"
SOURCE_FLOOR = "0.33.6"

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
    # code goes (envelope_hold.code_destination): only an email change recorded before 0.34.0 kept the address it
    # replaced (credential_changes.address_before), so for any other, and for an email change of an account that had
    # no address then, the server's operator alone can release the account. An account changed then that has no key
    # yet is not counted, though the hold reads no key and covers it once it sets one up: the text says so.
    "zk-envelope-held-after-admin-reset": (
        "SELECT count(*) AS held_accounts, count(*) FILTER (WHERE kind <> 'email' "
        "OR coalesce(btrim(previous_email), '') = '') AS released_only_by_the_host "
        "FROM (SELECT DISTINCT ON (c.target_user_id) c.target_user_id, c.kind, "
        "c.payload->>'previous_email' AS previous_email FROM credential_changes c "
        "JOIN user_keypairs k ON k.user_id = c.target_user_id WHERE c.status IN ('made', 'approved') "
        "AND c.applied_at > (now() AT TIME ZONE 'utc') - interval '14 days' "
        "ORDER BY c.target_user_id, c.applied_at) t HAVING count(*) > 0"),
    # While the newest recording levels record less than Full of a kind earlier releases recorded in full: the
    # query of the data marker that keeps those releases from starting (app/core/recording_marker.py, STRICTER_SQL).
    "recording-levels-changed": (
        "SELECT 1 FROM audit_privacy_policies WHERE version = (SELECT max(version) FROM audit_privacy_policies) "
        "AND (signin_names <> 'full' OR emails <> 'full' OR ip <> 'full' OR user_agent <> 'full')"),
    # While a legal hold stands or what one kept waits for its purge (app/core/legal_hold_marker.py, DETECT_SQL).
    "legal-holds-block-rollback": (
        "SELECT 1 FROM legal_hold_vaults WHERE released_at IS NULL "
        "UNION ALL SELECT 1 FROM held_files UNION ALL SELECT 1 FROM held_folders "
        "UNION ALL SELECT 1 FROM held_name_history LIMIT 1"),
    # While a compliance case is open or the records of compliance access must be kept: the marker itself, which
    # alone knows COMPLIANCE_RECORD_MIN_DAYS (app/core/compliance_marker.py, CONDITION).
    "compliance-records-block-rollback": (
        "SELECT key, requires_at_least, since FROM data_requirements WHERE key = 'compliance-records'"),
    # The records of what an earlier release cannot read or would destroy, each of which it refuses to start on
    # (app/core/data_requirements.py).
    "older-images-refuse-newer-data": (
        "SELECT key, requires_at_least, reason, since FROM data_requirements ORDER BY key"),
}

# The text of every condition, for the release commit to copy with the query.
SUMMARY = {
    "audit-history-compressed-after-90-days": (
        "From 0.34.0 the audit log is still kept for ever by default, but each UTC day older than 90 days "
        "(AUDIT_HOT_DAYS, 31 to 3650, or Settings, Activity and records) is moved from audit_logs into compressed "
        "daily blocks (audit_archive_blocks), each checked against the log's integrity chain before its rows are "
        "removed; nothing is deleted. Archiving starts 14 days after 0.34.0 first starts "
        "(AUDIT_ARCHIVE_START_AFTER_DAYS, 0 to 90), and again 14 days after it starts once more following more than "
        "12 hours on an earlier release that wrote to the audit log, or more than 3 days on one or stopped, so going "
        "back to an earlier release within that time needs nothing. The Activity page and its exports read archived "
        "days; a tool that reads audit_logs directly sees only the newer days. python dockvault.py audit unarchive "
        "puts days back as rows once they fit. The check counts the rows archiving will move when it starts, with "
        "the default windows: those of the days before the day 76 days ago."),
    "audit-retention-runs-on-a-timer": (
        "Before 0.34.0 a positive AUDIT_LOG_RETENTION_DAYS deleted old audit rows only when an administrator opened "
        "the activity dashboard, so rows older than it can be in the database now. From 0.34.0 the pruner deletes "
        "them on a timer. On an install that already has a positive value nothing is deleted at the upgrade: the "
        "value first waits RETENTION_REDUCTION_DELAY_DAYS (7 by default) as a change that deletes sooner, every "
        "administrator is told, and any administrator can cancel it in Settings, Activity and records. "
        "Administration and security rows are kept at least 365 days whatever the value "
        "(AUDIT_PROTECTED_MIN_DAYS). python dockvault.py audit retention shows the values in force. The check shows "
        "the number of audit rows and the oldest."),
    "audit-protected-minimum-365-days": (
        "From 0.34.0 administration and security audit rows (what administrators did, and the security events) are "
        "kept at least AUDIT_PROTECTED_MIN_DAYS (365 by default) whatever the maximum days, and the size cap never "
        "deletes them; only .env lowers the minimum. A deployment whose AUDIT_LOG_RETENTION_DAYS is below 365 keeps "
        "these rows longer than before; one that must delete them sooner sets AUDIT_PROTECTED_MIN_DAYS before the "
        "upgrade. The server refuses to start when AUDIT_PROTECTED_MIN_DAYS or AUDIT_MIN_RETENTION_DAYS is longer "
        "than PLAN_LOG_MAX_DAYS, or AUDIT_LOG_RETENTION_DAYS is shorter than AUDIT_MIN_RETENTION_DAYS."),
    "container-output-rotates": (
        "From 0.34.0 the shipped compose files rotate each container's output (docker logs): Docker's json-file "
        "driver keeps at most DOCKER_LOG_MAX_FILE files (5 by default) of DOCKER_LOG_MAX_SIZE (10m by default) per "
        "container. Only installs whose compose files come from 0.34.0 get it: set up from it, or updated after "
        "updating the checkout (git pull, or git fetch --tags and git checkout v0.34.0). An install that updates by "
        "pulling images keeps its old compose files, which never rotate: update the checkout, or add the logging "
        "block to each service by hand. A Docker host whose default log driver is journald or syslog refuses these "
        "options: remove the block there (README, Container logs)."),
    "storage-volume-keeps-free-space": (
        "From 0.34.0 the storage volume keeps free space: an upload, an SFTP write or a copy that would leave less "
        "is refused (507). MIN_FREE_SPACE_GB sets it in GB; unset, it is the larger of 2 GB and 5% of the volume, "
        "never more than half of it nor more than 20 GB; 0 turns it off. A volume that already has less free refuses "
        "them all from the first start: free some space, grow the volume or lower MIN_FREE_SPACE_GB in .env first. "
        "python dockvault.py update checks the volume before the upgrade only when the tool itself is 0.34.0 or later "
        "(update the checkout first: git pull, or git fetch --tags and git checkout v0.34.0; an older tool does not "
        "check). To check by hand: docker exec vault df -h /app/storage (the container is vault-api in the split "
        "layout and the local trial) shows the volume's Size and Available, and Available must be more than the floor "
        "its Size gives."),
    "alert-names-and-addresses-cleared-after-30-days": (
        "From 0.34.0 each failed sign-in is kept in full in the security record for SECURITY_RECORD_DAYS (30 by "
        "default, 7 to 365), and security alerts lose the name and the address that raised them after the same "
        "time, resolved or not; their messages no longer spell them out. The first pass after the upgrade clears "
        "every older alert. Resolved alerts are deleted after SECURITY_ALERT_RETENTION_DAYS (90 by default) on a "
        "timer, where earlier releases deleted them only when the alerts were read. The check counts the alerts "
        "whose name or address will be cleared."),
    "ended-invitations-and-codes-deleted-after-30-days": (
        "From 0.34.0 invitations are deleted 30 days after they are accepted, revoked or expire, and used or expired "
        "password reset links, one-time codes and email-change codes 30 days after they end; earlier releases kept "
        "them. The first pass after the upgrade deletes every older one, so the list of invitations shows only the "
        "ended ones of the last 30 days. The lineage an administrator's accepted invitation gave is kept apart, and "
        "the audit log keeps every event. Notifications stay until the person dismisses them unless "
        "NOTIFICATION_RETENTION_DAYS (or Settings, Activity and records) gives them a window. The check counts what "
        "the first pass deletes."),
    "panel-retention-not-read": (
        "Going back to 0.33.x: the values administrators set in Settings, Activity and records are not read, and "
        "the changes waiting do not run. Retention falls back to AUDIT_LOG_RETENTION_DAYS, applied again only when "
        "the activity dashboard is opened, and resolved alerts are deleted only when they are read. Set "
        "AUDIT_LOG_RETENTION_DAYS=0 before going back: the older release would otherwise delete old audit rows the "
        "integrity chain has sealed, and back on 0.34.0 python dockvault.py audit verify reports them missing until "
        "python dockvault.py audit acknowledge-removed-before --before <time> --retention-days <days> seals over "
        "them. What the older "
        "release ignores stays for the next upgrade. The check lists the values set in the panel."),
    "archived-audit-history-hidden": (
        "An earlier release cannot read the audit log's compressed daily blocks. While any block exists, 0.33.1 and "
        "later refuse to start on this database, and 0.33.0 and earlier start without seeing those days. Before "
        "going back, put the days back as rows with this release: python dockvault.py audit unarchive (it checks "
        "the database volume's free space first: restored days take 7 to 12 times their compressed size), then go "
        "back. Within 14 days of the first 0.34.0 start (AUDIT_ARCHIVE_START_AFTER_DAYS), or of a start of 0.34.0 "
        "after more than 12 hours on an earlier release that wrote to the audit log, or more than 3 days on one or "
        "stopped, there is nothing to undo. The check finds the archived days."),
    "zk-envelope-held-after-admin-reset": (
        "From 0.34.0, for ZK_ENVELOPE_HOLD_DAYS days (14 by default) after an administrator or the server's "
        "operator changed an account's sign-in details, the account's zero-knowledge encryption key is given to a "
        "browser only after it enters a code sent by email to the address the account had before the first of "
        "those changes. Changes made before the upgrade count: an account with an encryption key whose sign-in "
        "details were changed in the 14 days before the upgrade is held from the first start (opening the key "
        "answers 403 zk-envelope-hold), and an account changed then that has no key yet is held as soon as it sets "
        "one up, until the hold ends. Only an email change recorded before 0.34.0 kept the address it replaced, "
        "so for an account whose first such change was of another kind or an email change of an account that had no "
        "address, or on a deployment without mail, no code can be sent (409 zk-envelope-hold-no-mail): the server's "
        "operator releases it with python dockvault.py accounts --action release-key-hold, or the hold ends "
        "ZK_ENVELOPE_HOLD_DAYS days after the last change. The check below counts the accounts held at the first "
        "start and those only the server's operator can release; it cannot count an account that sets up a key "
        "later, so a check that finds none does not mean no account will be held. ZK_ENVELOPE_HOLD_DAYS=0 in .env "
        "before the upgrade turns the hold off. Going back to an earlier release lifts the hold."),
    "recording-levels-changed": (
        "From 0.34.0 the recording levels (Settings, Activity and records, or the AUDIT_MAX_* lines of .env) decide "
        "how much of names typed at sign-in, email addresses, IP addresses and browser descriptions the audit log "
        "records; by default it records them in full, as earlier releases do. While the newest levels record less "
        "than Full of any of them, an earlier release would record them all in full again, behind the notice that "
        "tells users otherwise: 0.33.1 and later refuse to start on this database, and python dockvault.py update "
        "refuses to go back unless --force-downgrade is given. Before going back, set those levels back to Full and "
        "remove any AUDIT_MAX_* line in .env that lowers one, then start 0.34.0 once so it removes the record that "
        "stops the earlier release. The check finds the newest levels while they record less than Full."),
    # The legal holds' own condition (app/core/legal_hold_marker.py, CONDITION), word for word.
    "legal-holds-block-rollback": (
        "While a legal hold stands, or what a hold kept (files, folders, the old names of renamed ones) waits for its "
        "purge, going back to a release before 0.34.0 would destroy it: release the holds and let the purge run "
        "first."),
    # The compliance records' own condition (app/core/compliance_marker.py, CONDITION), word for word.
    "compliance-records-block-rollback": (
        "From 0.34.0, while a compliance case is open, a case's records must still be kept, or the record of a step of "
        "compliance access taken (an auditor right given or taken, a case's steps, a name revealed) is younger than "
        "COMPLIANCE_RECORD_MIN_DAYS (2190 by default, at least 365), an earlier release would not keep them: it knows "
        "no cases, and with a positive AUDIT_LOG_RETENTION_DAYS, which 0.34.0 leaves in .env as a waiting change, it "
        "deletes every older audit row the first time an administrator opens the dashboard's activity feed. So 0.33.1 "
        "and later refuse to start on this database, and python dockvault.py update refuses to go back unless "
        "--force-downgrade is given. A refused request, which any account can make, a vault owner's own steps on "
        "Access to my vaults, and a notice to a vault's owner (also of access someone else gave to their vault) do "
        "not count. Wait until no case is open and those records are older than COMPLIANCE_RECORD_MIN_DAYS, then "
        "start 0.34.0 once so it removes the record that stops the earlier release. An earlier release started "
        "sooner with ALLOW_START_ON_NEWER_DATA=true keeps the audit rows only while .env sets no "
        "AUDIT_LOG_RETENTION_DAYS. The check finds that record."),
    "older-images-refuse-newer-data": (
        "From 0.34.0 the release records in the table data_requirements each state of the data that an earlier "
        "release cannot read or would destroy, for as long as it lasts: archived audit days, legal holds and what "
        "they kept, recording levels below Full, and open compliance cases and the records of compliance access "
        "while they must be kept. 0.33.1 and later refuse to start on a database that holds such "
        "a record, and print what to undo with 0.34.0 before going back; python dockvault.py update refuses to go "
        "back while one exists unless --force-downgrade is given. ALLOW_START_ON_NEWER_DATA=true in .env starts an "
        "earlier release anyway, on data it cannot fully read: it may show an incomplete audit log and delete what "
        "0.34.0 keeps. 0.33.0 and earlier do not read the table. The check lists the records."),
    "promotion-resets-passwords-set-by-others": (
        "From 0.34.0 each account records whether its current password is its own or one someone else set: an "
        "administrator, a user who manages users, the server's operator, or a reset link another account made. At "
        "the upgrade this is read once from the audit log, and a password whose setting the log no longer holds "
        "counts as the person's own. When an account whose password someone else set is made an administrator, that "
        "password stops working, its sessions end, and the person sets a new one through a reset link sent to their "
        "own email address (when none can be sent, the administrator who promoted them gets a link to hand over); "
        "until then the account cannot approve a held change to someone's sign-in details. What an earlier release "
        "did after going back to it is not read on the return to 0.34.0: a password an administrator set while it "
        "ran counts as the person's own, and an account marked before keeps its mark though its person set a "
        "password of their own meanwhile."),
}

# The conditions whose rows stop the upgraded deployment going back across the edge.
BLOCKS_ROLLBACK = {"archived-audit-history-hidden", "recording-levels-changed", "legal-holds-block-rollback",
                   "compliance-records-block-rollback", "older-images-refuse-newer-data"}
# Checked on the upgraded database: a rollback's conditions.
ON_UPGRADED = {"archived-audit-history-hidden", "panel-retention-not-read", "recording-levels-changed",
               "legal-holds-block-rollback", "compliance-records-block-rollback", "older-images-refuse-newer-data"}
# Conditions that have no query: what they say cannot be read from the database.
WITHOUT_DETECT = ("audit-protected-minimum-365-days", "container-output-rotates", "storage-volume-keeps-free-space",
                  "promotion-resets-passwords-set-by-others")
# Every condition of 0.34.0, in the order the release commit writes them on each edge into it.
CONDITIONS = (
    "audit-history-compressed-after-90-days",
    "audit-retention-runs-on-a-timer",
    "audit-protected-minimum-365-days",
    "container-output-rotates",
    "storage-volume-keeps-free-space",
    "alert-names-and-addresses-cleared-after-30-days",
    "ended-invitations-and-codes-deleted-after-30-days",
    "archived-audit-history-hidden",
    "panel-retention-not-read",
    "recording-levels-changed",
    "legal-holds-block-rollback",
    "compliance-records-block-rollback",
    "older-images-refuse-newer-data",
    "promotion-resets-passwords-set-by-others",
    "zk-envelope-held-after-admin-reset",
)
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
    "recording-levels-changed": {"audit_privacy_policies"},
    "legal-holds-block-rollback": {"legal_hold_vaults", "held_files", "held_folders", "held_name_history"},
    "compliance-records-block-rollback": {"data_requirements"},
    "older-images-refuse-newer-data": {"data_requirements"},
}
# The tables and columns 0.33.2 has that the queries on the database being upgraded read (from its models).
OLDER_SCHEMA = {
    "audit_logs": {"timestamp"},
    "security_alerts": {"timestamp", "username", "ip_address"},
    "account_invitations": {"accepted_at", "revoked_at", "expires_at"},
    "password_reset_tokens": {"consumed_at", "expires_at"},
    "otp_codes": {"consumed_at", "expires_at"},
    "email_change_codes": {"consumed_at", "expires_at"},
    "credential_changes": {"target_user_id", "kind", "status", "applied_at", "payload"},
    "user_keypairs": {"user_id"},
}


def _version_key(version: str) -> tuple:
    return tuple(int(part) for part in version.split("."))


def edge_problems(matrix: dict) -> list:
    """What the edges into INTO of an upgrade matrix (docs/upgrade-matrix.json, as loaded) lack, as a list of
    sentences; empty when every such edge that can be taken leaves from SOURCE_FLOOR or later and carries every
    condition of CONDITIONS as kept here: the same query, the rollback flag on exactly the conditions that block a
    rollback, and the same text."""
    problems = []
    edges = [edge for edge in matrix.get("edges", []) if edge.get("to") == INTO and edge.get("kind") != "blocked"]
    if INTO in matrix.get("versions", {}) and not edges:
        problems.append(f"no edge that can be taken leads into {INTO}")
    for edge in edges:
        where = f"the edge {edge.get('from')} -> {INTO}"
        if _version_key(edge["from"]) < _version_key(SOURCE_FLOOR):
            problems.append(f"{where} skips {SOURCE_FLOOR}: an edge into {INTO} leaves from {SOURCE_FLOOR} or later")
        have = {condition.get("id"): condition for condition in edge.get("conditions", [])}
        for cid in CONDITIONS:
            condition = have.get(cid)
            if condition is None:
                problems.append(f"{where} lacks the condition {cid}")
                continue
            if condition.get("detect") != DETECT.get(cid):
                problems.append(f"{where} gives {cid} another detect query than the one kept here")
            if cid in BLOCKS_ROLLBACK and condition.get("blocks_rollback") is not True:
                problems.append(f"{where} leaves blocks_rollback off {cid}, which blocks a rollback")
            if cid not in BLOCKS_ROLLBACK and "blocks_rollback" in condition:
                problems.append(f"{where} marks {cid} with blocks_rollback, which blocks none")
            if condition.get("summary") != SUMMARY[cid]:
                problems.append(f"{where} gives {cid} another text than the one kept here")
    return problems


def condition(cid: str) -> dict:
    """The condition ``cid`` as the release commit writes it on an edge into INTO: the text kept here, the query and
    the rollback flag."""
    out = {"id": cid, "summary": SUMMARY[cid]}
    if cid in DETECT:
        out["detect"] = DETECT[cid]
    if cid in BLOCKS_ROLLBACK:
        out["blocks_rollback"] = True
    return out


def before_the_release(matrix: dict) -> dict:
    """A copy of ``matrix`` with only the releases below INTO: every release from INTO on, every edge to or from
    one, and the lines from INTO's on taken out, and the newest line left the newest again (no end date). The same
    matrix whether or not ``matrix`` already declares INTO."""
    out = copy.deepcopy(matrix)
    floor = _version_key(INTO)
    out["versions"] = {v: entry for v, entry in out["versions"].items() if _version_key(v) < floor}
    out["edges"] = [edge for edge in out["edges"]
                    if _version_key(edge["from"]) < floor and _version_key(edge["to"]) < floor]
    if "lines" in out:
        lines = {line: dict(entry) for line, entry in out["lines"].items() if _version_key(line + ".0") < floor}
        if lines:
            newest = max(lines, key=lambda line: _version_key(line + ".0"))
            lines[newest]["security_fixes_until"] = None
        out["lines"] = lines
    return out


def with_the_release(matrix: dict) -> dict:
    """``matrix`` as the release commit makes it from this file: the releases below INTO, then INTO declared (its
    entry made from SOURCE_FLOOR's), its line listed, and one edge into it, from SOURCE_FLOOR, with every condition.
    SOURCE_FLOOR must be the newest release below INTO: a later one needs its own edge into INTO."""
    data = before_the_release(matrix)
    newest = max(data["versions"], key=_version_key)
    assert newest == SOURCE_FLOOR, "a later release of the line before needs its own edge into 0.34.0 here"
    entry = copy.deepcopy(data["versions"][newest])
    entry.update(released="2026-11-15", notes="The release.")
    entry["support"] = {"eol": False, "secure": True}
    entry.pop("vulnerabilities", None)
    data["versions"][INTO] = entry
    data["lines"] = {"0.33": {"security_fixes_until": "2027-05-15"}, "0.34": {"security_fixes_until": None}}
    data["edges"].append({"from": SOURCE_FLOOR, "to": INTO, "kind": "direct", "reversible": True,
                          "requires_backup": True, "conditions": [condition(cid) for cid in CONDITIONS]})
    return data
