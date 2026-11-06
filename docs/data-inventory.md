# Personal data inventory

What a DockVault deployment stores about people: where, which fields, why, for how long, and how it
is erased. It is written for the operator of a deployment (in GDPR terms, the controller) filling in
a record of processing activities (Art. 30) or a privacy notice (Art. 13 and 14). It describes
version 0.33.2. Entries marked **New in 0.33.0**, **New in 0.33.1** or **New in 0.33.2** are what that
release started storing; each release's list is repeated at the end.

DockVault is software you run. Nothing described here leaves your deployment unless you configure it
to: email goes through the SMTP server you set, the optional update check sends no personal data
(see [SECURITY.md](../.github/SECURITY.md)), and there is no telemetry.

The purposes below say why the software keeps each item. The legal basis for each, and whether a
retention period suits your organisation, are yours to decide.

## Whose data

| Who | How they appear |
|---|---|
| Account holders (users and administrators) | Their account, content, sessions, devices, keys, and the audit log of what they did. |
| Holders of a temporary credential | Someone an account holder gave a temporary credential to. They act under that account; the audit log records the credential's name. |
| Recipients of a public link (a file, folder or note) | No account. Each visit is audited with their address and browser's user agent. |
| Senders to an upload link | No account. Their address is kept with the upload for about a day, and each upload is audited with their address and user agent. |
| Anyone who types a name at the sign-in page | A failed sign-in is audited with the address and, on the web, the user agent. A name that is an account's username, or its email address where the sign-in method accepts one, is recorded as the account's username, and a temporary credential's name with the credential; any other name (a password typed into the username box included) exactly as typed, or as the recording levels keep a name typed at a failed sign-in (**new in 0.34.0**). The sign-in throttles count it under a keyed stand-in, not the name. |
| People invited by email | Their username, email address and role, from the invitation. |
| Administrators acting on others | Their username appears in the records of the people they changed, and in the record of each administrator they made. |

## Where it is kept

| Store | Location | Kept until |
|---|---|---|
| [Database](#database) | PostgreSQL, volume `vault_pg_data` | Per table, below. |
| [Cache](#cache-redis) | Redis. The shipped compose files keep its data in memory only (`/data` is a tmpfs). | Each key expires on its own, from minutes to a day (30 days for a lock with no end on a name that is no account). A restart of the Redis container empties it. |
| [Files](#files) | Volume `vault_storage` | The file is deleted or expires. |
| [Logs](#logs) | The container output, and a size-capped file in volume `vault_logs` | Rotation: the file at a third of `LOG_PULL_SINK_MAX_MB` (5 MB by default), the output at `DOCKER_LOG_MAX_SIZE` (10m) per file and `DOCKER_LOG_MAX_FILE` (5) files per container. |
| [Email](#email) | Your SMTP server and the recipients' mailboxes | Outside DockVault. It keeps no copy of what it sends. |
| [Exports and backups](#exports-backups-and-host-tools) | Wherever the person who made them saves them | Outside DockVault. |
| [The browser](#the-browser) | Each person's browser storage | Sign-out, or the person clearing it. |

The database and file volumes are only as protected as the disk they sit on: see "What is encrypted
at rest" in the [README](../README.md#what-is-encrypted-at-rest--and-the-host-disk-encryption-prerequisite).

## Database

"Deleted with the account" means the row goes when the account is deleted (a database cascade). An
account cannot be deleted while it owns vaults: transfer or delete them first.

### Accounts and sign-in

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `users` | Username, email (optional), password hash, role, active and locked state, failed sign-in count, last sign-in, creation time and creator, storage quota, SFTP settings. **New in 0.33.0:** `second_factor_reset_at`, when an administrator reset the person's second factor. **New in 0.33.1:** `permission_defaults_revision`, the revision of the role's default permissions the account has been given. **New in 0.34.0:** `password_set_by` and `password_set_by_other_at`, which account set the current password and when, when that was someone other than the person (an administrator, a user who manages users, the server's operator, or the maker of a reset link someone else made); filled once at the first start from the audit log for existing accounts, cleared when the person sets their own. `privacy_seen_version`, the version of the recording notice the person last said they had read. | The account; taking back a password someone else set when the account is made an administrator, and refusing its approvals until then. | Life of the account. | Deleting the account. |
| `user_ssh_keys` | Key name, public key, fingerprint, created, last used, who added it. **New in 0.34.0:** `created_by_name`, the username of who added it (the person, an administrator, or `operator@host`), kept when that account is deleted; filled at the first start for older keys from the account that added them or the audit row of the addition. | SFTP sign-in by key; showing who added a key, and telling its owner when the administrator who added it leaves. | Until removed. | The person or an administrator removing it; deleted with the account. |
| `second_factor_enrollments`, `second_factor_recovery_codes` | Method, the authenticator seed (encrypted), times; recovery-code hashes. | Second factor. | Until reset or removed. | Resetting the second factor; deleted with the account. |
| `active_sessions` | Session token hash, the account, a temporary credential if one was used, the client address, start, last activity, expiry. **New in 0.33.1:** where it was signed in (`web` or `sftp`). The Activity page's "Now" panel shows each signed-in account's latest address from here. **New in 0.34.0:** when the session entered the emailed code that releases the account's encryption key during the hold after an administrator's change. | Keeping a person signed in; ending sessions. | While the session lasts, then 30 days after it ended (longer only if tokens are configured to live longer). | The pruner (every `LOG_PRUNE_INTERVAL_MINUTES`, 15 by default); deleted with the account. |
| `pending_logins` | The account, client address, attempts. | A sign-in waiting for its second factor. | 30 days after it completed or expired. | The pruner; deleted with the account. |
| `sign_in_lockouts` **New in 0.33.0** | The account, the source address (an IPv6 address as its /64, or `*` for the account-wide count), failure count, window start, last failure, lock start and end. | Automatic locks: wrong passwords from one address lock new sign-ins from that address, and past a higher count from all addresses together over about 24 hours, from everywhere. | An address count with no lock: a day after its last failure. The account-wide count: at most a day after its last failure, by when it has lost every one (it loses one every 24 hours divided by the backstop, every 72 minutes by default). A right password adds nothing here. A lock: until it ends (`ACCOUNT_LOCKOUT_MINUTES`, 15 by default; the account-wide pause lasts until its count has lost a failure, if that is later), or until an administrator clears it when that setting is 0. | The periodic cleanup; an administrator's unlock (deletes every row for the account); deleted with the account. |
| `temporary_credentials`, `temp_credential_vault_access` | The generated username, a hash of the credential, the owner's note about it (free text), its scope and passcode hash, times, creator. | Delegated, time-limited access. | Until the owner deletes it: an expired credential stays listed. | The owner deleting it; deleted with the account. |
| `devices`, `device_grants` | Device label, secret hashes, last seen, created, expiry; which vaults it syncs. | Desktop sync. | Until revoked and deleted. | The person deleting the device; deleted with the account. |
| `password_reset_tokens` | The account, token hash, times, who created it (an administrator, or a user given the permission to manage users). **New in 0.33.0:** whether another account made it. | Password reset. | An unused token is replaced when a new one is issued; a used one is kept. **New in 0.34.0:** a used or expired token is deleted 30 days after it ends, by the pruner. **New in 0.33.0:** a token another account made is deleted when it is used or looked up after its maker could no longer make it (demoted, deactivated, locked, deleted, the permission taken away), and when its account is made an administrator and its maker is not one. | Deleted with the account. |
| `otp_codes`, `email_change_codes` | The account, the new email address a code was sent to, code hash, attempts, times. **New in 0.34.0:** also the codes that release the account's encryption key during the hold after an administrator changed its sign-in details, with the address the code was sent to. | Confirming an email change; releasing the encryption key. | An unused code is replaced when a new one is issued; a used one is kept. **New in 0.34.0:** a used or expired code is deleted 30 days after it ends, by the pruner. | Deleted with the account. |
| `account_invitations` | The invitee's username, email address and role, token hash, times, who created it, the account it became; **new in 0.33.0**, for an administrator's invitation, the ids of the inviter and of the administrators the inviter descends from, as they stood when it was made. | Inviting someone to create an account; the ids keep the two-administrator rule's lineage if the inviter is demoted or deleted before it is accepted. | Kept after it is accepted, revoked or expired. **Changed in 0.34.0:** deleted 30 days after it ends (it is accepted, revoked or expires, whichever comes first), by the pruner; a pending invitation is kept. The lineage an administrator's invitation kept is copied into `admin_grants` when it is accepted, so it outlasts the row. | The pruner; until then the database only (see [Erasing a person](#erasing-a-person)). |

### Access and collaboration

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `groups`, `user_groups`, `user_permissions`, `user_endpoint_permissions` | Group names and descriptions; who belongs to which group with what role, who added them and when; granted permissions. | Access control. | Until changed. **New in 0.33.0:** a change of role resets an account's granted permissions (`user_endpoint_permissions`) to the new role's defaults, keeping those another administrator granted it. | An administrator; memberships and grants are deleted with the account. |
| `vault_members`, `vault_group_access`, `vault_favorites`, `vault_views` | Who can use which vault and how, who added them and when; a person's starred vaults and when they last opened each. | Access control; the vault list's order. | Until changed. | The vault owner or an administrator; deleted with the account or the vault. |
| `shares`, `share_claims` | Who shared what with which people or departments, limits, status; who claimed it, when they last used it, how many downloads. | Sharing inside the deployment. | After expiry or revocation too, until the shared item, the vault or the sharer's account is deleted. | Deleting the item, the vault or the account. |
| `user_keypairs`, `vault_member_keys`, `vault_member_index_keys`, `zk_share_invites` | Public keys, fingerprints, wrapped keys, who granted or revoked them. **New in 0.34.0:** `user_keypairs` records whether the key was set up within 14 days after an administrator changed the account's sign-in details, or while the account's password was one an administrator chose (yes or no, not when or which), shown beside the key to whoever shares a zero-knowledge vault with the account, and only to someone who could pick the account in the recipient picker. | Zero-knowledge vaults. | Until revoked or replaced. | Deleted with the account or the vault. |
| `vault_key_proofs` **New in 0.33.2** | For each key epoch of a zero-knowledge vault: the vault, the epoch, how it was set up (`create`, `rotate`, `bootstrap` or `owner_reset`), when, and the id of the account that installed it (`created_by`), the only column that points to a person. The proof material beside it (a public key, a sealed private key and two MACs) is derived from the vault's key and says nothing about anyone. | A change to the vault's keys (rotating, sharing, setting the name-index key) must prove it holds the current epoch's key; the account id says who set up each epoch's check. | Until the vault is deleted, or until its epoch is retired (an epoch below the oldest one still in use, when a manager retires old key versions). | Deleted with the vault; retiring the epoch; `created_by` is cleared (set to empty) when that account is deleted, and the row stays for the vault. |
| `zk_key_proof_challenges` **New in 0.33.2** | The id of the account a challenge was issued to (`user_id`), the vault it is for, the operation, the key epochs, a sealed one-time server key, a random nonce, a hash of the vault's verifying key, and when it was issued. | Each key change to a zero-knowledge vault answers a one-time challenge issued to that account for that vault and operation; the account id makes sure only the account it was issued to can use it. At most 32 live challenges per account. | Five minutes. A challenge is deleted as soon as it is answered. | Answering it; the account's next challenge request deletes its expired ones; the pruner (every `LOG_PRUNE_INTERVAL_MINUTES`, 15 by default) deletes the rest; deleted with the account. |

### Content

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `vaults`, `folders`, `files` | Names and descriptions, sealed at rest; the owner, who uploaded or last changed a file, sizes, times, expiry. The last access to a vault, by anyone. | Storing the content. | Until deleted, or until a file's expiry when the vault has one. | The owner or a member with delete rights; the expiry sweep. |
| `notes` | Title and body, sealed at rest; for a note sent by someone else, the sender's username. | Notes. | Until deleted. | The person deleting the note; deleted with the account. |
| `chunked_upload_sessions` | The uploader, the file name and type (Standard vaults; cleared when the upload finishes or fails), sizes. | Resumable uploads. | About a day. | The expiry sweep. |

### Links for people without an account

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `public_links` | The owner, the target, a hash of the link and of its PIN or password, limits, use and download counts, last use. | Sharing a file or folder by link. | Until the owner deletes it, after expiry or revocation too. | The owner; deleted with the owner's account or the target. |
| `note_public_links` | The owner, a copy of the note's title and text taken when the link was made, a hash of the link and of its PIN or password, limits, view counts, last view. | Sharing a note by link. | Until the owner deletes it. | The owner; deleted with the owner's account. |
| `receivers` | The owner, a label, the target vault, limits, how long uploads are kept, upload count, last upload. | Upload links. | Until the owner deletes it. | The owner; deleted with the owner's account. |
| `receiver_upload_sessions` | The sender's address, and proof that the link's secret was given. | Accounting an upload in progress. | About a day, with its upload session. | The expiry sweep. |

Visits to a link and uploads through one are also in the audit log.

### Audit and security records

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `audit_logs` | See [The audit log](#the-audit-log). | Accountability and security. | **For ever by default** (`AUDIT_LOG_RETENTION_DAYS=0`). | The pruner, by the maximum days (`AUDIT_LOG_RETENTION_DAYS`, or the panel) and the size cap (`AUDIT_LOG_MAX_MB`, or the panel), never below the protected minimums (`AUDIT_MIN_RETENTION_DAYS`; `AUDIT_PROTECTED_MIN_DAYS`, 365 days, for administration and security rows, which the size cap never deletes), and not while the hold switch (`RETENTION_HOLD`, or the panel) is on. **Not** deleted with the account. |
| `security_alerts` | Event type, a message, the username and address involved, details, who resolved it and their notes. **Changed in 0.34.0:** the message no longer spells out the name and the address (it is completed from the alert's own fields when shown). | Alerting administrators to attacks. | A resolved alert: `SECURITY_ALERT_RETENTION_DAYS` (90 by default). An unresolved alert: until resolved. **New in 0.34.0:** the name and the address are cleared once the alert is older than the security record's window (`SECURITY_RECORD_DAYS`), resolved or not. | The pruner deletes old resolved alerts and clears the names and addresses, unless the hold switch is on. **Not** deleted with the account. |
| `security_records` **New in 0.34.0** | Each failed sign-in (a web password, a second-factor code, an SFTP password): the time, what failed, the account the name matched, the name exactly as typed (which can be a password typed into the wrong box), the address, the way in, the reason, and the alert it raised. Kept in full whatever the audit log keeps. A record that cannot be written (a fault in this table) never costs the failure's audit row: the row is written, and an alert for the administrators (`audit_recording_degraded`) says records are missing. | Blocking addresses, counting failures and investigating attacks. | `SECURITY_RECORD_DAYS` (30 by default; the panel can change it between `SECURITY_RECORD_MIN_DAYS` and `SECURITY_RECORD_MAX_DAYS`). | The pruner, unless the hold switch is on. The account id is cleared when the account is deleted. |
| `rate_limit_records` | An address (**changed in 0.34.0:** as its throttle subject, an IPv6 address as its /64 and an IPv4 address written as IPv6 as the IPv4 one); for a password sign-in, a keyed stand-in for the name typed, with the address (**changed in 0.33.0**: it was the name as typed); for an SFTP key sign-in, the address and the name as typed; a device's id. Counts and times. | Sign-in throttling while Redis is unavailable. | An hour. | The pruner. |
| `credential_changes` **New in 0.33.0** | The account changed; the kind of change; the requesting and deciding administrators' usernames; times; a summary, which can hold the new email address, or an SSH key's name and fingerprint; while a request waits, what it would set (a password hash, an address or a key), and the ids of the administrator who asked, of the administrators that administrator's grant descends from, and of those who had changed the account in the 14 days before; and for an email change that was made, the address before and after. **New in 0.34.0:** when the server's operator released the hold the change put on the account's encryption key; and for any other change that was made, the account's email address at the time. | A second change to someone's sign-in within 14 days waits for another administrator; for 14 days after an administrator changes someone's email address, a self-service reset link goes to the address before; while a change holds the account's encryption key, the code that releases it goes to the address the account had before the change. | A request still waiting: until it is decided or expires (at most 7 days), when what it would set is cleared. A change made, or a request denied, withdrawn or expired: 14 days after that. | The pruner (every `LOG_PRUNE_INTERVAL_MINUTES`, 15 by default); deleted with the changed account. An administrator's username stays on the rows of the accounts they changed until then. The audit log keeps the history. |
| `admin_grants` **New in 0.33.0** | For each administrator: who made them one (the administrator's id and username, or the server's operator), when, and the ids of the administrators that grant descends from. | Who may approve a held change: neither the administrator who asked nor the approver may have made the other one, directly or through administrators they made, and the approver must have been one for 14 days before the request. | While the account is an administrator. | A demotion; deleted with the account. The maker's username stays on it after the maker's account is deleted. |
| `notifications` | The recipient, type, title and text, read state. The text can name other people. **New in 0.33.0:** notices of every administrator's change to a person's account (lock, unlock, deactivation, role, password, reset link, second factor, email, SSH key) and of credential-change requests, whose text holds the old and new email address, an SSH key's name and fingerprint, and the administrator's username; and to every other administrator, that an account became an administrator and who made it one. **New in 0.34.0:** notices about encryption keys: that a change to a zero-knowledge vault's key was refused because it did not come with the account's own key, that a key was set up for the account, that a vault's owner reset its key (naming the owner's username), and that a member's key for a vault the person owns does not match. No notice names a vault. | Telling people what happened. | Until the person deletes it. **New in 0.34.0:** with `NOTIFICATION_RETENTION_DAYS` (or the panel's "Delete notifications after", 30 to 3650 days) a notification is deleted that long after it arrives, read or not; 0, the default, keeps it. | The person; the pruner; deleted with the account. |
| `activity_saved_searches` **New in 0.33.0** | An administrator's saved Activity filters, at most 50 each: a name, and filters that can hold other people's usernames (names typed at sign-in included), addresses and free text. **Changed in 0.34.0:** the person filter keeps a name the audit log holds in full (an account's username, or a name recorded in full under earlier levels) as typed; any other name, one typed at a failed sign-in, is kept as the recording levels keep those: in full, as its fingerprint, or, at "not recorded", not at all (such a search cannot be saved). The free text and addresses are kept as typed. | Reusing a search. | Until deleted. | The administrator; deleted with the administrator's account. |
| `user_preferences` | Display choices only, from fixed lists. **New in 0.33.0:** "Hide note text" is kept here (it used to be in the browser), with the Activity page's page size, live updates and range. | Remembering a person's choices. | Until changed. | Deleted with the account. |
| `log_pull_tokens` | Token name, prefix and hash, who created it, last use. | Log access. | Until disabled and deleted. | An administrator. |
| `audit_seals` **New in 0.34.0** | The audit log's integrity chain: one seal per closed hour of audit rows (two hashes over the hour's rows and the ids of its rows), and one per retention change, cancel, acknowledgment and deletion of audit rows. A retention change's seal names the setting, its values, the change's id and the administrator's account id; an acknowledgment's names the seals it acknowledges. An hour's seal also keeps the 16-byte ids of its rows, and, for rows written without a nonce, a random value per hour from which their nonces are derived. No username, address, name or text of a row: those enter only as a hash, under each row's random nonce. | Finding changes made to the audit log in the database. | For ever: seals are never deleted, and they stay when the rows they cover are deleted. | Nothing deletes a seal. Deleting rows writes a seal that says so; an erase destroys the rows' nonces, so the old hashes reveal nothing. |
| `audit_archive_blocks` **New in 0.34.0** | Audit rows older than the row window (`AUDIT_HOT_DAYS`, 90 days by default), compressed: each block is a part of one UTC day and holds every column of every row it took from `audit_logs`, so the same personal data as those rows (see [The audit log](#the-audit-log)), and the per-hour values from which the nonces of rows written without one are derived. A count of rows and bytes by action, status and channel, and by hour, and of rows by hour, action, status and channel, per block, for the summaries and the size cap. The Activity page and its exports read archived days for a time range that reaches them, through a temporary table that goes with the request. | The audit log, kept compressed: it is kept for ever by default. Archiving starts `AUDIT_ARCHIVE_START_AFTER_DAYS` (14) days after 0.34.0 first ran here (when it began sealing the audit log); a day `audit unarchive` put back stays rows that long again. While any block exists, a row in `data_requirements` keeps 0.33.1 and later from starting. | As long as the audit rows it holds: the audit log's retention applies to archived rows as to the others (the maximum, the size cap, the protected minimums, the hold). | The pruner deletes archived rows by the audit log's retention, rewriting the block (a compliance case's rows stay while they must be kept); `dockvault.py audit unarchive` puts days back as rows and removes their blocks. A day holding a compliance case's rows that must be kept stays rows, whole, until they may go. **Not** deleted with the account: a block keeps the account id of a deleted account (a restored row has it cleared, as the database clears it on a row, and the Activity page shows it cleared). |
| `audit_value_removals` **New in 0.34.0** | For each removal of values recorded under earlier recording levels: the levels it brings rows down to and the time before which its rows were written, who asked for it and who cancelled it (id and username), when, why it waits, and how many rows it changed (counts). | The removal waits its delay before it runs, and any administrator can cancel it meanwhile. | For ever, as a record alongside the audit log. | Nothing deletes a row. The account ids are cleared when the account is deleted. |
| `erase_requests` **New in 0.34.0** | For each per-person erase: the name it removes, only sealed (AES-256-GCM under a key derived from `ENCRYPTION_KEY`, bound to the request), the placeholder it writes, who asked for it and who cancelled it (id and username), when, why it waits, and what it changed in each place (counts). | The erase waits its delay before it runs, and any administrator can cancel it meanwhile. | For ever, as a record alongside the audit log; the sealed name is deleted when the erase completes or is cancelled, or, while a confirmed legal hold stands or a compliance case is open, once neither does. | Nothing deletes a row. The sealed name is deleted with the erase's end (under a confirmed legal hold or an open case, by the pruner once neither holds it); the account ids are cleared when the account is deleted. |
| `managed_setting_changes` **New in 0.34.0** | For each change of a managed setting that deletes records sooner: the setting, the values before and after, the id and username of the administrator who asked and of the one who cancelled it, and when. | A change that deletes records sooner waits `RETENTION_REDUCTION_DELAY_DAYS` (7 by default) and any administrator can cancel it meanwhile; this is the record of each one and how it ended. What waits, and what the pruner applies, is the audit log's integrity chain's: the retention screen lists the waiting changes from it, not from this table. | For ever, as a record alongside the audit log. | Nothing deletes it. The account ids are cleared when the account is deleted; the usernames stay. |

### Compliance access (new in 0.34.0)

An auditor (an account two administrators gave the auditor right) may open vaults in a case a second
administrator approves; the vault's owner is told at once. A case can keep a vault's files under a legal
hold. Free text (a justification, a note to the owner, an objection, a reason) is sealed at rest under a
key derived from `ENCRYPTION_KEY`, bound to its row; the audit rows of a case carry ids, never names. The
pruner keeps a case's audit rows while the case is open or a hold stands, and for
`COMPLIANCE_RECORD_MIN_DAYS` (2190 by default) after it closes; rows of the compliance category are kept
that long after they were written. 30 days after a case closes, the counts of the files opened and the exports
under it are kept on the case (`compliance_cases`), and read from there once its rows are archived or deleted;
its rows are kept until then whatever the floor. The owner's "Access to my vaults" page lists each file opened
from those rows: once they are no longer kept, it says until when they were, as the list may no longer be
complete.

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `auditor_grants` | The account given the auditor right and its username at the time; who proposed, approved, turned down or revoked it (ids and usernames, or the server's operator); a sealed note and reasons; the id of the TOTP enrollment the grant is bound to and the account's role when it was approved; what the approval rule read when it was proposed (the ids of the proposer, of the administrators in their lineage, of who had changed the account's sign-in details in the 14 days before, of who created the account and of the administrators in that creator's lineage); the ids and usernames of everyone who changed the account's sign-in details while it stood; times and state. | Who may act as an auditor, granted by two people, and suspended or ended when the account changes. | For ever, as the record of who held the right. | Nothing deletes it. Account ids are cleared when an account is deleted, but for those in what the rule read when it was proposed; the usernames stay. |
| `compliance_cases`, `compliance_case_scopes`, `compliance_case_vaults`, `compliance_case_people` | The auditor (id and username) and who approved, turned down or closed the case; purpose and legal basis; the sealed justification, note to the owner, objection and reasons; the vaults, folders and custodians asked for and given, with each vault's owner at the approval; the people the case concerns (owners, custodians, people named); dates, and when someone else first changed the sign-in details of the account that started the case, and how. | The investigation and its accountability: who asked, why, what for, who approved it, and whom it concerns. | For ever by default: the case records are never deleted by the app. Their audit rows: while the case is open or a hold stands, then `COMPLIANCE_RECORD_MIN_DAYS` after it closes, then as the audit log's retention says. | Nothing deletes them. The auditor's account cannot be deleted while it has a case; the ids of who approved, turned down or closed it are cleared when their account is deleted; the people concerned and the vault owners are kept by id. |
| `compliance_exports` | The case, who made the export, when, how many files and bytes, and the hash of its manifest. No file names. | Exports are fetched once, by the account that made them. | With the case. | With the case. |
| `compliance_reveals` | The auditor (id and username), the audit row whose recorded name was revealed, its vault, the reason's category and the sealed reason. | Accountability for a name revealed outside a case. | For ever. | Nothing deletes it. The auditor's id is cleared when the account is deleted. |
| `compliance_notice_outbox` | The vault owner's id, the kind of notice and the counts and dates it says (never a vault, file or folder name), the sealed email address it goes to (and the address before an administrator's recent change), which of them it reached, the delivery state and attempts, and when the owner said they had read it. A notice that someone else gave a person access to the owner's vault (no case) also holds the usernames of who gave it and of each person given access, their accounts' creation dates and makers, whether their passwords were set by someone else, a department's name, and the vaults' ids. | The owner's email notice is written with the access it tells of and sent with retries; a later address change cannot reroute it. The banner after sign-in shows while a notice of a case is unread. | With the case; a notice with no case, `COMPLIANCE_RECORD_MIN_DAYS` after it was written once it was delivered, given up or had no address (a notice still waiting to be sent is kept). | With the case; the owner's id is cleared when the account is deleted. A notice with no case: the pruner's `owner_notices` job, which the logs hold stops. |
| `legal_hold_vaults` | The case and vault; who placed, confirmed and released the hold (ids and usernames) and the sealed reason; dates. | A legal hold keeps what is deleted from the vault, until released and purged. | For ever, as the record of the hold. | Nothing deletes it. Account ids are cleared when an account is deleted. |
| `held_name_history` | The name a file or folder had before it was renamed while its vault was under a hold (sealed as it was), the object, the vault and when. | A rename cannot erase what a hold keeps. | Until the hold is released and what it kept is purged. | The purge after the hold's release. |
| `held_files`, `held_folders` | Every column of a file or folder row deleted from a vault under a legal hold, as it was (its sealed name, MIME type and checksum, size, who uploaded or created it, its storage path; the stored file stays on disk), with when, why (deleted, replaced, expired, moved, a duplicate) and by whose account it was deleted. Built by the database from the live tables, filled by its triggers. | What a legal hold keeps: for the people using the vault the deletion is done; the case's records keep it. | While a hold stands on the vault, then `COMPLIANCE_HOLD_PURGE_DELAY_DAYS` after the last one is released or lapses. | The purge after the hold's release, which secure-deletes the stored file too (`held_file_purged`). |

### Other tables

`system_settings`, `schema_steps`, `retired_object_ids`, `share_tags`, `note_link_tags`,
`receiver_tags`, `second_factor_actions`, `email_actions`, `email_profiles`, `email_templates`,
`email_resources`, `vault_storage_grants`, `vault_key_history`, `ecc_registration_challenges` and
`ecc_key_update_challenges` hold settings, policies, templates, storage allocations and key material.
(**New in 0.34.0:** the pruner also deletes the rows of the two challenge tables once their five minutes
are up, and both keep their one-time key only sealed with the deployment key, as
`zk_key_proof_challenges` does.)
Their only personal data is the id of the account that created, owns or was allocated an item, and
`email_profiles` holds the sending address and SMTP login you configure. Tag policies can list
account and group ids that may use a tag. `data_requirements` holds no personal data: each row
says which version a change to the stored data needs, what the change was, and how to undo it.
`compliance_case_counters` (new in 0.34.0) holds the last case number given in each year.

`managed_settings` (new in 0.34.0) holds the values administrators set for the settings the panel
manages within the deployment's limits, one row per setting, with the id and username of whoever set
each one last and when. A row is overwritten by the next change and never deleted.

Everyone can read what the audit log records, how long each store keeps data and who can see it at
`/recording` (new in 0.34.0), linked from the sign-in, invitation and link pages and the account menu; the
operator states the legal basis and a contact in Settings, Activity and records.

`audit_privacy_policies` (new in 0.34.0) holds each version of the recording levels (what the audit log
records of each kind of personal data), with the id and username of the administrator who saved it, or
"server configuration" for a version the server wrote to bring a level within a lowered `.env` limit, and
when. Rows are never changed or deleted: each change adds a version.

`sftp_processes` (new in 0.34.0) holds each running SFTP server process's version and its container's
host name, refreshed every 30 seconds; it holds no personal data. A process removes its row when it
stops, and rows not refreshed for 7 days are removed.

### The audit log

Each row of `audit_logs` holds:

- the account's id and username. For a failed sign-in, no account id: the account's username when the
  name typed is an account's username or **(new in 0.34.0)** its email address where the sign-in method
  accepts one (the web's method in Settings, Accounts & Access; SFTP signs in by username), a temporary
  credential's name with its id and name when the name typed is one, and otherwise the name as it was
  typed, as the recording levels keep it;
- for a temporary credential, its id and **(new in 0.33.0)** its name, kept after the credential is
  deleted;
- what happened (the action), its outcome, the resource's type and id, and the time;
- the client address. Behind a reverse proxy, the real client address when the proxy is listed in
  `TRUSTED_PROXIES`;
- **New in 0.33.0:** the browser's user agent (up to 512 characters), the HTTP method, the route and
  the way the request came in (`channel`: web, SFTP, public link, upload link or device sync). They
  are filled on every web, public-link, upload-link and device-sync row; SFTP rows carry no user
  agent. Before 0.33.0 no row carried a user agent;
- details, which depend on the action: for example the account a change was made to, an email
  address before and after a change, who a share went to, or the filters of an export. Vault, file
  and folder names are never stored in the details; nor are session tokens, passwords or link tokens,
  and of an error only its type is. **New in 0.33.2:** a change to a zero-knowledge vault's keys
  records how it was proved (`proof`), and a refused key proof records the operation and which part
  failed. The proof itself (its header, MACs, challenge nonce) and the request body are never stored.
  **New in 0.34.0:** a detail whose key the application does not classify is not stored (its key is
  noted in `recorded`, and an alert is raised);
- an error message for a failure;
- **New in 0.34.0: the recording levels.** What a row keeps of vault, file and folder names, of the name typed
  at a failed sign-in, of email addresses, of the address and of the user agent follows the levels an
  administrator chooses, within the
  limits `.env` sets (`AUDIT_MAX_NAMES`, `AUDIT_MAX_SIGNIN_NAMES`, `AUDIT_MAX_EMAILS`, `AUDIT_MAX_IP`,
  `AUDIT_MAX_USER_AGENT`). Version 1, the default, records what earlier releases did. A value recorded at
  a lower level is either not stored or stored in another form in `recorded` (a shortened address keeps
  the /24 or /48 it is in; a name at the fingerprint level keeps a keyed fingerprint, under a key of its
  own for each vault's names); the row's own columns and details hold only values recorded in full. A row
  never keeps a vault, file or folder name in plain text: at the full level a name is kept sealed in
  `recorded`, encrypted under a key derived for its vault and its row, and is opened only for administrators
  who can read the vault: the vault's own name always; a file's or a folder's name only in a vault that is not
  zero-knowledge, and in a password-protected vault only once its password is given on the Activity page.
  A fingerprint is made with `AUDIT_FINGERPRINT_KEY` (or a key derived from `ENCRYPTION_KEY`): it hides a
  name from someone who reads the database without `.env`, but anyone who holds `.env` (it is in the
  backups) can test guesses, and finds a short or common name quickly. Any administrator can also test a
  guess of a name typed at a failed sign-in, by searching the Activity page for it: the search fingerprints
  what is typed and finds the rows that kept the same fingerprint. Name fingerprints, and names opened from
  their seals, are shown and exported only to administrators who can read the vault.
  `privacy_version` says which version of the levels a row was recorded under (none: an earlier release;
  -1: recorded without its personal values because deciding failed, with an alert). Changing the levels
  rewrites no older row by itself. An administrator can then ask, on the same page, to remove the values
  recorded under earlier levels: once `RETENTION_REDUCTION_DELAY_DAYS` has passed (any administrator can
  cancel it meanwhile, and every administrator is told), every row written before the request, archived or
  not, keeps only what the levels in force record (`audit_value_removals`). With `AUDIT_IP_FULL_DAYS` (the
  panel's "Keep full addresses in audit rows for"; no limit by default) an address recorded in full is
  shortened to its /24 or /48 once its row is that many days old (in a day the archive holds, once the whole
  day is: up to a day later). Either change gives each changed row a new
  `seal_nonce`, and the integrity chain records it and still verifies. Both wait while a confirmed legal hold
  stands or a compliance case is open, and leave a case's rows that must be kept as they are; a removal then stays
  running, and says so, until the case lets them go, and changes them and completes then, and the shortening
  comes back to them, as rows or in an archived day, once the case lets them go;
- **New in 0.34.0:** `seal_nonce`, 16 random bytes on every row written from 0.34.0 on, under which the
  log's integrity chain hashes the row's personal values (`audit_seals`), so that once it is destroyed the
  hash reveals nothing about them. `case_id`: the compliance case a row was written under (see
  Compliance access, above), empty on every other row. **Empty on every row so far:** `ip_via`
  (how the address was learned). `security_alerts` gains the same `ip_via`, also empty.

Rows are not deleted when the account they name is deleted: its id is cleared and its username is
kept, and the deletion itself adds a row. With the default `AUDIT_LOG_RETENTION_DAYS=0` every row is
kept for ever. A positive value makes the pruner delete rows older than that many days, on a timer, unless
the hold switch is on (`RETENTION_HOLD`, or the panel). Administration and security rows are kept at least
`AUDIT_PROTECTED_MIN_DAYS` (365 days by default) whatever the maximum, and a size cap (`AUDIT_LOG_MAX_MB`)
never deletes them. The size cap counts each hour's bytes as the integrity chain sealed them, and only once
`RETENTION_REDUCTION_DELAY_DAYS` of running time have passed since the hour was sealed. An administrator can change the maximum, the minimums and the cap in the panel,
within the limits `.env` sets; a change that deletes sooner waits `RETENTION_REDUCTION_DELAY_DAYS` and
every administrator is told. After an upgrade from a release that deleted only when an administrator's
dashboard loaded, a positive `AUDIT_LOG_RETENTION_DAYS` first waits in the same way. The application only
adds rows and deletes old ones; anyone with database access can change the table, but from 0.34.0 every
closed hour is sealed (`audit_seals`), and a change made in the database without the server's key to an
hour already sealed is found by `python dockvault.py audit verify` and by the server's daily check. It is not
found when it is made by whoever holds the key (`AUDIT_CHAIN_KEY`, or `ENCRYPTION_KEY` when that is unset),
nor before the row's hour is sealed (about two hours).

Names typed at failed sign-ins appear on the Activity page (filtered as "no account", which also lists a
failed sign-in for an account or a temporary credential, as its row has no account id) and in its exports. The summary charts' "most active people" leaves them out, and the page's username search
suggests only accounts: it does not read the log for its suggestions, whatever it is asked.

## Cache (Redis)

In memory only with the shipped compose files. Every key below expires on its own.

| Key | Holds | Lifetime |
|---|---|---|
| `session:*`, `denylist:session:*` | A session token's hash with its session and account id; ended sessions. | 30 minutes; a token's remaining life. |
| `temp_cred:<name>` | A temporary credential's ids and times. | The credential's lifetime. |
| `otp:<purpose>:<account>` | A pending code's hash and the new email address it was sent to. | The code's lifetime. |
| `rate_limit:login_user:<name key>\|<address>`, `rate_limit:login_ip:<address>` | Failed sign-ins per name and address, and per address. **Changed in 0.34.0:** the address is its throttle subject (an IPv6 address as its /64, an IPv4 address written as IPv6 as the IPv4 one), as in every per-address count. **Changed in 0.33.0:** the name is a keyed stand-in, 128 bits of an HMAC of it under the deployment's secret (`LOG_TOKEN_PEPPER`, else one derived from `JWT_SECRET_KEY`), which cannot be reversed or confirmed without that secret; it was the name as typed. | The login window (`RATE_LIMIT_LOGIN_WINDOW_SECONDS`, 5 minutes by default). |
| `rate_limit:login_phantom:<address>\|<name key>`, `rate_limit:login_phantom:*\|<name key>` **New in 0.33.0** | Failed sign-ins for a name that is no account, counted and paused exactly like an account's so a refusal does not reveal whether it exists. The name is a keyed stand-in, as above. | Like the database's rows for an account: the address count, a day after its last failure or its lock's end; the account-wide count, about a day, or until its pause ends if later. A lock with no end (`ACCOUNT_LOCKOUT_MINUTES` of 0): 30 days. |
| `security:failed_login:<name key>:<address>` | Failed sign-ins, for alerts. **Changed in 0.34.0:** the address is its throttle subject, as above. **Changed in 0.33.0:** the name is a keyed stand-in, as above; it was the name as typed. | `SECURITY_FAILED_LOGIN_WINDOW` (10 minutes by default). |
| `rate_limit:sftp_pk:<address>:<name>`, `rate_limit:device_sync:*`, `rate_limit:vault:*`, `rate_limit:api:*`, `rate_limit:ws_connect:ip:<address>` (**new in 0.33.0**), `security:file_deletion:*` | Throttles keyed by address, the name as typed (an SFTP key sign-in), account or device. **Changed in 0.34.0:** an address is its throttle subject, as above. **New in 0.34.0:** the web app's sign-outs are counted in `rate_limit:api:auth_sign_out:*`, by the session each ends (the hash of it `denylist:session:*` holds), or by address when the token names no session. | Their windows: seconds to minutes. |
| `publiclink:grant:<grant hash>` | A public file or folder link's download grant, stored under a hash of the grant (the grant itself goes only to the browser that redeemed the link): the link's id, the address that redeemed it, and when it was minted. | 60 seconds, or until the download it was minted for uses it. |
| `publiclink:fail:<link hash>`, `notelink:fail:<link hash>`, `receiver:fail:<link hash>` | Wrong PINs or passwords given for a file, note or upload link: a count, under a hash of the link's token. Five lock the link, from every address, until the key expires. | 15 minutes from the first wrong one; the right one, given before the link is locked, deletes it. |
| `publiclink_redeem:<address>:<link hash>`, `notelink_redeem:<address>:<link hash>`, `receiver_open:<address>:<link hash>`, `publiclink_redeem_ip:<address>`, `notelink_redeem_ip:<address>`, `receiver_open_ip:<address>`, `publiclink_download_ip:<address>` | The times of the last minute's requests to open a link (per address and link, and per address), and to download through a file link (per address). The address is its throttle subject, as above. | A minute. |
| `operation:*` | A transfer in progress: account id and username, the file name, size, progress. | An hour. |
| Upload markers | A same-name upload in progress: the member's id and the name, encrypted. | 5 minutes by default. |
| `device_reuse_alert:<device>` | That an alert was raised for a device. | An hour. |

Messages published between processes (the Activity page's live signal, which carries only an event's
id and category, and security alerts) are not stored.

## Files

`vault_storage` holds the files people upload, encrypted at rest (AES-256-GCM; a zero-knowledge
vault's files are encrypted in the browser, and the server has no key). While an upload is in
progress, its pieces are staged on the same volume (resumable uploads) or in memory (SFTP). A file
stays until someone deletes it, or until its expiry when the vault or upload link has one and
`ENFORCE_FILE_EXPIRY` is on (the default). Files uploaded by people without an account through an
upload link are kept for the link's retention.

What is in the files is up to the people who store them; DockVault does not read Standard vault
files except to serve them, and cannot read zero-knowledge ones.

## Logs

- **Container output** (`docker logs`): the web access log (client address and port, method, path
  with any link, invitation or reset token in it redacted, the query's parameter names but never their
  values, status; a WebSocket handshake's line the same way) and the application's own lines
  (startup, counts from the cleanups, warnings). Those lines name accounts by id and carry no file
  names or passwords. A database error's text leaves out the statement's values (**new in 0.33.0**),
  and an unexpected error, or a failed audit, notification or security-event write, is logged by its
  class and where it was raised. The database driver's own text can still name a value that broke a
  uniqueness rule (a username, an address), and some older error lines print it. **Changed in 0.34.0:**
  a query's values were printed, so a search sent in the query (an Activity search for a name, an
  address or free text) reached this log; now only the names are, a WebSocket handshake's line
  included, and a line read back through log access from before the change serves only the names too,
  except an older line whose query held nothing but bare, name-like parts, which is served as it was
  written. The shipped compose files rotate it (**new in 0.34.0**): Docker's `json-file` driver keeps at
  most `DOCKER_LOG_MAX_FILE` files (5) of `DOCKER_LOG_MAX_SIZE` (10m) per container, so the oldest lines go
  as new ones arrive. A deployment that updates only by pulling images keeps the compose files it was set
  up with, which never rotate it, until it updates its checkout. A host whose Docker sends container output
  to journald, syslog or a log shipper keeps it there only once the block is removed (README,
  "Container logs").
- **The log-access file** (volume `vault_logs`, `LOG_PULL_SINK_PATH`): the same web lines, and the
  SFTP server's in the combined single-container mode. It rotates at a third of `LOG_PULL_SINK_MAX_MB`
  (**new in 0.34.0**; 15 by default, so 5 MB) and keeps two older files, `LOG_PULL_SINK_MAX_MB` in all,
  so the oldest lines go as new ones arrive. Administrators can read the newest lines (at most the newest
  5 MB) through Settings, Log access, when `PLAN_LOG_PULL` is on.

## Email

Sent only when you configure SMTP. DockVault keeps no copy; what is sent stays in your mail system and
the recipients' mailboxes.

| Email | Sent to | Holds |
|---|---|---|
| Password reset | The account's address. **New in 0.33.0:** for 14 days after an administrator changed it, a reset the person asks for goes to the address before (nothing is sent if there was none). **New in 0.34.0:** also sent the same way when the person is made an administrator while holding a password someone else set | A reset link; when it goes to the address before, a line saying why; at a promotion, a line saying why. |
| Email change verification | The new address | A confirmation code. |
| Account invitation | The invitee | The invitation link and their username. |
| Account changed by an administrator **New in 0.33.0** | The person; for an email change, the **old** address | What changed (for an email change, the old address and the new one masked, as n***@example.com; an SSH key's name and fingerprint), when, and the administrator's username. **New in 0.34.0:** also that their password was reset when they were made an administrator, because someone else had set it. It cannot be switched off. |
| New administrator **New in 0.33.0** | Every other active administrator | Which account became an administrator, how (created, promoted, or an invitation accepted), by whom, and when. It cannot be switched off. |
| SSH keys an administrator added **New in 0.34.0** | The owner of each account that holds SSH keys an administrator added, when that administrator is demoted, deactivated, locked or deleted | The administrator's username, why they left, each key's name and fingerprint, and a link to Your account. It cannot be switched off. The other administrators get an in-app notice naming the accounts. |
| Welcome, new sign-in alert, something shared with you, added to a vault, temporary credential issued | The person concerned | Off unless an administrator turns each on. The username and the template's text. |
| Email Studio sends | People or addresses an administrator chooses | The template the administrator wrote. |

## Exports, backups and host tools

- **Activity export** **New in 0.33.0** (replaces `/audit/export`): an administrator downloads up to
  100,000 audit rows as CSV or NDJSON, with the time, event, outcome, username (names typed at sign-in
  included), temporary credential name and id, channel, address, method, route, user agent, resource,
  details and error. No vault, file or folder names. Each export is itself audited
  (`audit_exported`, with its filters). The file is personal data wherever it is saved.
- **Log access**: an administrator's download of the log-access file.
- **The audit chain's head record** **New in 0.34.0**: a file on the keys volume (`AUDIT_CHAIN_HEAD_FILE`)
  that holds the newest seal's number and hash, the chain's key ids, the hour summaries of the last 30
  days (counts and hashes, and the salt of an hour whose rows have no nonce), a digest per older day, the
  retention checkpoints (the newest retention state, the cancels, and the ids of completed erases: request
  ids and seal numbers, never a name), and the integrity check's findings (kinds, times, seal numbers and
  row ids, never a row's values). Kept with the keys volume, in every backup, which archives the keys volume
  before the database. A restore of a backup leaves a mark beside it until `python dockvault.py audit
  accept-restore`. **`python dockvault.py audit verify`** prints the findings and the chain's head on the
  host's terminal; an export of the Activity page ends with that head. A head kept elsewhere is checked with
  `audit verify --anchor <head>`, and `--no-key` checks as someone holding no key would (reading nothing
  beyond the database's own tables). **`python dockvault.py audit
  acknowledge`** and the other host commands (`rekey`, `after-record`, `accept-database-head`,
  `accept-restore`, `acknowledge-removed-before`, `change-key`) write their seals audited as the host
  operator; `after-record --discard` saves the seals it deletes in a file beside the head record.
  `change-key` keeps the old key beside `.env` (mode 600), in `.audit-chain-key.previous.<VAULT_VOLUME_PREFIX>`
  (one file for each volume set), until the chain has moved to the new one; `lock` does not seal it, and Reset
  moves the file of the set it destroys aside as `.audit-chain-key.removed-<VAULT_VOLUME_PREFIX>`.
  **`python dockvault.py audit retention`** (**new in 0.34.0**) prints how long each kind of record is kept,
  as the server has it, and where each value comes from, and the changes waiting with the username of the
  administrator who asked for each (not audited, like the other reads on the host); with `--set NAME=VALUE`
  it changes a line of `.env` once the server has checked it. `audit unarchive` restores archived
  days as audit rows; `audit compact` gives the audit tables' free space back to the system (both are on
  the `audit` menu too).
- **Backups** made with `python dockvault.py`: every data volume and the `.env`, so everything above, and,
  while a change of the chain's key is not finished, the old key kept beside `.env` (sealed with `.env`
  under `--lock`), which a restore puts back.
  Keep and expire them under your own policy; a backup made before an erasure still holds what was
  erased.
- **`python dockvault.py accounts`** on the host: the server's operator can look an account up (its
  email and last sign-in are printed on the host's terminal, and the lookup is not audited, since the
  operator can read the database anyway) and change it (audited as the host operator). **New in
  0.33.0:** it can list the accounts that may view or manage users without being administrators (their
  usernames, roles, and who granted each permission when), not audited either. **New in 0.33.1:** it
  can list the permissions an administrator revoked that a restart before 0.33.1 granted again (usernames,
  roles, the permission, and when it was revoked and granted again, read from the audit log), not
  audited either, and unlock an account (its automatic locks and an administrator's lock), audited as
  the host operator. **New in 0.34.0:** `python -m app.core.host_operator zk-status`, run in the web
  container, prints the deployment's zero-knowledge counts and switches (no personal data: no names,
  keys or content), not audited.
- **`python dockvault.py cases`** on the host (new in 0.34.0): lists the open auditor rights and cases
  (usernames, states, dates, a case's purpose and legal basis), shows where an auditor's account came from
  (when and by whom it was created, who set its password, whether it has an authenticator) and, only when
  the server's operator may approve a case, the case's justification. Printed on the host's terminal and not
  audited, since the operator can read the database anyway; approving an auditor right or a case, turning a
  case down, confirming a case's legal hold and revoking an auditor right are audited as the host operator.
  What stops going back to an older version is listed without any personal data.

## The browser

The web app keeps the sign-in token and the signed-in account's basic details in the browser's local
storage (session storage in a private window), the tab's vault unlock state in session storage, and
display choices (theme, skin, layout, sort order). Signing out removes the token, the account details
and the unlock state. **New in 0.34.0:** it also ends the session on the server at once (its row in
`active_sessions` is marked ended, and its token is refused everywhere from then on), and signs out the
other tabs of the same browser that hold the same token; before, a session signed out of in the web app
stayed valid on the server until it expired. Display choices are kept. A tab that could not check its
session as it loaded (no answer from the server, a server error, a rate limit) signs out only itself, as
before, and ends nothing: the session is refused only when the server says so.

## Erasing a person

1. **Delete the account** (Users page). It is refused while the person owns vaults (transfer or
   delete them) or is the last administrator. The deletion removes the account and everything the
   tables above mark "deleted with the account": sign-in data, keys, sessions, devices, temporary
   credentials, notes, notifications, preferences, saved searches, memberships, their shares and
   links, upload links, credential-change records about them, and the record of who made them an
   administrator.
2. **What stays** after the account is deleted:
   - their rows in `audit_logs` (username, addresses, user agents, details), and the row recording
     the deletion;
   - `security_alerts` naming them (resolved ones age out after `SECURITY_ALERT_RETENTION_DAYS`);
   - `security_records` of failed sign-ins with their name (deleted after `SECURITY_RECORD_DAYS`; the account
     id on them is cleared);
   - their username on other accounts' `credential_changes` rows, as the requesting or deciding
     administrator, and their id in a request's kept approval record, until those rows are deleted 14
     days after the change or decision (a request they had open is withdrawn when they are deleted);
     and in other
     people's notifications and received notes;
   - their username on the `admin_grants` record of each administrator they made, and their id in the
     lineage of each administrator made through them and of administrators' invitations, while those
     records are kept;
   - other administrators' saved searches, and earlier exports' recorded filters, that name them;
   - an `account_invitations` row that named them;
   - files they uploaded to other people's vaults (their id is cleared; the file belongs to the
     vault);
   - backups, exports and logs made before the deletion, and email already sent.
   Cache entries expire on their own within a day (a lock with no end on a name that is no account:
   30 days); those about names typed at sign-in hold only a keyed stand-in.
3. **Removing what stays**, if you decide it must go (audit records are often kept to establish or
   defend legal claims; that is your decision): **erase the name** (Settings, Activity and records,
   "Erase a person's records"; new in 0.34.0). Type the name exactly as the records hold it: a deleted
   account's username, or a name typed at a failed sign-in. The preview counts what it would change in
   each place below, lists the near misses (the same name in another case or another form, each erased
   only by an erase of its own), and says what it does not reach. Asking asks for your password, and the
   erase waits `RETENTION_REDUCTION_DELAY_DAYS` (7 days by default); any administrator can cancel it
   until it begins, and every administrator is told. It is refused while an account, a temporary
   credential or an invitation still waiting has the name, for any name that starts with `erased-`, and
   for the names the server writes into the records for itself (`system`, `server configuration`, the
   host's operator `operator@host`, and the server acting on a retention limit in `.env`). No account can
   take any of those names, in any case or spacing; an account an older release let take one keeps
   working, and every administrator is told of it once at the start after the upgrade (an erase of that
   name stays refused).

   When it runs, every row of the audit log whose username is exactly that name, and every archived row,
   gets a placeholder (`erased-` and 8 random characters) in its place: its address, browser
   description, temporary credential's name, error text and `recorded` values are cleared, and of its
   details only ids, counts and the other values always recorded stay, never one that holds the name.
   The integrity chain records each changed row (its hash before and after) and still verifies. The same
   run gives the placeholder to the name in `security_records` (its address is cleared too),
   `security_alerts` (its address too), `credential_changes`, `admin_grants`, ended
   `account_invitations` (the email address is cleared), other administrators' saved searches,
   notifications, received notes, `managed_setting_changes`, `managed_settings`,
   `audit_privacy_policies`, `user_ssh_keys`, `erase_requests` and `audit_value_removals`. The name it
   removes is kept only
   sealed in `erase_requests` until then, and deleted when the erase completes or is cancelled; the
   audit rows of the request, the cancel and the completion name the placeholder, never the person.

   It waits while the hold switch is on, while a restore is not finished, while a legal hold stands confirmed
   or a compliance case is open (any of them: an audit row of what was done in a held vault need not name the
   case; a cancelled erase keeps its sealed name until neither holds; a case that holds only a hold nobody has
   confirmed yet holds nothing back), and, with
   `ERASE_BLOCKED_BY_PROTECTED_MINIMUM=true` (for deployments whose records must be kept intact), until
   every audit row it would change is older than the protected minimum for its kind. Rows of the name a
   compliance case keeps as they are (a closed case's rows within its records' floor) it leaves: the other
   records get the placeholder, and the erase stays running, says so, and keeps the name sealed until the case
   lets those rows go; it erases them and completes then.

   **What an erase does not reach:** backups, exports and copies made before it (and the database's own
   files until their space is reused: the erase runs a plain VACUUM, and `dockvault.py audit compact`
   rewrites the tables); container output and the log-access file; email already sent; other people's
   audit rows that name the person in their details (an administrator's row recording the deletion of
   their account, for example); audit rows with no time; a compliance case's audit rows while they must be
   kept (while the case is open or a hold stands, and `COMPLIANCE_RECORD_MIN_DAYS` after it closes), which stay
   as they are until then (the erase waits for them, as above); and the records of compliance access (cases,
   legal holds, auditor rights, revealed names and owners' notices), which keep who asked, approved and acted.

## Retention settings

`python dockvault.py audit retention` prints these as the running server has them, and changes a `.env`
line after checking it; Settings, Activity and records shows them in the panel.

| Setting | Default | Governs |
|---|---|---|
| `AUDIT_LOG_RETENTION_DAYS` | `0` (keep for ever) | Audit rows: the deployment's maximum days, which the panel can change. |
| `AUDIT_MIN_RETENTION_DAYS` | `0` | Audit rows: none younger is deleted; the panel cannot go below it. |
| `AUDIT_PROTECTED_MIN_DAYS` | `365` | Administration and security audit rows: none younger is deleted by age; only `.env` lowers it. |
| `AUDIT_LOG_MAX_MB` | `0` (off) | Audit rows: a size cap; the oldest go first, never administration or security rows. |
| `PLAN_LOG_MAX_DAYS`, `PLAN_LOG_MAX_MB` | `-1` (none) | Ceilings on the audit log's maximum days and size cap. |
| `RETENTION_REDUCTION_DELAY_DAYS` | `7` | How long a change that deletes sooner waits; any administrator can cancel it meanwhile. |
| `RETENTION_HOLD` | `false` | When `true`, nothing deletes audit rows, security records or alerts, and the panel cannot turn the hold off. |
| `AUDIT_HOT_DAYS` | `90` | Audit rows older than this (31 to 3650) are moved into compressed daily blocks, `audit_archive_blocks`; nothing is deleted. |
| `AUDIT_ARCHIVE_START_AFTER_DAYS` | `14` | Archiving starts this long (0 to 90) after 0.34.0 first ran. |
| `AUDIT_IP_FULL_DAYS` | `0` (keep) | Addresses in audit rows: one recorded in full is shortened to its /24 or /48 once its row is this many days old, and in a day the archive holds once the whole day is that old (1 to 36500; the panel can change it). |
| `ERASE_BLOCKED_BY_PROTECTED_MINIMUM` | `false` | When `true`, a per-person erase waits until every audit row it would change is older than the protected minimum for its kind. |
| `LOG_PRUNE_INTERVAL_MINUTES` | `15` | How often the pruner deletes old records (and seals the audit log's hours). At most 360 take effect: the integrity chain needs a seal at least every 12 hours. |
| `SECURITY_ALERT_RETENTION_DAYS` | `90` | Resolved security alerts. |
| `NOTIFICATION_RETENTION_DAYS` | `0` (keep) | Notifications, read or not, after they arrive (30 to 3650 days; the panel can change it). |
| `LOG_PULL_SINK_MAX_MB` | `15` | The log-access file and its two older copies, in all (3 to 1000). |
| `SECURITY_RECORD_DAYS` | `30` | Failed sign-ins kept in full, and the names and addresses in security alerts (between `SECURITY_RECORD_MIN_DAYS`, 7, and `SECURITY_RECORD_MAX_DAYS`, 365). |
| `ACCOUNT_LOCKOUT_MINUTES` | `15` | Automatic locks, and the phantom-name counters in Redis. |
| `RATE_LIMIT_LOGIN_WINDOW_SECONDS` | `300` | Sign-in counters. |
| `ENFORCE_FILE_EXPIRY` | `true` | Whether vault and upload-link expiry deletes files. |
| `COMPLIANCE_RECORD_MIN_DAYS` | `2190` | A compliance case's audit rows after the case closes, and the compliance rows of the audit log after they were written: none younger is deleted. A case's rows are also kept while it is open or a hold stands. |
| Per vault and per upload link | Off | How long files are kept. |
| Fixed | 30 days | Finished sessions and pending sign-ins. |
| Fixed | 14 days | Credential-change records, after the change is made or the request ends. |
| Fixed | 30 days | Invitations, after they are accepted, revoked or expire (**new in 0.34.0**). |
| Fixed | 30 days | Password reset links, one-time codes and email-change codes, after they are used or expire (**new in 0.34.0**). |
| Fixed | About a day | Failed sign-in counts with no lock, after their last failure (database and cache). |
| Fixed | About a day | Resumable-upload sessions and an upload-link sender's address. |

## What 0.33.0 added

- `audit_logs`: the user agent, method, route and channel are now filled on web, public-link,
  upload-link and device-sync rows, including those of people with no account (link recipients and
  upload-link senders); and a temporary credential's name, kept after it is deleted.
- `sign_in_lockouts`: failed sign-ins per account and source address (an IPv6 address as its /64), and
  per account from all addresses together over about 24 hours.
- Redis `rate_limit:login_phantom:` keys: a keyed stand-in for each name typed at sign-in that is no
  account.
- `credential_changes`: administrators' requests to change someone's sign-in, with their summary, and
  the address before and after an email change, each kept for 14 days after the change or decision.
- `admin_grants`: who made each administrator one, and when; and on an administrator's invitation
  (`account_invitations.inviter_lineage`), the administrators the inviter descends from.
- Notifications and an email ("Account changed by an administrator") for every administrator's change
  to a person's account, the email going to the old address for an email change and naming the new
  one masked; and a notification and an email ("New administrator") to every other administrator
  when an account becomes one.
- `activity_saved_searches`: administrators' saved Activity filters.
- `users.second_factor_reset_at`.
- `user_preferences`: "Hide note text" and the Activity page's choices.
- The Activity export, replacing `/audit/export`, and the Activity page's "Now" panel, which shows
  each signed-in account's latest address from the existing sessions.
- Removed: the Live Monitor, whose feed of activity went to every administrator's open page. The
  Activity page's live signal carries only an event's id and category.
- Changed: the cache keys and the fallback table that count failed sign-ins by name hold a keyed
  stand-in, not the name as typed; the Activity page's username search suggests accounts only and
  never reads the audit log.

## What 0.33.1 added

- `users.permission_defaults_revision`.
- `active_sessions.channel`: whether a session was signed in over the web or SFTP.
- `audit_logs`: `permission_default_granted`, when a start gives an account a permission its role gained
  by default in a newer release.

## What 0.33.2 added

- `vault_key_proofs`: for each zero-knowledge key epoch, the id of the account that set up its key
  check, kept with the vault until the epoch is retired, and cleared when that account is deleted.
- `zk_key_proof_challenges`: the id of the account each key-proof challenge was issued to, for five
  minutes at most.
- `audit_logs`: how each change to a zero-knowledge vault's keys was proved (`proof`), each refused key
  proof (`zk_key_proof_failed`, with the operation and the part that failed), each change accepted
  without one while the check is switched off (`zk_key_proof_absent`), each key check set up for an
  older vault (`zk_key_proof_bootstrapped`) and each owner's reset of it (`zk_owner_key_reset`). The
  proof itself and the request body are never stored.
- Changed: the web app's forms are sent only by its scripts, never by the browser itself, so what is
  typed into them (a username and password at sign-in included) no longer reaches an address, the
  browser history or a reverse proxy's log when a form is sent before the page has finished loading.

## What 0.34.0 added

How long records are kept, the audit log's integrity, its archive and erasing a person:

- Timed deletion: the pruner deletes on a timer, in the web container only, never when a page is read.
  Audit rows are still kept for ever by default; a positive `AUDIT_LOG_RETENTION_DAYS` from an earlier
  release first waits `RETENTION_REDUCTION_DELAY_DAYS` with notice. Administration and security rows are kept
  at least `AUDIT_PROTECTED_MIN_DAYS` (365). The panel can change the numbers within `.env`'s limits; a
  change that deletes sooner waits and every administrator is told (`managed_settings`,
  `managed_setting_changes`). The hold switch (`RETENTION_HOLD`) stops every deletion of logs.
- `security_records`: each failed sign-in in full for `SECURITY_RECORD_DAYS` (30); security alerts lose
  their names and addresses after the same time, and their messages no longer spell them out.
- `audit_seals` and `audit_logs.seal_nonce`: the integrity chain, and the head record on the keys volume.
- `audit_archive_blocks`: audit rows older than `AUDIT_HOT_DAYS` (90), compressed, from
  `AUDIT_ARCHIVE_START_AFTER_DAYS` (14) after the upgrade. They hold the same personal data as the rows they
  replace (a day holding a compliance case's rows that must be kept stays rows). `python dockvault.py audit
  unarchive` restores them; an earlier release cannot read them.
- `erase_requests`: a per-person erase, with its name only sealed; see [Erasing a person](#erasing-a-person)
  and what it does not reach.
- `audit_value_removals`: a removal of the values recorded under earlier recording levels, asked for after a
  level is lowered; and `AUDIT_IP_FULL_DAYS`, how long an address stays in full in an audit row (see
  [The audit log](#the-audit-log)).
- Working records: invitations, and used or expired reset links, one-time codes and email-change codes, are
  deleted 30 days after they end (they were kept); notifications after `NOTIFICATION_RETENTION_DAYS` when
  set (0 keeps them, as before). The pruner deletes none of them while a confirmed legal hold stands or a
  compliance case is open; a new reset link or one-time code still replaces an unused one at once, and a reset
  link refused when it is used is deleted. The log-access file holds `LOG_PULL_SINK_MAX_MB` (15) in all.
- Container output rotates in the shipped compose files (`DOCKER_LOG_MAX_SIZE`, `DOCKER_LOG_MAX_FILE`), on
  installs whose compose files come from 0.34.0.
- Zero-knowledge keys: for `ZK_ENVELOPE_HOLD_DAYS` (14 by default, 0 to 14; 0 turns it off) after an
  administrator or the server's operator changed an account's sign-in details, its encryption key is given to a
  browser only after a code sent by email: the code and the address it went to (`otp_codes`), when a session
  entered it (`active_sessions`), and the account's address at each change and when the server's operator
  released a hold (`credential_changes`). Also whether a key was set up within 14 days after such a change
  (`user_keypairs`); notices about encryption keys (`notifications`); and in `audit_logs`, what a member's
  browser found when it checked a vault key it holds (`zk_key_check_mismatch`), and each code sent, wrong code
  and release (`zk_envelope_release_code_sent`, `zk_envelope_release_failed`, `zk_envelope_released`). The
  pruner deletes expired key registration and envelope challenges, whose one-time keys are kept sealed.
