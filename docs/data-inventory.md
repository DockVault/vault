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
| [Logs](#logs) | The container output, and a size-capped file in volume `vault_logs` | Rotation (the file) or your Docker logging settings (the output). |
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
| `active_sessions` | Session token hash, the account, a temporary credential if one was used, the client address, start, last activity, expiry. **New in 0.33.1:** where it was signed in (`web` or `sftp`). The Activity page's "Now" panel shows each signed-in account's latest address from here. | Keeping a person signed in; ending sessions. | While the session lasts, then 30 days after it ended (longer only if tokens are configured to live longer). | The pruner (every `LOG_PRUNE_INTERVAL_MINUTES`, 15 by default); deleted with the account. |
| `pending_logins` | The account, client address, attempts. | A sign-in waiting for its second factor. | 30 days after it completed or expired. | The pruner; deleted with the account. |
| `sign_in_lockouts` **New in 0.33.0** | The account, the source address (an IPv6 address as its /64, or `*` for the account-wide count), failure count, window start, last failure, lock start and end. | Automatic locks: wrong passwords from one address lock new sign-ins from that address, and past a higher count from all addresses together over about 24 hours, from everywhere. | An address count with no lock: a day after its last failure. The account-wide count: at most a day after its last failure, by when it has lost every one (it loses one every 24 hours divided by the backstop, every 72 minutes by default). A right password adds nothing here. A lock: until it ends (`ACCOUNT_LOCKOUT_MINUTES`, 15 by default; the account-wide pause lasts until its count has lost a failure, if that is later), or until an administrator clears it when that setting is 0. | The periodic cleanup; an administrator's unlock (deletes every row for the account); deleted with the account. |
| `temporary_credentials`, `temp_credential_vault_access` | The generated username, a hash of the credential, the owner's note about it (free text), its scope and passcode hash, times, creator. | Delegated, time-limited access. | Until the owner deletes it: an expired credential stays listed. | The owner deleting it; deleted with the account. |
| `devices`, `device_grants` | Device label, secret hashes, last seen, created, expiry; which vaults it syncs. | Desktop sync. | Until revoked and deleted. | The person deleting the device; deleted with the account. |
| `password_reset_tokens` | The account, token hash, times, who created it (an administrator, or a user given the permission to manage users). **New in 0.33.0:** whether another account made it. | Password reset. | An unused token is replaced when a new one is issued; a used one is kept. **New in 0.33.0:** a token another account made is deleted when it is used or looked up after its maker could no longer make it (demoted, deactivated, locked, deleted, the permission taken away), and when its account is made an administrator and its maker is not one. | Deleted with the account. |
| `otp_codes`, `email_change_codes` | The account, the new email address a code was sent to, code hash, attempts, times. | Confirming an email change. | An unused code is replaced when a new one is issued; a used one is kept. | Deleted with the account. |
| `account_invitations` | The invitee's username, email address and role, token hash, times, who created it, the account it became; **new in 0.33.0**, for an administrator's invitation, the ids of the inviter and of the administrators the inviter descends from, as they stood when it was made. | Inviting someone to create an account; the ids keep the two-administrator rule's lineage if the inviter is demoted or deleted before it is accepted. | Kept after it is accepted, revoked or expired. The app never deletes it. | The database only (see [Erasing a person](#erasing-a-person)). |

### Access and collaboration

| Table | Personal data | Purpose | Kept for | Erased by |
|---|---|---|---|---|
| `groups`, `user_groups`, `user_permissions`, `user_endpoint_permissions` | Group names and descriptions; who belongs to which group with what role, who added them and when; granted permissions. | Access control. | Until changed. **New in 0.33.0:** a change of role resets an account's granted permissions (`user_endpoint_permissions`) to the new role's defaults, keeping those another administrator granted it. | An administrator; memberships and grants are deleted with the account. |
| `vault_members`, `vault_group_access`, `vault_favorites`, `vault_views` | Who can use which vault and how, who added them and when; a person's starred vaults and when they last opened each. | Access control; the vault list's order. | Until changed. | The vault owner or an administrator; deleted with the account or the vault. |
| `shares`, `share_claims` | Who shared what with which people or departments, limits, status; who claimed it, when they last used it, how many downloads. | Sharing inside the deployment. | After expiry or revocation too, until the shared item, the vault or the sharer's account is deleted. | Deleting the item, the vault or the account. |
| `user_keypairs`, `vault_member_keys`, `vault_member_index_keys`, `zk_share_invites` | Public keys, fingerprints, wrapped keys, who granted or revoked them. | Zero-knowledge vaults. | Until revoked or replaced. | Deleted with the account or the vault. |
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
| `credential_changes` **New in 0.33.0** | The account changed; the kind of change; the requesting and deciding administrators' usernames; times; a summary, which can hold the new email address, or an SSH key's name and fingerprint; while a request waits, what it would set (a password hash, an address or a key), and the ids of the administrator who asked, of the administrators that administrator's grant descends from, and of those who had changed the account in the 14 days before; and for an email change that was made, the address before and after. | A second change to someone's sign-in within 14 days waits for another administrator; for 14 days after an administrator changes someone's email address, a self-service reset link goes to the address before. | A request still waiting: until it is decided or expires (at most 7 days), when what it would set is cleared. A change made, or a request denied, withdrawn or expired: 14 days after that. | The pruner (every `LOG_PRUNE_INTERVAL_MINUTES`, 15 by default); deleted with the changed account. An administrator's username stays on the rows of the accounts they changed until then. The audit log keeps the history. |
| `admin_grants` **New in 0.33.0** | For each administrator: who made them one (the administrator's id and username, or the server's operator), when, and the ids of the administrators that grant descends from. | Who may approve a held change: neither the administrator who asked nor the approver may have made the other one, directly or through administrators they made, and the approver must have been one for 14 days before the request. | While the account is an administrator. | A demotion; deleted with the account. The maker's username stays on it after the maker's account is deleted. |
| `notifications` | The recipient, type, title and text, read state. The text can name other people. **New in 0.33.0:** notices of every administrator's change to a person's account (lock, unlock, deactivation, role, password, reset link, second factor, email, SSH key) and of credential-change requests, whose text holds the old and new email address, an SSH key's name and fingerprint, and the administrator's username; and to every other administrator, that an account became an administrator and who made it one. | Telling people what happened. | Until the person deletes it. | The person; deleted with the account. |
| `activity_saved_searches` **New in 0.33.0** | An administrator's saved Activity filters, at most 50 each: a name, and filters that can hold other people's usernames (names typed at sign-in included), addresses and free text. **Changed in 0.34.0:** the person filter keeps a name the audit log holds in full (an account's username, or a name recorded in full under earlier levels) as typed; any other name, one typed at a failed sign-in, is kept as the recording levels keep those: in full, as its fingerprint, or, at "not recorded", not at all (such a search cannot be saved). The free text and addresses are kept as typed. | Reusing a search. | Until deleted. | The administrator; deleted with the administrator's account. |
| `user_preferences` | Display choices only, from fixed lists. **New in 0.33.0:** "Hide note text" is kept here (it used to be in the browser), with the Activity page's page size, live updates and range. | Remembering a person's choices. | Until changed. | Deleted with the account. |
| `log_pull_tokens` | Token name, prefix and hash, who created it, last use. | Log access. | Until disabled and deleted. | An administrator. |
| `managed_setting_changes` **New in 0.34.0** | For each change of a managed setting that deletes records sooner: the setting, the values before and after, the id and username of the administrator who asked and of the one who cancelled it, and when. | A change that deletes records sooner waits `RETENTION_REDUCTION_DELAY_DAYS` (7 by default) and any administrator can cancel it meanwhile; this is the record of each one and how it ended. | For ever, as a record alongside the audit log. | Nothing deletes it. The account ids are cleared when the account is deleted; the usernames stay. |

### Other tables

`system_settings`, `schema_steps`, `retired_object_ids`, `share_tags`, `note_link_tags`,
`receiver_tags`, `second_factor_actions`, `email_actions`, `email_profiles`, `email_templates`,
`email_resources`, `vault_storage_grants`, `vault_key_history`, `ecc_registration_challenges` and
`ecc_key_update_challenges` hold settings, policies, templates, storage allocations and key material.
Their only personal data is the id of the account that created, owns or was allocated an item, and
`email_profiles` holds the sending address and SMTP login you configure. Tag policies can list
account and group ids that may use a tag. `data_requirements` holds no personal data: each row
says which version a change to the stored data needs, what the change was, and how to undo it.

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
  never rewrites older rows;
- **New in 0.34.0, and empty on every row so far:** `seal_nonce` (a random value per row for the log's
  integrity chain), `ip_via` (how the address was learned) and `case_id` (a compliance case).
  `security_alerts` gains the same `ip_via`, also empty.

Rows are not deleted when the account they name is deleted: its id is cleared and its username is
kept, and the deletion itself adds a row. With the default `AUDIT_LOG_RETENTION_DAYS=0` every row is
kept for ever. A positive value makes the pruner delete rows older than that many days, on a timer, unless
the hold switch is on (`RETENTION_HOLD`, or the panel). Administration and security rows are kept at least
`AUDIT_PROTECTED_MIN_DAYS` (365 days by default) whatever the maximum, and a size cap (`AUDIT_LOG_MAX_MB`)
never deletes them. An administrator can change the maximum, the minimums and the cap in the panel,
within the limits `.env` sets; a change that deletes sooner waits `RETENTION_REDUCTION_DELAY_DAYS` and
every administrator is told. After an upgrade from a release that deleted only when an administrator's
dashboard loaded, a positive `AUDIT_LOG_RETENTION_DAYS` first waits in the same way. The application only
adds rows and deletes old ones; anyone with database access can change the table.

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
| `rate_limit:sftp_pk:<address>:<name>`, `rate_limit:device_sync:*`, `rate_limit:vault:*`, `rate_limit:api:*`, `rate_limit:ws_connect:ip:<address>` (**new in 0.33.0**), `security:file_deletion:*` | Throttles keyed by address, the name as typed (an SFTP key sign-in), account or device. **Changed in 0.34.0:** an address is its throttle subject, as above. | Their windows: seconds to minutes. |
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
  values, status) and the application's own lines
  (startup, counts from the cleanups, warnings). Those lines name accounts by id and carry no file
  names or passwords. A database error's text leaves out the statement's values (**new in 0.33.0**),
  and an unexpected error, or a failed audit, notification or security-event write, is logged by its
  class and where it was raised. The database driver's own text can still name a value that broke a
  uniqueness rule (a username, an address), and some older error lines print it. **Changed in 0.34.0:**
  a query's values were printed, so a search sent in the query (an Activity search for a name, an
  address or free text) reached this log; now only the names are, and a line read back through log
  access from before the change serves only the names too. How long Docker
  keeps this is set by the host's Docker logging
  configuration; the shipped compose files set no limit, so set `max-size` and `max-file` for the
  logging driver if you need one.
- **The log-access file** (volume `vault_logs`, `LOG_PULL_SINK_PATH`): the same web lines, and the
  SFTP server's in the combined single-container mode. It rotates at 5 MB and keeps two older files,
  about 15 MB in all, so the oldest lines go as new ones arrive. Administrators can read it through
  Settings, Log access, when `PLAN_LOG_PULL` is on.

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
- **Backups** made with `python dockvault.py`: every data volume and the `.env`, so everything above.
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

## The browser

The web app keeps the sign-in token and the signed-in account's basic details in the browser's local
storage (session storage in a private window), the tab's vault unlock state in session storage, and
display choices (theme, skin, layout, sort order). Signing out removes the token, the account details
and the unlock state.

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
   defend legal claims; that is your decision): set `AUDIT_LOG_RETENTION_DAYS`, or delete rows in the
   database. For example, in the database container:

   ```sql
   -- Back up first. These deletions are not themselves audited.
   DELETE FROM audit_logs WHERE username = 'the-username';
   DELETE FROM security_alerts WHERE username = 'the-username';
   DELETE FROM security_records WHERE name = 'the-username';
   DELETE FROM account_invitations WHERE username = 'the-username';
   ```

   The same statements remove a name typed at sign-in that is no account. A name can also appear
   inside other rows' `details`; search them with `details::text LIKE '%the-username%'` before
   deciding.

There is no built-in per-person erasure yet.

## Retention settings

| Setting | Default | Governs |
|---|---|---|
| `AUDIT_LOG_RETENTION_DAYS` | `0` (keep for ever) | Audit rows: the deployment's maximum days, which the panel can change. |
| `AUDIT_MIN_RETENTION_DAYS` | `0` | Audit rows: none younger is deleted; the panel cannot go below it. |
| `AUDIT_PROTECTED_MIN_DAYS` | `365` | Administration and security audit rows: none younger is deleted by age; only `.env` lowers it. |
| `AUDIT_LOG_MAX_MB` | `0` (off) | Audit rows: a size cap; the oldest go first, never administration or security rows. |
| `PLAN_LOG_MAX_DAYS`, `PLAN_LOG_MAX_MB` | `-1` (none) | Ceilings on the audit log's maximum days and size cap. |
| `RETENTION_REDUCTION_DELAY_DAYS` | `7` | How long a change that deletes sooner waits; any administrator can cancel it meanwhile. |
| `RETENTION_HOLD` | `false` | When `true`, nothing deletes audit rows, security records or alerts, and the panel cannot turn the hold off. |
| `LOG_PRUNE_INTERVAL_MINUTES` | `15` | How often the pruner deletes old records. |
| `SECURITY_ALERT_RETENTION_DAYS` | `90` | Resolved security alerts. |
| `SECURITY_RECORD_DAYS` | `30` | Failed sign-ins kept in full, and the names and addresses in security alerts (between `SECURITY_RECORD_MIN_DAYS`, 7, and `SECURITY_RECORD_MAX_DAYS`, 365). |
| `ACCOUNT_LOCKOUT_MINUTES` | `15` | Automatic locks, and the phantom-name counters in Redis. |
| `RATE_LIMIT_LOGIN_WINDOW_SECONDS` | `300` | Sign-in counters. |
| `ENFORCE_FILE_EXPIRY` | `true` | Whether vault and upload-link expiry deletes files. |
| Per vault and per upload link | Off | How long files are kept. |
| Fixed | 30 days | Finished sessions and pending sign-ins. |
| Fixed | 14 days | Credential-change records, after the change is made or the request ends. |
| Fixed | About a day | Failed sign-in counts with no lock, after their last failure (database and cache). |
| Fixed | About a day | Resumable-upload sessions and an upload-link sender's address. |
| Fixed | About 15 MB | The log-access file. |

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
