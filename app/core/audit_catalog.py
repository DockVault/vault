"""The audit log's action catalog: every action name the vault stores, with the category it is
filtered under, a label a person reads, and a severity.

Some events were stored under more than one spelling over the releases (`USER_UPDATED` and
`user_updated`, `file_upload` and `file_uploaded`). Each is one entry here, with the other spellings as
aliases, so a category filter and a label find every row of that event whichever spelling it has.

tests/test_audit_catalog.py fails when code starts storing a name that is not here, so a new event
has to be given a category and a label when it is added.
"""
from typing import Dict, Iterable, List, NamedTuple, Optional, Tuple

# (key, label), in the order the Activity page lists them.
CATEGORIES: Tuple[Tuple[str, str], ...] = (
    ("sign_in", "Sign-in and sessions"),
    ("accounts", "Accounts"),
    ("temp_credentials", "Temporary credentials"),
    ("files", "Files and folders"),
    ("notes", "Notes"),
    ("shares", "Internal shares"),
    ("public_links", "Public links"),
    ("upload_links", "Upload links"),
    ("vaults", "Vaults and access"),
    ("zero_knowledge", "Zero-knowledge keys"),
    ("devices", "Devices and sync"),
    ("administration", "Administration"),
    ("compliance", "Compliance access"),
    ("security", "Security and denials"),
)

SEVERITIES = ("info", "notice", "warning")

# The label for a stored name the catalog does not know: rows written by an older release.
LEGACY_LABEL = "Other (legacy)"


class AuditAction(NamedTuple):
    name: str
    category: str
    label: str
    severity: str
    aliases: Tuple[str, ...] = ()
    # The server writes the row on its own, with no person acting (the file-expiry sweep). Such a row
    # has no user, and the Activity page says the system did it rather than "Unknown".
    automatic: bool = False
    # The row's username may be a name someone typed, with no account (a failed sign-in): an account's
    # name on such a row with no account linked is expected, not an account row unlinked from its account.
    typed_name: bool = False


ACTIONS: Tuple[AuditAction, ...] = (
    # Sign-in and sessions
    # An automatic lock pauses new sign-ins from one address, or from every address; sessions carry on.
    # A row says which (ROW_LABELS); these are the labels the filters list.
    AuditAction("account_auto_locked", "sign_in", "New sign-ins paused after failed sign-ins", "warning"),
    AuditAction("account_auto_unlocked", "sign_in", "Sign-ins resumed", "info"),
    AuditAction("login_failure", "sign_in", "Sign-in failed", "warning", typed_name=True),
    AuditAction("login_password_ok", "sign_in", "Password accepted, second factor pending", "info"),
    AuditAction("login_success", "sign_in", "Signed in", "info"),
    # A user said they had read the notice of what this vault records, after a change (reading, not consent).
    AuditAction("privacy_notice_seen", "sign_in", "Recording notice read", "info"),
    AuditAction("logout", "sign_in", "Signed out", "info"),
    AuditAction("second_factor_action_updated", "sign_in", "Step-up requirement changed for an action", "notice"),
    AuditAction("second_factor_actions_bulk_updated", "sign_in", "Step-up requirements changed for several actions", "notice"),
    # By an administrator or by the server's operator on the host: the label names neither.
    AuditAction("second_factor_admin_reset", "sign_in", "Second factor reset for another user", "warning"),
    AuditAction("second_factor_disabled", "sign_in", "Second factor turned off", "notice"),
    AuditAction("second_factor_enrolled", "sign_in", "Second factor set up", "notice"),
    AuditAction("second_factor_failed", "sign_in", "Second-factor code rejected", "warning"),
    AuditAction("second_factor_recovery_regenerated", "sign_in", "Recovery codes replaced", "notice"),
    AuditAction("second_factor_recovery_used", "sign_in", "Signed in with a recovery code", "notice"),
    AuditAction("step_up_password_failed", "sign_in", "Password re-check refused", "warning"),
    AuditAction("terminate_session", "sign_in", "Session ended remotely", "notice"),
    # Accounts
    AuditAction("account_invitation_accept_failed", "accounts", "Invitation could not be accepted", "warning"),
    AuditAction("account_invitation_accepted", "accounts", "Account created from an invitation", "notice"),
    AuditAction("account_invitation_created", "accounts", "Invitation created", "notice"),
    AuditAction("account_invitation_revoked", "accounts", "Invitation revoked", "notice"),
    AuditAction("account_self_signup", "accounts", "Account created by sign-up", "notice"),
    AuditAction("account_self_signup_failed", "accounts", "Sign-up refused", "warning"),
    # A second change to someone's sign-in details within 14 days is held for another administrator's
    # approval. Short enough to read whole in a phone's row.
    AuditAction("credential_change_approval_refused", "accounts", "Approval refused (not independent)",
                "warning"),
    AuditAction("credential_change_approved", "accounts", "Held change approved", "notice"),
    AuditAction("credential_change_denied", "accounts", "Held change denied", "notice"),
    AuditAction("credential_change_expired", "accounts", "Held change expired", "info", automatic=True),
    AuditAction("credential_change_held", "accounts", "Sign-in change held for approval", "notice"),
    AuditAction("credential_change_refused", "accounts", "Sign-in change refused (no approver)", "warning"),
    AuditAction("credential_change_withdrawn", "accounts", "Held change withdrawn", "info"),
    AuditAction("email_change_confirmed", "accounts", "Email address changed", "notice"),
    AuditAction("email_change_requested", "accounts", "Email change requested", "info"),
    # An account whose password someone else set was made an administrator: the password was made
    # unusable and its sessions ended, and the person sets a new one with a reset link.
    AuditAction("password_reset_at_promotion", "accounts", "Password taken back at promotion", "notice"),
    AuditAction("password_reset_completed", "accounts", "Password changed with a reset link", "notice"),
    AuditAction("password_reset_link_minted", "accounts", "Password reset link created", "notice"),
    # An open link a user who manages users made for an account that has just been made an
    # administrator: revoked with the promotion (app/api/api_server.py).
    AuditAction("password_reset_link_revoked", "accounts", "Password reset link revoked", "notice"),
    AuditAction("password_reset_link_sent", "accounts", "Password reset link emailed", "notice"),
    AuditAction("password_reset_requested", "accounts", "Password reset requested", "info"),
    # A change of role resets the account's permissions to the new role's defaults: the row lists what
    # was removed and added (app/api/api_server.py, _set_role).
    AuditAction("permissions_reset_for_role", "accounts", "Permissions reset for a new role", "notice"),
    # A start gives an account a permission its role gained by default in a newer release, once.
    AuditAction("permission_default_granted", "accounts", "New role default permission granted", "notice",
                automatic=True),
    AuditAction("role_changed", "accounts", "User role changed", "notice"),
    AuditAction("self_account_update", "accounts", "Own account details changed", "notice"),
    AuditAction("ssh_key_add", "accounts", "SSH key added", "notice"),
    AuditAction("ssh_key_remove", "accounts", "SSH key removed", "notice"),
    # An administrator who added SSH keys to other people's accounts was demoted, deactivated, locked or
    # deleted: one row per account holding such keys, whose owner is told (the keys keep working).
    AuditAction("ssh_keys_adder_left", "accounts", "SSH keys reported: their adder left", "notice"),
    AuditAction("user_created", "accounts", "User created", "notice"),
    AuditAction("user_deleted", "accounts", "User deleted", "warning"),
    AuditAction("USER_LOCK_CHANGED", "accounts", "User locked or unlocked", "notice"),
    AuditAction("USER_STATUS_CHANGED", "accounts", "User activated or deactivated", "notice"),
    AuditAction("user_updated", "accounts", "User updated", "notice", ("USER_UPDATED",)),
    # Temporary credentials
    AuditAction("temp_credential_created", "temp_credentials", "Temporary credential created", "notice", ("TEMP_CREDENTIAL_CREATED",)),
    AuditAction("TEMP_CREDENTIAL_DEACTIVATED", "temp_credentials", "Temporary credential deactivated", "notice"),
    AuditAction("TEMP_CREDENTIAL_DELETED", "temp_credentials", "Temporary credential deleted", "warning"),
    AuditAction("temp_passcode_failed", "temp_credentials", "Vault passcode rejected", "warning"),
    AuditAction("temp_passcode_minted", "temp_credentials", "Vault passcode created", "notice"),
    AuditAction("temp_passcode_used", "temp_credentials", "Vault opened with a passcode", "info"),
    # Files and folders
    AuditAction("file_copy", "files", "File copied", "info"),
    AuditAction("file_delete", "files", "File deleted", "info", ("file_deleted",)),
    AuditAction("file_download", "files", "File download started", "info", ("file_downloaded",)),
    AuditAction("file_download_completed", "files", "File download finished", "info"),
    AuditAction("file_download_range", "files", "Part of a file downloaded", "info"),
    AuditAction("file_expired", "files", "File deleted at its expiry", "info", automatic=True),
    AuditAction("file_move", "files", "File moved", "info"),
    # A preview: the file's content sent to the browser to be shown there (the preview, the text window). It
    # discloses the content as a download does and is gated and counted as one; the record says which it was.
    AuditAction("file_previewed", "files", "File sent to the browser for a preview", "info"),
    AuditAction("file_preview_completed", "files", "File preview finished", "info"),
    AuditAction("file_preview_rendered", "files", "File preview shown", "info"),
    AuditAction("file_rename", "files", "File renamed", "info"),
    AuditAction("file_upload", "files", "File uploaded", "info", ("file_uploaded",)),
    AuditAction("folder_copy", "files", "Folder copied", "info"),
    AuditAction("folder_create", "files", "Folder created", "info"),
    AuditAction("folder_delete", "files", "Folder deleted", "info"),
    AuditAction("folder_move", "files", "Folder moved", "info"),
    AuditAction("folder_rename", "files", "Folder renamed", "info"),
    AuditAction("size_limit_violation", "files", "Upload stopped at the vault size limit", "warning"),
    AuditAction("transfer_cancelled", "files", "Transfer stopped", "info"),
    AuditAction("upload_session_cancelled", "files", "Upload cancelled", "info"),
    AuditAction("upload_sessions_cleanup", "files", "Unfinished uploads cleared", "info"),
    # Notes
    AuditAction("note_adopted", "notes", "Received note added to my notes", "info"),
    AuditAction("note_created", "notes", "Note created", "info"),
    AuditAction("note_deleted", "notes", "Note deleted", "notice"),
    AuditAction("note_updated", "notes", "Note edited", "info"),
    # Internal shares
    AuditAction("note_send", "shares", "Note sent to a member", "info"),
    AuditAction("permission_revoked", "shares", "Share recipient removed", "notice"),
    AuditAction("share_claimed", "shares", "Share accepted", "info"),
    AuditAction("share_created", "shares", "Share created", "notice"),
    AuditAction("share_downloaded", "shares", "Shared file downloaded", "info"),
    AuditAction("share_expired", "shares", "Share expired", "info"),
    AuditAction("share_opened", "shares", "Shared vault opened", "info"),
    AuditAction("share_revoked", "shares", "Share revoked", "notice"),
    # Public links
    AuditAction("note_link_admin_revoke", "public_links", "Note link revoked by an admin", "notice"),
    AuditAction("note_link_admin_revoke_all", "public_links", "All note links revoked by an admin", "warning"),
    AuditAction("note_link_create", "public_links", "Note link created", "notice"),
    AuditAction("note_link_delete", "public_links", "Note link deleted", "info"),
    AuditAction("note_link_redeem", "public_links", "Note link opened", "info"),
    AuditAction("note_link_revoke", "public_links", "Note link revoked", "info"),
    AuditAction("public_link_admin_revoke", "public_links", "Public link revoked by an admin", "notice"),
    AuditAction("public_link_admin_revoke_all", "public_links", "All public links revoked by an admin", "warning"),
    AuditAction("public_link_create", "public_links", "Public link created", "notice"),
    AuditAction("public_link_delete", "public_links", "Public link deleted", "info"),
    AuditAction("public_link_download", "public_links", "Public link download started", "info"),
    AuditAction("public_link_download_completed", "public_links", "Public link download finished", "info"),
    AuditAction("public_link_redeem", "public_links", "Public link opened", "info"),
    AuditAction("public_link_revoke", "public_links", "Public link revoked", "info"),
    # The server could not start a download it had granted (the stored file missing or unreadable, no
    # transfer slot free): the use the link's redeem spent was given back.
    AuditAction("public_link_use_refunded", "public_links", "Public link use given back after a failed download",
                "notice"),
    # Upload links
    AuditAction("receiver_admin_revoke", "upload_links", "Upload link revoked by an admin", "notice"),
    AuditAction("receiver_create", "upload_links", "Upload link created", "notice"),
    AuditAction("receiver_link_replaced", "upload_links", "Upload link address replaced", "notice"),
    AuditAction("receiver_pause", "upload_links", "Upload link paused", "info"),
    AuditAction("receiver_resume", "upload_links", "Upload link resumed", "info"),
    AuditAction("receiver_retention_changed", "upload_links", "Upload link retention changed", "notice"),
    AuditAction("receiver_revoke", "upload_links", "Upload link revoked", "info"),
    AuditAction("receiver_upload_complete", "upload_links", "File received through an upload link", "info"),
    AuditAction("receiver_upload_open", "upload_links", "Upload started through an upload link", "info"),
    # Vaults and access
    AuditAction("group_created", "vaults", "Department created", "notice"),
    AuditAction("group_deleted", "vaults", "Department deleted", "warning"),
    AuditAction("group_member_removed", "vaults", "Member removed from a department", "notice"),
    AuditAction("group_members_added", "vaults", "Members added to a department", "notice"),
    AuditAction("group_updated", "vaults", "Department changed", "notice"),
    AuditAction("permission_granted", "vaults", "User permission granted", "notice", ("GRANT_PERMISSION",)),
    AuditAction("REVOKE_PERMISSION", "vaults", "User permission removed", "notice"),
    AuditAction("vault_created", "vaults", "Vault created", "info"),
    AuditAction("vault_deleted", "vaults", "Vault deleted", "warning"),
    AuditAction("vault_group_access_granted", "vaults", "Department given vault access", "notice"),
    AuditAction("vault_group_access_revoked", "vaults", "Department's vault access removed", "notice"),
    AuditAction("vault_info_updated", "vaults", "Vault details updated", "info", ("vault_updated",)),
    AuditAction("vault_key_rotation", "vaults", "Vault key rotation refused", "warning"),
    AuditAction("vault_password_changed", "vaults", "Vault password changed", "notice"),
    AuditAction("vault_permission_granted", "vaults", "Vault access granted", "notice"),
    AuditAction("vault_permission_revoked", "vaults", "Vault access removed", "notice"),
    AuditAction("vault_storage_allocated", "vaults", "Vault storage allocation changed", "info"),
    AuditAction("vault_settings_updated", "vaults", "Vault settings changed", "notice"),
    # An administrator gave a vault's password to see its names on the Activity page (or gave a wrong one).
    AuditAction("activity_vault_unlocked", "vaults", "Vault names unlocked on the Activity page", "notice"),
    # Zero-knowledge keys
    AuditAction("zk_index_key_wrapped", "zero_knowledge", "Name-index key given to members", "notice"),
    # A member's app found that a key it was given, or the vault's key check, does not match the vault's key.
    AuditAction("zk_key_check_mismatch", "zero_knowledge", "Vault key did not match a member's check", "warning"),
    # A request to change a vault's keys whose proof that the caller holds the keys did not check out, and
    # one accepted without such a proof (only while the host operator has turned enforcement off).
    AuditAction("zk_key_proof_absent", "zero_knowledge", "Vault key changed without proof of the key", "warning"),
    AuditAction("zk_key_proof_bootstrapped", "zero_knowledge", "Vault key check set up", "notice"),
    AuditAction("zk_key_proof_failed", "zero_knowledge", "Vault key change refused: key not proven", "warning"),
    AuditAction("zk_key_update_pop_failed", "zero_knowledge", "Encryption key change refused", "warning"),
    # The hold on an account's encryption-key envelope after an administrator changed its sign-in details.
    AuditAction("zk_envelope_release_code_sent", "zero_knowledge", "Code to open the encryption key sent",
                "info"),
    AuditAction("zk_envelope_release_failed", "zero_knowledge", "Wrong code to open the encryption key",
                "warning"),
    AuditAction("zk_envelope_released", "zero_knowledge", "Encryption key released after a sign-in change",
                "notice"),
    AuditAction("zk_keypair_registered", "zero_knowledge", "Encryption keys set up", "notice"),
    AuditAction("zk_member_key_granted", "zero_knowledge", "Vault key given to a member", "notice"),
    AuditAction("zk_member_key_revoked", "zero_knowledge", "Member's vault keys removed", "notice"),
    AuditAction("zk_names_sealed", "zero_knowledge", "File names encrypted in the browser", "info"),
    # The owner replaced damaged key material with fresh material (a new epoch), without proving the old key.
    AuditAction("zk_owner_key_reset", "zero_knowledge", "Vault key reset by its owner", "warning"),
    AuditAction("zk_passphrase_changed", "zero_knowledge", "Encryption passphrase changed", "notice"),
    AuditAction("zk_share_invited", "zero_knowledge", "Zero-knowledge vault invite created", "notice"),
    AuditAction("zk_vault_rekeyed", "zero_knowledge", "Vault encryption key rotated", "notice"),
    AuditAction("zk_versions_retired", "zero_knowledge", "Old vault key versions retired", "notice"),
    # Devices and sync
    AuditAction("device_delete", "devices", "Device removed", "notice"),
    AuditAction("device_grant", "devices", "Device given access to a vault", "notice"),
    AuditAction("device_grant_revoke", "devices", "Device's access to a vault removed", "notice"),
    AuditAction("device_refresh", "devices", "Device key renewed", "info"),
    AuditAction("device_register", "devices", "Device added", "notice"),
    AuditAction("device_restore", "devices", "Suspended device restored", "notice"),
    AuditAction("device_revoke", "devices", "Device revoked", "notice"),
    AuditAction("device_sync_cred_mint", "devices", "Sync login issued to a device", "info"),
    # Administration
    AuditAction("audit_exported", "administration", "Audit log exported", "notice"),
    # A new version of the recording levels (app/core/audit_privacy.py): by an administrator, or by the server
    # bringing a level within a lowered .env limit (then the row has no account and says so).
    AuditAction("audit_privacy_changed", "administration", "Recording levels changed", "warning"),
    AuditAction("brand_asset_reset", "administration", "Logo or icon reset to default", "info"),
    AuditAction("brand_asset_uploaded", "administration", "Logo or icon uploaded", "info"),
    AuditAction("email_action_test_sent", "administration", "Test automatic email sent", "info"),
    AuditAction("email_action_updated", "administration", "Automatic email changed", "notice"),
    AuditAction("email_profile_created", "administration", "Email sending profile created", "notice"),
    AuditAction("email_profile_deleted", "administration", "Email sending profile deleted", "warning"),
    AuditAction("email_profile_test_sent", "administration", "Test email sent from a sending profile", "info"),
    AuditAction("email_profile_updated", "administration", "Email sending profile changed", "notice"),
    AuditAction("email_resource_deleted", "administration", "Email image deleted", "warning"),
    AuditAction("email_resource_uploaded", "administration", "Email image uploaded", "info"),
    AuditAction("email_template_created", "administration", "Email template created", "notice"),
    AuditAction("email_template_deleted", "administration", "Email template deleted", "warning"),
    AuditAction("email_template_sent", "administration", "Email sent from a template", "info"),
    AuditAction("email_template_updated", "administration", "Email template changed", "notice"),
    AuditAction("log_settings_updated", "administration", "Log access settings changed", "notice"),
    AuditAction("log_token_disabled", "administration", "Log access token disabled", "notice"),
    AuditAction("log_token_generated", "administration", "Log access token created", "notice"),
    AuditAction("note_link_tag_created", "administration", "Note-link tag created", "notice"),
    AuditAction("note_link_tag_deactivated", "administration", "Note-link tag deactivated", "notice"),
    AuditAction("note_link_tag_updated", "administration", "Note-link tag changed", "notice"),
    AuditAction("receiver_tag_created", "administration", "Upload-link tag created", "notice"),
    # The audit log's integrity chain (app/core/audit_integrity.py): a check found the log or its seals
    # changed (announced once per finding; the status itself is kept outside the database), rows that arrived
    # in an hour already sealed were sealed late, and an acknowledgment of such warnings.
    AuditAction("audit_integrity_failed", "security", "Audit log integrity check failed", "warning",
                automatic=True),
    AuditAction("audit_rows_sealed_late", "security", "Audit rows sealed late", "warning", automatic=True),
    AuditAction("audit_integrity_acknowledged", "administration", "Audit log integrity warning acknowledged",
                "notice"),
    # What the host's operator does to the chain (dockvault.py audit): the chain moved to another key, seals
    # after the head record accepted or discarded, a restored database or backup accepted, and a removal made
    # by a release without the chain sealed over.
    AuditAction("audit_chain_key_changed", "administration", "Audit log chain moved to another key", "warning"),
    AuditAction("audit_seals_accepted", "administration", "Audit log seals accepted by the host", "warning"),
    AuditAction("audit_seals_discarded", "administration", "Audit log seals discarded by the host", "warning"),
    AuditAction("audit_chain_restored", "administration", "Audit log restore accepted", "warning"),
    AuditAction("audit_removal_acknowledged", "administration", "Audit rows removed by an older release sealed over",
                "warning"),
    # The host's `audit unarchive` (app/core/audit_archive.py): an archived day put back as rows.
    AuditAction("audit_archive_restored", "administration", "Archived audit day restored as rows", "notice"),
    # The pruner (app/core/retention.py): one row per job that deleted something in a pass.
    AuditAction("retention_pruned", "administration", "Old records deleted", "info", automatic=True),
    # A per-person erase (app/core/person_erase.py): asked for, cancelled by any administrator, and completed by
    # the server once due. Each names the placeholder the erase writes, never the name it removes.
    AuditAction("person_erase_requested", "administration", "Erase of a person's records requested", "warning"),
    AuditAction("person_erase_cancelled", "administration", "Erase of a person's records cancelled", "notice"),
    AuditAction("person_erased", "administration", "A person's records erased", "warning", automatic=True),
    # A removal of values recorded under earlier recording levels (app/core/audit_value_removal.py): asked for,
    # cancelled by any administrator, and completed by the pruner.
    AuditAction("audit_values_removal_requested", "administration", "Removal of earlier recorded values requested",
                "warning"),
    AuditAction("audit_values_removal_cancelled", "administration", "Removal of earlier recorded values cancelled",
                "notice"),
    AuditAction("audit_values_removed", "administration", "Earlier recorded values removed", "warning",
                automatic=True),
    AuditAction("receiver_tag_deactivated", "administration", "Upload-link tag deactivated", "notice"),
    AuditAction("receiver_tag_updated", "administration", "Upload-link tag changed", "notice"),
    # A managed setting (app/core/settings_registry.py): the row carries the values before and after.
    AuditAction("setting_changed", "administration", "Managed setting changed", "notice"),
    # A change that deletes records sooner waits (app/core/setting_changes.py): asked for, cancelled by any
    # administrator (or kept at the value in force), and applied by the server once it is due.
    AuditAction("setting_change_applied", "administration", "Waiting setting change applied", "warning",
                automatic=True),
    AuditAction("setting_change_cancelled", "administration", "Waiting setting change cancelled", "notice"),
    AuditAction("setting_change_scheduled", "administration",
                "Setting change that deletes records sooner scheduled by the server", "warning", automatic=True),
    AuditAction("setting_change_requested", "administration", "Setting change that deletes records sooner requested",
                "warning"),
    AuditAction("settings_updated", "administration", "Settings changed", "notice"),
    AuditAction("share_tag_created", "administration", "Share tag created", "notice"),
    AuditAction("share_tag_deactivated", "administration", "Share tag deactivated", "notice"),
    AuditAction("share_tag_updated", "administration", "Share tag changed", "notice"),
    AuditAction("test_email_sent", "administration", "Test email sent", "info"),
    AuditAction("update_settings_updated", "administration", "Update check interval changed", "notice"),
    # Security and denials
    AuditAction("access_denied", "security", "Access denied", "warning"),
    # Someone who is not an administrator, given the permission to manage users, reaching for an
    # administrator's account (or one above their role): refused (app/core/account_authority.py).
    AuditAction("account_change_refused_role", "security", "Change to a higher role's account refused",
                "warning"),
    AuditAction("admin_access_denied", "security", "Admin-only action refused", "warning"),
    AuditAction("device_access_denied", "security", "Device management refused", "warning"),
    AuditAction("device_secret_reuse_revoke", "security", "Old device key reused, device revoked", "warning"),
    AuditAction("device_secret_reuse_suspend", "security", "Old device key reused, device suspended", "warning"),
    AuditAction("endpoint_permission_denied", "security", "Action refused for lack of permission", "warning"),
    AuditAction("id_scope_denied", "security", "File or folder outside the granted scope refused", "warning"),
    # A reset link someone made for another account, used when its maker could no longer make it (demoted,
    # deactivated, locked, deleted, the permission taken away, or the account made an administrator):
    # refused like an unknown link, and revoked (app/core/account_authority.py, link_refusal).
    AuditAction("password_reset_link_refused", "security", "Reset link refused: its maker may no longer make it",
                "warning"),
    AuditAction("security_alert_resolved", "security", "Security alert resolved", "notice"),
    AuditAction("vault_cap_denied", "security", "Vault action outside the credential's rights refused", "warning"),
    AuditAction("vault_scope_denied", "security", "Vault outside the granted scope refused", "warning"),
    AuditAction("vault_self_access_refused", "security", "Self-granted vault access refused", "warning"),

    # Compliance access: the auditor right, cases, what an auditor opens in one, legal holds, names revealed
    # outside a case, and the owner's notice. Rows carry ids, never names or the case's free text (which is
    # sealed in the compliance tables). The pruner keeps these rows at least COMPLIANCE_RECORD_MIN_DAYS, and
    # a case's rows while it is open or holds a vault (app/core/compliance_retention.py).
    AuditAction("auditor_grant_proposed", "compliance", "Auditor right proposed", "notice"),
    AuditAction("auditor_granted", "compliance", "Auditor right granted", "warning"),
    AuditAction("auditor_grant_rejected", "compliance", "Auditor right turned down", "notice"),
    AuditAction("auditor_grant_lapsed", "compliance", "Auditor right proposal lapsed", "info", automatic=True),
    AuditAction("auditor_grant_refused", "compliance", "Auditor right refused", "warning"),
    AuditAction("auditor_revoked", "compliance", "Auditor right revoked", "notice"),
    AuditAction("auditor_suspended", "compliance", "Auditor right suspended", "warning"),
    AuditAction("auditor_reconfirmed", "compliance", "Auditor right reconfirmed", "notice"),
    AuditAction("auditor_grant_expired", "compliance", "Auditor right expired", "info", automatic=True),
    AuditAction("auditor_events_viewed", "compliance", "Auditor viewed events", "info"),
    AuditAction("case_requested", "compliance", "Case requested", "notice"),
    AuditAction("case_approved", "compliance", "Case approved", "warning"),
    AuditAction("case_rejected", "compliance", "Case turned down", "notice"),
    AuditAction("case_withdrawn", "compliance", "Case withdrawn", "info"),
    AuditAction("case_extended", "compliance", "Case access extended", "warning"),
    AuditAction("case_suspended", "compliance", "Case suspended", "notice"),
    AuditAction("case_resumed", "compliance", "Case resumed", "notice"),
    AuditAction("case_closed", "compliance", "Case closed", "notice"),
    AuditAction("case_scope_narrowed", "compliance", "Case scope narrowed", "info"),
    AuditAction("case_expired_unapproved", "compliance", "Case expired before approval", "info", automatic=True),
    AuditAction("case_access_ended", "compliance", "Case access ended", "info", automatic=True),
    AuditAction("case_picker_viewed", "compliance", "Vaults listed for a case", "info"),
    AuditAction("case_objection_recorded", "compliance", "Objection recorded on a case", "notice"),
    AuditAction("case_folder_listed", "compliance", "Folder listed in a case", "info"),
    AuditAction("case_file_viewed", "compliance", "File opened in a case", "notice"),
    AuditAction("case_search", "compliance", "Searched in a case", "info"),
    AuditAction("case_names_viewed", "compliance", "Names shown for a case", "info"),
    AuditAction("case_vault_unlocked", "compliance", "Vault unlocked in a case", "notice"),
    AuditAction("case_export_started", "compliance", "Case export prepared", "notice"),
    AuditAction("case_export_completed", "compliance", "Case export fetched", "notice"),
    AuditAction("case_export_aborted", "compliance", "Case export stopped before its end", "warning"),
    AuditAction("case_access_refused", "compliance", "Case access refused", "warning"),
    AuditAction("hold_placed", "compliance", "Legal hold placed", "warning"),
    AuditAction("hold_confirmed", "compliance", "Legal hold confirmed", "notice"),
    AuditAction("hold_lapsed", "compliance", "Legal hold lapsed unconfirmed", "notice", automatic=True),
    AuditAction("hold_released", "compliance", "Legal hold released", "warning"),
    AuditAction("hold_release_undone", "compliance", "Legal hold release undone", "notice"),
    AuditAction("hold_reviewed", "compliance", "Legal hold reviewed", "info"),
    AuditAction("held_file_kept", "compliance", "Deleted file kept by a legal hold", "info"),
    AuditAction("held_file_purged", "compliance", "Kept file deleted after its hold", "info", automatic=True),
    AuditAction("hold_blocked_delete", "compliance", "Deletion refused under a legal hold", "warning"),
    AuditAction("audit_name_revealed", "compliance", "Recorded name revealed", "warning"),
    AuditAction("owner_notice_written", "compliance", "Owner told of compliance access", "info"),
    AuditAction("owner_notice_seen", "compliance", "Owner read the notices of compliance access", "info"),
    AuditAction("owner_access_unlocked", "compliance", "Owner unlocked a vault's names on Access to my vaults",
                "info"),
    AuditAction("owner_notice_email_sent", "compliance", "Owner notice emailed", "info", automatic=True),
    AuditAction("owner_notice_email_failed", "compliance", "Owner notice email failed", "warning", automatic=True),
)

_CATEGORY_LABELS: Dict[str, str] = dict(CATEGORIES)
_BY_STORED_NAME: Dict[str, AuditAction] = {}
for _a in ACTIONS:
    for _n in (_a.name,) + _a.aliases:
        _BY_STORED_NAME[_n] = _a


def lookup(stored_name: str) -> Optional[AuditAction]:
    """The catalog entry for a stored action name or one of its aliases, or None."""
    return _BY_STORED_NAME.get(stored_name)


def label_for(stored_name: str) -> str:
    """What the Activity page shows for a stored action name."""
    entry = lookup(stored_name)
    return entry.label if entry else LEGACY_LABEL


# Labels that depend on what a row recorded. An automatic lock and its end read by the lock's scope,
# in the Users page's words. A row written before 0.33.0 records no scope: its lock then held the whole
# account, so it keeps the words it had.
ROW_LABELS: Dict[str, Dict[Optional[str], str]] = {
    "account_auto_locked": {"address": "New sign-ins paused from one address",
                            "account": "New sign-ins paused from every address",
                            None: "Account locked after failed sign-ins"},
    "account_auto_unlocked": {"address": "Sign-ins resumed", "account": "Sign-ins resumed",
                              None: "Account unlocked when its lock ran out"},
}


def row_label(stored_name: str, details=None) -> str:
    """What the Activity page shows for one stored row: its entry's label, or the one for what the row
    recorded (ROW_LABELS)."""
    entry = lookup(stored_name)
    if entry is None:
        return LEGACY_LABEL
    by_scope = ROW_LABELS.get(entry.name)
    if not by_scope:
        return entry.label
    scope = details.get("scope") if isinstance(details, dict) else None
    return by_scope.get(scope if scope in by_scope else None)


def labels_of(entry: AuditAction) -> Tuple[str, ...]:
    """Every label an entry's rows can show: what a search for the page's words must match."""
    return (entry.label,) + tuple(v for v in ROW_LABELS.get(entry.name, {}).values() if v != entry.label)


def category_label(key: str) -> Optional[str]:
    return _CATEGORY_LABELS.get(key)


def stored_names(categories: Iterable[str]) -> List[str]:
    """Every stored spelling of every event in the given categories: what an `action IN (...)` filter
    needs so that rows written under an older spelling match too."""
    wanted = set(categories)
    out: List[str] = []
    for a in ACTIONS:
        if a.category in wanted:
            out.extend((a.name,) + a.aliases)
    return out
