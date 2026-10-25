"""The tables, and their columns, that the models of 0.33.5 declare (app/core/models.py at the v0.33.5 tag), for
test_upgrade_schema_divergence.py. Holds no tests.

An install upgraded from 0.33.5 has these tables already, so create_all builds none of them again: a column a later
model declares on one of them reaches that install only through an ADD COLUMN of the start's statements. A table
that is not listed here is new since 0.33.5, and create_all builds it with every column. The list is what 0.33.5
shipped and does not change; test_the_older_schema_listed_is_0_33_5s checks it against the tag when the checkout
has it.
"""

TABLES = {
    "account_invitations": (
        "accepted_at", "accepted_user_id", "created_at", "created_by", "email", "expires_at", "id", "inviter_lineage",
        "revoked_at", "role", "token_hash", "token_prefix", "username"),
    "active_sessions": (
        "channel", "expires_at", "id", "ip_address", "is_active", "last_activity", "revoked", "session_token",
        "started_at", "temp_credential_id", "user_id"),
    "activity_saved_searches": ("created_at", "filters", "id", "is_default", "name", "updated_at", "user_id"),
    "admin_grants": ("granted_at", "granted_by_id", "granted_by_name", "lineage", "user_id"),
    "audit_logs": (
        "action", "channel", "details", "endpoint", "error_message", "id", "ip_address", "method", "resource_id",
        "resource_type", "status", "temp_credential_id", "temp_credential_name", "timestamp", "user_agent", "user_id",
        "username"),
    "chunked_upload_sessions": (
        "blob_id", "bytes_received", "chunks_received", "client_object_id", "completed_at", "created_at", "enc_mime",
        "enc_name", "error_message", "expires_at", "file_id", "filename", "folder_id", "id", "last_chunk_at",
        "mime_type", "name_bi", "name_bi_candidates", "status", "temp_credential_id", "temp_file_path",
        "total_chunks", "total_size", "user_id", "vault_id", "zk_key_version"),
    "credential_changes": (
        "applied_at", "approval_snapshot", "decided_at", "decided_by_id", "decided_by_name", "expires_at", "id",
        "kind", "payload", "requested_at", "requested_by_id", "requested_by_name", "status", "summary",
        "target_user_id"),
    "data_requirements": ("key", "reason", "requires_at_least", "since", "undo"),
    "device_grants": (
        "device_id", "granted_at", "granted_by_user_id", "id", "is_active", "vault_id", "vault_password_fingerprint"),
    "devices": (
        "created_at", "epoch", "expires_at", "id", "is_active", "label", "last_seen", "prev_secret_hash",
        "prev_secret_retired_at", "secret_hash", "suspended", "user_id"),
    "ecc_key_update_challenges": ("created_at", "id", "nonce", "server_private_key", "user_id"),
    "ecc_registration_challenges": ("created_at", "id", "nonce", "server_private_key", "user_id"),
    "email_actions": ("category", "description", "enabled", "key", "name", "template_id", "updated_at"),
    "email_change_codes": ("code_hash", "consumed_at", "created_at", "expires_at", "id", "new_email", "user_id"),
    "email_profiles": (
        "created_at", "description", "from_email", "from_name", "id", "is_default", "name", "smtp_allow_insecure_tls",
        "smtp_password", "smtp_port", "smtp_server", "smtp_username", "updated_at"),
    "email_resources": ("byte_size", "content_type", "created_at", "data", "filename", "id", "sha256", "uploaded_by"),
    "email_templates": (
        "body_html", "created_at", "created_by", "default_key", "description", "id", "name", "profile_id", "subject",
        "updated_at", "updated_by"),
    "files": (
        "checksum_sha256", "content_mac", "created_at", "enc_checksum", "enc_mime", "enc_name", "encryption_metadata",
        "expires_at", "folder_id", "id", "is_encrypted", "mime_type", "modified_by", "name", "name_bi",
        "original_name", "password_hash", "size_bytes", "storage_path", "updated_at", "uploaded_by", "vault_id"),
    "folders": (
        "created_at", "created_by", "enc_name", "id", "name", "name_bi", "name_key_version", "parent_folder_id",
        "password_hash", "updated_at", "vault_id"),
    "groups": ("color", "created_at", "created_by", "description", "id", "name", "parent_id", "updated_at"),
    "log_pull_tokens": (
        "created_at", "created_by", "disabled", "id", "last_used_at", "name", "scope", "token_hash", "token_prefix"),
    "note_link_tags": (
        "allowed_department_ids", "allowed_targets", "allowed_user_ids", "auto_enroll_new_users", "blocked_user_ids",
        "border_color", "created_at", "created_by", "default_ttl_hours", "description", "icon", "id", "is_active",
        "max_ttl_hours", "max_uses_cap", "min_pin_len", "min_token_len", "name", "password_min_len",
        "password_require_alnum", "require_secret", "updated_at"),
    "note_public_links": (
        "body_snapshot", "created_at", "expires_at", "id", "last_viewed_at", "max_uses", "owner_id", "password_hash",
        "revoked", "secret_kind", "tag_id", "title_snapshot", "token", "token_enc", "token_hash", "token_len",
        "use_count", "view_count"),
    "notes": (
        "adopted", "body", "created_at", "id", "is_favorite", "owner_id", "sent_from_name", "sent_from_user_id",
        "title", "updated_at"),
    "notifications": (
        "body", "created_at", "dedup_key", "id", "is_read", "read_at", "target", "title", "type", "user_id"),
    "otp_codes": (
        "attempts", "code_hash", "consumed_at", "created_at", "destination", "expires_at", "id", "max_attempts",
        "purpose", "user_id"),
    "password_reset_tokens": (
        "consumed_at", "created_at", "created_by", "expires_at", "id", "made_by_other", "token_hash", "token_prefix",
        "user_id"),
    "pending_logins": (
        "attempts", "client_ip", "consumed_at", "created_at", "enrollment_required", "expires_at", "id", "user_id"),
    "public_links": (
        "bytes_served", "created_at", "download_count", "expires_at", "id", "last_used_at", "max_uses", "owner_id",
        "password_hash", "revoked", "secret_kind", "tag_id", "target_file_id", "target_folder_id", "target_type",
        "token_enc", "token_hash", "token_len", "use_count", "vault_id"),
    "rate_limit_records": ("action", "attempt_count", "id", "identifier", "last_attempt", "window_start"),
    "receiver_tags": (
        "allowed_department_ids", "allowed_user_ids", "auto_enroll_new_users", "blocked_user_ids", "border_color",
        "created_at", "created_by", "default_ttl_hours", "description", "icon", "id", "is_active", "kind_floor",
        "max_file_bytes_cap", "max_total_bytes_cap", "max_ttl_hours", "max_uploads_cap", "min_pin_len",
        "min_token_len", "name", "password_min_len", "password_require_alnum", "require_secret",
        "retention_default_days", "retention_max_days", "updated_at"),
    "receiver_upload_sessions": ("client_ip", "created_at", "receiver_id", "secret_hash", "session_id"),
    "receivers": (
        "created_at", "envelope", "expires_at", "id", "kind", "label", "last_upload_at", "max_file_bytes",
        "max_total_bytes", "max_uploads", "owner_id", "password_hash", "paused", "reserved_bytes", "retention_days",
        "revoked", "secret_kind", "tag_id", "token_hash", "token_len", "upload_count", "vault_id"),
    "retired_object_ids": ("id", "kind", "spent_at", "vault_id"),
    "schema_steps": ("app_version", "detail", "outcome", "recorded_at", "step_id", "summary"),
    "second_factor_actions": ("key", "require_otp", "require_password", "updated_at"),
    "second_factor_enrollments": (
        "confirmed_at", "created_at", "id", "last_used_at", "last_used_step", "method", "secret_enc", "status",
        "user_id"),
    "second_factor_recovery_codes": ("code_hash", "code_prefix", "consumed_at", "created_at", "id", "user_id"),
    "security_alerts": (
        "details", "event_type", "id", "ip_address", "message", "resolution_notes", "resolved", "resolved_at",
        "resolved_by", "severity", "timestamp", "user_id", "username"),
    "share_claims": ("claimed_at", "download_count", "id", "last_access_at", "revoked", "share_id", "user_id"),
    "share_tags": (
        "allow_custom", "allow_view_only", "allowed_audiences", "allowed_department_ids", "allowed_user_ids",
        "auto_enroll_new_users", "blocked_user_ids", "color", "created_at", "created_by", "default_lifetime_minutes",
        "default_view_only", "description", "force_view_only", "id", "is_active", "max_downloads_cap",
        "max_downloads_default", "max_lifetime_minutes", "max_recipients_cap", "max_recipients_default", "name",
        "updated_at"),
    "shares": (
        "audience_department_ids", "audience_user_ids", "claim_audience", "created_at", "creator_id", "expires_at",
        "id", "link_token_hash", "max_downloads", "max_recipients", "revoked_at", "revoked_by", "status", "tag_id",
        "tag_policy_snapshot", "target_file_id", "target_folder_id", "target_type", "vault_id", "view_only"),
    "sign_in_lockouts": (
        "failed_attempts", "id", "last_failure_at", "locked_at", "locked_until", "source", "user_id", "window_start"),
    "system_settings": ("key", "updated_at", "value"),
    "temp_credential_vault_access": (
        "created_at", "created_by", "id", "passcode_expires_at", "passcode_hash", "passcode_kind",
        "passcode_max_uses", "passcode_use_count", "scope_ids", "temp_credential_id", "vault_caps", "vault_id",
        "vault_password_fingerprint"),
    "temporary_credentials": (
        "can_create_temp_credentials", "created_at", "created_by_temp_credential_id", "credential_hash",
        "deactivate_at", "device_id", "expires_at", "id", "is_active", "is_used", "note", "password_shown", "scope",
        "slot_released_at", "temp_username", "used_at", "user_id", "vault_access_mode"),
    "user_endpoint_permissions": ("endpoint_group", "granted_at", "granted_by", "id", "user_id"),
    "user_groups": ("added_at", "added_by", "group_id", "group_role", "user_id"),
    "user_keypairs": (
        "created_at", "curve", "encrypted_private_key", "fingerprint", "id", "last_used", "previous_public_key",
        "public_key", "updated_at", "user_id", "version"),
    "user_permissions": ("granted_at", "granted_by", "permission", "user_id"),
    "user_preferences": ("preferences", "updated_at", "user_id"),
    "user_ssh_keys": (
        "created_at", "created_by", "fingerprint", "id", "key_type", "last_used", "name", "public_key", "user_id"),
    "users": (
        "created_at", "created_by", "email", "failed_login_attempts", "id", "is_active", "is_locked", "last_login",
        "locked_until", "password_hash", "permission_defaults_revision", "role", "second_factor_reset_at",
        "sftp_enabled", "sftp_password_auth", "storage_quota_bytes", "updated_at", "username"),
    "vault_favorites": ("created_at", "user_id", "vault_id"),
    "vault_group_access": ("added_at", "added_by", "group_id", "permission", "vault_id"),
    "vault_key_history": (
        "created_at", "encrypted_key", "id", "key_encryption_metadata", "key_salt", "key_version", "retired_at",
        "vault_id"),
    "vault_key_proofs": (
        "created_at", "created_by", "dek_check", "dek_epoch", "format", "id", "lineage_tag", "proof_public_key",
        "sealed_private_key", "source", "vault_id"),
    "vault_member_index_keys": (
        "encrypted_index_key", "ephemeral_public_key", "granted_at", "granted_by", "id", "index_key_version",
        "is_active", "revoked_at", "revoked_by", "user_id", "vault_id", "wrapping_algorithm"),
    "vault_member_keys": (
        "encrypted_dek", "ephemeral_public_key", "granted_at", "granted_by", "id", "is_active", "key_version",
        "revoked_at", "revoked_by", "user_id", "vault_id", "wrapping_algorithm"),
    "vault_members": (
        "added_at", "added_by", "delete_permission", "manage_permission", "read_permission", "user_id", "vault_id",
        "write_permission"),
    "vault_storage_grants": ("created_at", "granted_bytes", "id", "updated_at", "user_id", "vault_id"),
    "vault_views": ("user_id", "vault_id", "viewed_at"),
    "vaults": (
        "created_at", "dek_version", "description", "enc_description", "enc_name", "encrypted_vault_key",
        "expire_files_after_days", "expire_files_unit", "file_count", "id", "is_active", "key_created_at",
        "key_encryption_metadata", "key_salt", "key_version", "key_wrapping_mode", "last_accessed", "member_keys",
        "name", "name_key_version", "owner_id", "password_hash", "size_limit", "team_key", "team_key_version",
        "team_public_key", "total_size_bytes", "type", "unlock_remember_minutes", "updated_at"),
    "zk_key_proof_challenges": (
        "created_at", "dek_epoch", "id", "mode", "nonce", "op", "server_private_key_sealed", "team_epoch", "user_id",
        "vault_id", "verifier_sha256"),
    "zk_share_invites": ("created_at", "id", "invited_by", "target_user_id", "vault_id"),
}
