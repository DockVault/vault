"""The settings of the Settings pages that the settings registry does not resolve: listed for the pages only.

Most of what an administrator changes in Settings is kept in the general settings store (PUT /settings) or
in a table of its own (tags, sending profiles, templates, log tokens), and SETTINGS_LOCKED_KEYS does not
cover it. Each such setting is a field of the registry (settings_registry.register_field) under the name
its page gives it (``data-setting`` in static/index.html), so that every setting on every page has a level
and the release it arrived in, like the registry's own settings, and the pages can sort, mark and search
them from one list. tests/test_settings_levels.py keeps this list and the pages' markup the same, both ways.

The level follows the registry's one rule: essential is what most administrators change in their first
month with the vault (naming and branding it, the upload size, storage, the password and second-factor
rules, sending email, and switching on sharing, links, invitations and password reset); everything else
is advanced.
"""
from __future__ import annotations

from app.core import settings_registry as registry

E, A = registry.ESSENTIAL, registry.ADVANCED

# (key, level, since) per page, in the order the page shows them.
FIELDS: dict[str, tuple] = {
    "general": (
        ("update_check_interval", A, "0.7.0"),
        ("app_name", E, "0.6.0"),
        ("app_description", A, "0.6.0"),
        ("max_file_size", E, "0.6.0"),
        ("allowed_file_types", A, "0.6.0"),
    ),
    "branding": (
        ("brand_full_name", E, "0.6.0"),
        ("brand_tagline", A, "0.6.0"),
        ("brand_company_name", E, "0.6.0"),
        ("brand_support_email", E, "0.6.0"),
        ("brand_copyright_holder", A, "0.6.0"),
        ("brand_company_url", A, "0.6.0"),
        ("brand_website_url", A, "0.6.0"),
        ("brand_docs_url", A, "0.6.0"),
        ("brand_primary_color", E, "0.6.0"),
        ("brand_secondary_color", A, "0.6.0"),
        ("brand_accent_color", A, "0.6.0"),
        ("brand_success_color", A, "0.6.0"),
        ("brand_warning_color", A, "0.6.0"),
        ("brand_error_color", A, "0.6.0"),
        ("brand_text_color", A, "0.6.0"),
        ("brand_background_color", A, "0.6.0"),
        ("brand_logo", E, "0.6.0"),
        ("brand_favicon", A, "0.6.0"),
    ),
    "security": (
        ("password_min_length", E, "0.6.0"),
        ("password_requirements", E, "0.6.0"),
        ("session_timeout", A, "0.6.0"),
        ("mfa_mode", E, "0.20.0"),
        ("mfa_sftp_policy", A, "0.20.0"),
        ("mfa_email_ttl", A, "0.20.0"),
        ("step_up_actions", A, "0.20.0"),
    ),
    "storage": (
        ("deployment_storage_limit", E, "0.11.0"),
        ("default_quota", E, "0.6.0"),
        ("max_vaults_per_user", A, "0.24.0"),
        ("max_vault_size", A, "0.6.0"),
    ),
    "email": (
        ("email_profiles", E, "0.14.0"),
        ("email_templates", A, "0.14.0"),
        ("email_actions", A, "0.14.0"),
    ),
    "sftp": (
        ("sftp_temp_credential_departments", A, "0.6.0"),
        ("directory_search_scope", A, "0.6.0"),
        ("zero_knowledge_enabled", E, "0.6.0"),
        ("force_zero_knowledge", A, "0.6.0"),
        ("zk_exempt_departments", A, "0.6.0"),
        ("zk_idle_lock_minutes", A, "0.6.0"),
        ("temp_passcodes_enabled", A, "0.6.0"),
        ("temp_passcode_one_time_default", A, "0.6.0"),
        ("temp_passcode_single_vault_only", A, "0.6.0"),
        ("temp_passcode_allow_custom", A, "0.6.0"),
        ("temp_passcode_min_length", A, "0.6.0"),
        ("max_temp_creds_per_user", A, "0.24.0"),
        ("temp_passcode_complexity", A, "0.6.0"),
        ("temp_passcode_max_lifetime", A, "0.6.0"),
        ("temp_cred_allow_zk_vaults", A, "0.6.0"),
        ("force_no_remember_vault_password", A, "0.6.0"),
    ),
    "sharing": (
        ("sharing_enabled", E, "0.6.0"),
        ("share_tags", A, "0.6.0"),
    ),
    "notelinks": (
        ("note_max_chars", A, "0.16.0"),
        ("public_note_links_enabled", E, "0.15.0"),
        ("public_note_link_user_cap", A, "0.15.0"),
        ("public_file_links_enabled", E, "0.23.0"),
        ("link_tags", A, "0.15.0"),
    ),
    "uploadlinks": (
        ("public_receivers_enabled", E, "0.23.0"),
        ("public_receiver_user_cap", A, "0.23.0"),
        ("receiver_tags", A, "0.23.0"),
    ),
    "accounts": (
        ("invite_enabled", E, "0.13.0"),
        ("signup_enabled", A, "0.13.0"),
        ("invite_ttl_hours", A, "0.13.0"),
        ("signup_domain_mode", A, "0.13.0"),
        ("signup_domains", A, "0.13.0"),
        ("email_requirement", A, "0.13.0"),
        ("login_identifier", A, "0.13.0"),
        ("email_change_verification", A, "0.13.0"),
        ("email_change_code_lifetime", A, "0.16.0"),
        ("password_reset_enabled", E, "0.16.0"),
        ("password_reset_link_lifetime", A, "0.16.0"),
    ),
    "logs": (
        ("log_components", A, "0.6.0"),
        ("log_hide_endpoint", A, "0.6.0"),
        ("log_tokens", A, "0.6.0"),
    ),
    "records": (
        ("recording_notice", A, "0.34.0"),
    ),
}


def _register() -> None:
    for page, fields in FIELDS.items():
        for key, level, since in fields:
            if key not in registry._FIELDS:
                registry.register_field(key, page=page, level=level, since=since)


_register()
