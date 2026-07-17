"""Pure helpers for the admin upload-policy settings (allowed file types, max file size).

No app imports, so they unit-test in isolation and are shared by both the web upload paths
(app/api/api_server.py) and the SFTP write path (app/sftp/sftp_server.py). Callers read the raw
values out of the SystemSetting('global') blob and pass them in.
"""


def parse_allowed_exts(raw):
    """The stored allowed_file_types value -> a set of lowercased, dot-stripped extensions, or None
    (no restriction). A non-list, or an empty/all-blank list, means 'allow everything'."""
    if not isinstance(raw, (list, tuple)):
        return None
    out = {e.strip().lstrip(".").lower() for e in raw if isinstance(e, str) and e.strip()}
    return out or None


def file_ext(name):
    """The lowercased extension of a filename (no leading dot), or '' when there is none."""
    return name.rsplit(".", 1)[-1].lower() if (name and "." in name) else ""


def file_type_allowed(name, allowed_exts):
    """True when allowed_exts is None (no restriction) or the file's extension is in the set. An
    extension-less name is allowed only if '' is explicitly in the set."""
    return allowed_exts is None or file_ext(name) in allowed_exts


def effective_max_file_bytes(env_bytes, stored_mb):
    """Per-file upload ceiling in bytes: the admin 'max file size' (MB) clamped to the deployment
    env cap `env_bytes` — the UI can only LOWER the limit, never raise the hard ceiling. Falls back
    to `env_bytes` when the stored value is unset / non-positive / unparseable."""
    try:
        mb = float(stored_mb)
    except (TypeError, ValueError):
        return env_bytes
    if mb <= 0:
        return env_bytes
    return min(env_bytes, int(mb * 1024 * 1024))
