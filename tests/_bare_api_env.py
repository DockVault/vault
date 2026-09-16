"""Set the minimal environment the API bootstrap requires, so a unit module that imports
app.api.api_server passes when run ALONE — CI runs each unit module on its own with no .env.

Importing app.api.api_server runs bootstrap_entrypoint("API"), whose _validate_runtime_settings
requires DATABASE_URL, a valid Fernet ENCRYPTION_KEY, and JWT_SECRET_KEY; without a complete set the
import fails closed with SystemExit. In the full lane an alphabetically earlier module has already set
a complete set, so a per-module block that set only SECRET_KEY passed there but died alone. This one
helper sets the complete minimal set (dummy but well-formed) so every consumer is self-sufficient.

setdefault only, so a real deployment environment — or an earlier module — is never overridden. The
ENCRYPTION_KEY is a fixed, well-formed Fernet key (32 url-safe-base64 bytes); it decrypts nothing real,
it only lets the bootstrap's validation pass.
"""
import base64
import os

_FERNET_KEY = base64.urlsafe_b64encode(b"0" * 32).decode()  # a valid, fixed, throwaway Fernet key


def set_bare_api_env():
    for key, value in {
        "DATABASE_URL": "postgresql://x:x@localhost:5432/x",
        "REDIS_URL": "redis://localhost:6379/0",
        "SECRET_KEY": "t" * 32,
        "ENCRYPTION_KEY": _FERNET_KEY,
        "JWT_SECRET_KEY": "t" * 32,
    }.items():
        os.environ.setdefault(key, value)
