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

The database and Redis are at 0.0.0.0. Some offline tests run code that tries the database or Redis
and carries on when it cannot reach them. At localhost, where nothing listens, Linux refuses at once,
but Windows tries each of localhost's two addresses for two seconds before giving up: four seconds for
each such try, and the offline lane makes dozens of them. Windows refuses 0.0.0.0 at once, as an
address no connection can use; Linux takes it for this host, as it took localhost.
"""
import base64
import os

_FERNET_KEY = base64.urlsafe_b64encode(b"0" * 32).decode()  # a valid, fixed, throwaway Fernet key


def set_bare_api_env():
    for key, value in {
        "DATABASE_URL": "postgresql://x:x@0.0.0.0:5432/x",
        "REDIS_URL": "redis://0.0.0.0:6379/0",
        "REDIS_HOST": "0.0.0.0",
        "SECRET_KEY": "t" * 32,
        "ENCRYPTION_KEY": _FERNET_KEY,
        "JWT_SECRET_KEY": "t" * 32,
    }.items():
        os.environ.setdefault(key, value)
