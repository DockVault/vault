"""Explicit, import-safe runtime bootstrap contracts."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.unit
FERNET_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
JWT_SECRET = "j" * 64
SECRET_ENV_NAMES = {
    "ADMIN_PASSWORD",
    "DATABASE_URL",
    "ENCRYPTION_KEY",
    "JWT_ALGORITHM",
    "JWT_SECRET_KEY",
    "MASTER_KEY_SALT",
    "MASTER_PASSWORD_HASH",
    "REDIS_PASSWORD",
    "ENCRYPTED_ADMIN_PASSWORD",
    "ENCRYPTED_DATABASE_URL",
    "ENCRYPTED_ENCRYPTION_KEY",
    "ENCRYPTED_JWT_SECRET_KEY",
    "ENCRYPTED_REDIS_PASSWORD",
}


def _clean_env():
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in SECRET_ENV_NAMES and key != "DOCKER_CONTAINER"
    }
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _runtime_env(tmp_path):
    env = _clean_env()
    env.update(
        {
            "ADMIN_PASSWORD": "",
            "DATABASE_URL": "postgresql://user:pass@127.0.0.1:5432/vault",
            "ENCRYPTION_KEY": FERNET_KEY,
            "ENVIRONMENT": "production",
            "FILE_STORAGE_PATH": str(tmp_path / "storage"),
            "JWT_ALGORITHM": "HS256",
            "JWT_SECRET_KEY": JWT_SECRET,
            "LOG_FILE_PATH": str(tmp_path / "logs" / "server.log"),
            "SFTP_HOST_KEY_PATH": str(tmp_path / "keys" / "ssh_host_rsa_key"),
        }
    )
    return env


def _run(script, tmp_path, env=None):
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env or _clean_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
    )


def test_core_imports_are_silent_and_side_effect_free(tmp_path):
    # A hostile cwd dotenv proves model construction does not implicitly read it.
    (tmp_path / ".env").write_text(
        "JWT_SECRET_KEY=dotenv-must-not-be-read-during-import\n",
        encoding="utf-8",
    )
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    script = """
import app.core.config as config
import app.core.startup_security
import app.core.models
import app.core.security
import app.core.database
assert config.settings.jwt_secret_key == ""
assert config.settings.redis_port == 6379
assert config.runtime_is_initialized() is False
"""
    env = _clean_env()
    env["REDIS_PORT"] = "not-a-number"
    proc = _run(script, tmp_path, env)
    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""
    assert after == before


def test_host_dotenv_load_is_explicit_and_process_environment_wins(tmp_path):
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "\n".join(
            [
                "API_PORT=8111",
                "DATABASE_URL=postgresql://file:file@127.0.0.1:5432/filedb",
                f"ENCRYPTION_KEY={FERNET_KEY}",
                f"JWT_SECRET_KEY={JWT_SECRET}",
                f"FILE_STORAGE_PATH={tmp_path / 'storage'}",
                f"LOG_FILE_PATH={tmp_path / 'logs' / 'server.log'}",
                f"SFTP_HOST_KEY_PATH={tmp_path / 'keys' / 'host'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    env = _clean_env()
    env["API_PORT"] = "9191"
    script = """
from pathlib import Path
import app.core.config as config
config._is_container_runtime = lambda: False
s = config.initialize_runtime(interactive=False)
assert s.api_port == 9191
assert s.database_url.startswith("postgresql://file:file@")
assert Path(s.file_storage_path).is_dir()
assert Path(s.log_file_path).parent.is_dir()
assert Path(s.sftp_host_key_path).parent.is_dir()
"""
    proc = _run(script, tmp_path, env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_asgi_import_bootstraps_dotenv_before_app_construction(tmp_path):
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "ALLOWED_HOSTS=vault.example",
                "DATABASE_URL=postgresql://file:file@127.0.0.1:5432/filedb",
                f"ENCRYPTION_KEY={FERNET_KEY}",
                "ENVIRONMENT=development",
                f"JWT_SECRET_KEY={JWT_SECRET}",
                "RATE_LIMIT_API_DEFAULT=7",
                f"FILE_STORAGE_PATH={tmp_path / 'storage'}",
                f"LOG_FILE_PATH={tmp_path / 'logs' / 'server.log'}",
                f"SFTP_HOST_KEY_PATH={tmp_path / 'keys' / 'host'}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    script = """
from app.api import api_server

assert api_server.settings.allowed_hosts == "vault.example"
assert api_server.app.docs_url == "/docs"
middleware = {item.cls.__name__: item for item in api_server.app.user_middleware}
assert middleware["TrustedHostMiddleware"].kwargs["allowed_hosts"] == [
    "vault.example",
    "localhost",
    "127.0.0.1",
]
assert middleware["RateLimitMiddleware"].kwargs["default_limit"] == 7
"""
    proc = _run(script, tmp_path, _clean_env())
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_plaintext_runtime_initializes_once(tmp_path):
    script = """
from pathlib import Path
from app.core.config import initialize_runtime, runtime_is_initialized
first = initialize_runtime(interactive=False)
second = initialize_runtime(interactive=False)
assert first is second
assert runtime_is_initialized() is True
assert Path(first.file_storage_path).is_dir()
"""
    proc = _run(script, tmp_path, _runtime_env(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_encrypted_runtime_initializes_without_plaintext_secret_env(tmp_path):
    script = f"""
import os
import bcrypt
from cryptography.fernet import Fernet
from app.core.startup_security import (
    CredentialManager,
    bcrypt_password_bytes,
)

password = "correct horse battery staple"
salt = "runtime-bootstrap-salt"
manager = CredentialManager()
wrapper = Fernet(manager.derive_key_from_password(password, salt))
values = {{
    "ENCRYPTION_KEY": {FERNET_KEY!r},
    "DATABASE_URL": "postgresql://enc:enc@127.0.0.1:5432/vault",
    "REDIS_PASSWORD": "",
    "JWT_SECRET_KEY": {JWT_SECRET!r},
    "ADMIN_PASSWORD": "Strong-Admin-Password-27",
}}
os.environ["MASTER_PASSWORD_HASH"] = bcrypt.hashpw(
    bcrypt_password_bytes(password), bcrypt.gensalt()
).decode()
os.environ["MASTER_KEY_SALT"] = salt
for name, value in values.items():
    os.environ["ENCRYPTED_" + name] = wrapper.encrypt(value.encode()).decode()

from app.core.config import initialize_runtime
active = initialize_runtime(master_password=password, interactive=False)
assert active.database_url == values["DATABASE_URL"]
assert active.encryption_key == values["ENCRYPTION_KEY"]
assert active.jwt_secret_key == values["JWT_SECRET_KEY"]
assert "DATABASE_URL" not in os.environ
"""
    env = _clean_env()
    env.update(
        {
            "FILE_STORAGE_PATH": str(tmp_path / "storage"),
            "LOG_FILE_PATH": str(tmp_path / "logs" / "server.log"),
            "SFTP_HOST_KEY_PATH": str(tmp_path / "keys" / "host"),
        }
    )
    proc = _run(script, tmp_path, env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


@pytest.mark.parametrize(
    ("env_change", "expected_code", "sentinel"),
    [
        ({"DATABASE_URL": None}, "required-secret-missing", "postgresql://"),
        ({"JWT_SECRET_KEY": "weak-jwt-sentinel"}, "jwt-secret-weak", "weak-jwt-sentinel"),
        ({"JWT_ALGORITHM": "RS256"}, "jwt-algorithm-invalid", "RS256"),
        (
            {"ADMIN_PASSWORD": "weakpass"},
            "admin-bootstrap-password-weak",
            "weakpass",
        ),
    ],
)
def test_entrypoint_fatal_conditions_are_nonzero_and_sanitized(
    tmp_path, env_change, expected_code, sentinel
):
    env = _runtime_env(tmp_path)
    for key, value in env_change.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    proc = _run(
        "from app.core.config import bootstrap_entrypoint; "
        "bootstrap_entrypoint('api')",
        tmp_path,
        env,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert expected_code in proc.stderr
    assert sentinel not in output
    assert "Traceback" not in output


def test_bad_encrypted_credentials_fail_without_secret_output(tmp_path):
    script = """
import os
import bcrypt
from app.core.startup_security import bcrypt_password_bytes

password = "encrypted-store-password-sentinel"
os.environ["MASTER_PASSWORD_HASH"] = bcrypt.hashpw(
    bcrypt_password_bytes(password), bcrypt.gensalt()
).decode()
os.environ["MASTER_KEY_SALT"] = "salt-sentinel"
for name in (
    "ENCRYPTION_KEY",
    "DATABASE_URL",
    "REDIS_PASSWORD",
    "JWT_SECRET_KEY",
    "ADMIN_PASSWORD",
):
    os.environ["ENCRYPTED_" + name] = "ciphertext-sentinel-" + name

from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("api", master_password=password)
"""
    proc = _run(script, tmp_path, _clean_env())
    output = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "credential-decryption-failed" in proc.stderr
    for secret_fragment in (
        "encrypted-store-password-sentinel",
        "salt-sentinel",
        "ciphertext-sentinel",
    ):
        assert secret_fragment not in output
    assert "Traceback" not in output


def test_database_and_cache_consumers_construct_exactly_once(tmp_path):
    script = """
from app.core.config import runtime_is_initialized
import app.core.database as database
assert runtime_is_initialized() is False

calls = {"engine": 0, "session": 0, "redis": 0}
class Engine:
    def dispose(self):
        pass
class Cache:
    pass
def make_engine(*args, **kwargs):
    calls["engine"] += 1
    return Engine()
def make_session(*args, **kwargs):
    calls["session"] += 1
    return object()
def make_cache(*args, **kwargs):
    calls["redis"] += 1
    return Cache()

database.create_engine = make_engine
database.sessionmaker = make_session
database.redis.Redis = make_cache
database.initialize_consumers()
database.initialize_consumers()
assert calls == {"engine": 1, "session": 1, "redis": 1}
assert runtime_is_initialized() is True
"""
    proc = _run(script, tmp_path, _runtime_env(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_crypto_operation_initializes_runtime_on_demand(tmp_path):
    script = """
from app.core.config import runtime_is_initialized
from app.core.security import decrypt_file_content, encrypt_file_content

assert runtime_is_initialized() is False
ciphertext = encrypt_file_content(b"maintenance-helper")
assert runtime_is_initialized() is True
assert decrypt_file_content(ciphertext) == b"maintenance-helper"
"""
    proc = _run(script, tmp_path, _runtime_env(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert proc.stderr == ""


def test_split_and_combined_launch_paths_use_bootstrapped_server_modules():
    api = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    sftp = (ROOT / "app" / "sftp" / "sftp_server.py").read_text(encoding="utf-8")
    for source, component, database_import in (
        (api, 'bootstrap_entrypoint("API")', "from app.core.database import"),
        (sftp, 'bootstrap_entrypoint("SFTP")', "from app.core.database import"),
    ):
        assert component in source
        assert source.index(component) < source.index(database_import)

    combined = (ROOT / "run_combined.py").read_text(encoding="utf-8")
    assert '_spawn("app.api.api_server", "web")' in combined
    assert '_spawn("app.sftp.sftp_server", "sftp")' in combined

    for compose_name in ("docker-compose.yml", "docker-compose.secure.yml"):
        compose = (ROOT / "deploy" / compose_name).read_text(encoding="utf-8")
        assert '["python", "-m", "app.api.api_server"]' in compose
        assert '["python", "-m", "app.sftp.sftp_server"]' in compose
