"""
Configuration management for the secure SFTP server.
Handles loading and validating environment variables.
"""
import os
import sys
import threading
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, ValidationError, validator
from dotenv import load_dotenv
from cryptography.fernet import Fernet

from app.core.startup_security import CredentialUnlockError, credential_manager


class RuntimeBootstrapError(RuntimeError):
    """Typed startup failure whose text is always safe for operator logs."""

    def __init__(self, code: str, safe_message: str):
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


def _credential_default(name: str, default=None):
    """Read an unlocked credential without making Settings import-time active."""
    if not credential_manager.is_unlocked:
        return default
    return credential_manager.get(name) or default


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        # Host entrypoints load one explicit cwd .env before constructing runtime
        # settings. Model construction itself never searches or reads the filesystem.
        env_file=None,
        case_sensitive=False,
        extra='ignore'  # Ignore encrypted_ fields and other extras
    )
    
    # Database Configuration (loaded from credential_manager)
    database_url: str = Field(
        default_factory=lambda: _credential_default('DATABASE_URL', ""),
        description="PostgreSQL connection URL (encrypted)"
    )
    
    # Redis Configuration
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_password: Optional[str] = Field(
        default_factory=lambda: _credential_default('REDIS_PASSWORD'),
        description="Redis password (encrypted)"
    )
    # Keep Redis failures FAST so the fail-closed login throttle's DB fallback kicks in
    # quickly during a Redis outage instead of every request blocking on the connect
    # timeout. Paired with the rate-limiter circuit breaker (a few failures => skip Redis
    # entirely for a short cooldown). Low single-digit seconds is plenty on a LAN.
    redis_connect_timeout: float = Field(default=1.0)
    redis_socket_timeout: float = Field(default=2.0)
    
    # SFTP Server Configuration
    sftp_host: str = Field(default="0.0.0.0")
    sftp_port: int = Field(default=2222)
    sftp_host_key_path: str = Field(default="./keys/ssh_host_rsa_key")
    
    # API Server Configuration
    api_host: str = Field(default="0.0.0.0")  # Bind to all interfaces for network access
    api_port: int = Field(default=8000)
    api_use_https: bool = Field(default=False)  # Enable HTTPS
    api_ssl_certfile: str = Field(default="./certs/cert.pem")
    api_ssl_keyfile: str = Field(default="./certs/key.pem")
    
    # Environment Configuration
    environment: str = Field(default="production")  # Options: development, production

    # Opt-in self-update check (default OFF). When on, the app checks GitHub Releases at most
    # once/day for a newer version and shows an admin-only banner. Fail-closed-silent (never
    # blocks a request, never errors to the user) and NO telemetry / instance identifier — only
    # the outbound request's egress IP reaches GitHub. See app/services/update_check.py.
    update_check_enabled: bool = Field(default=False)
    # A control-plane-managed (SaaS) deployment upgrades via operator promote, not self-service,
    # so the update banner is SUPPRESSED when this is set (the control plane sets it at provision).
    managed_deployment: bool = Field(default=False)
    # How often (minutes) an ENABLED update check may make a real outbound request to GitHub. This
    # is the env default; an admin can override it live in Settings. Both are clamped to a
    # rate-limit-safe floor (see app/services/update_check.py: MIN/MAX_INTERVAL_MINUTES).
    update_check_interval_minutes: int = Field(default=360)

    # Plan-imposed feature ceiling. The control plane injects these as PLAN_* env
    # vars at provision time so a deployment can't use features its plan excludes —
    # a HARD ceiling (a pushed admin /settings value could be toggled back by the
    # customer's own admin; an env ceiling cannot). Defaults are PERMISSIVE so an
    # un-gated / local-dev vault (no PLAN_* env) behaves exactly as before.
    plan_zero_knowledge: bool = Field(default=True)         # may zero-knowledge vaults be created at all
    plan_force_zero_knowledge: bool = Field(default=False)  # plan mandates zero-knowledge org-wide (Enterprise)
    plan_max_zk_vaults: int = Field(default=-1)             # cap on ZK vaults (-1 unlimited, 0 none, N capped)
    plan_max_storage_gb: int = Field(default=-1)            # aggregate storage cap across the deployment, GB (-1 unlimited)
    plan_max_users: int = Field(default=-1)                 # cap on user accounts (-1 unlimited, 0 = block all, N capped)
    # Operator-set allowlist of the vault TYPES this deployment may create (comma-separated,
    # e.g. "standard" to forbid zero-knowledge org-wide, or "zero_knowledge" for ZK-only).
    # Like the other PLAN_* ceilings it is injected by the control plane and is HARD: the
    # customer's own admin cannot widen it (there is no local /settings override), so it is
    # the admin-irreversible "allowed vault types" policy. EMPTY (the default) means NO
    # restriction — every recognised type is creatable, so an un-gated / local-dev vault
    # behaves exactly as before. Unrecognised entries are ignored; an all-invalid value is
    # treated as empty (permissive) so a typo can never brick all vault creation.
    plan_allowed_vault_types: str = Field(default="")
    # May this deployment expose the authenticated log-PULL endpoint (GET /logs)?
    # DELIBERATELY default FALSE — unlike the other PLAN_* ceilings (which default permissive so
    # an un-gated vault behaves as before), exposing the log stream is the UNSAFE direction, and
    # "as before" here means "no log endpoint at all". So the endpoint 404s everywhere until the
    # control plane injects PLAN_LOG_PULL=1 (Phase 2 plan-tiering) AND an admin enables a
    # component. Even then it is a HARD ceiling the customer's own admin cannot widen.
    plan_log_pull: bool = Field(default=False)

    # Security Configuration (loaded from credential_manager)
    encryption_key: str = Field(
        default_factory=lambda: _credential_default('ENCRYPTION_KEY', ""),
        description="Fernet encryption key for file encryption (encrypted)"
    )
    jwt_secret_key: str = Field(
        default_factory=lambda: _credential_default('JWT_SECRET_KEY', ""),
        description="Secret key for JWT token generation (encrypted)"
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=30)

    # Dedicated HMAC pepper for hashing log-pull tokens at rest (NOT derived from
    # ENCRYPTION_KEY/JWT_SECRET_KEY — a distinct secret so a leak of one does not compromise
    # stored token hashes). Plain env (not credential_manager) — it is only needed when the
    # log-pull ceiling is on, and its weakness is caught by a startup refusal below.
    log_token_pepper: str = Field(default="")

    # Temporary Credentials Configuration
    temp_cred_validity_minutes: int = Field(default=65)
    temp_cred_session_grace_minutes: int = Field(default=65)
    temp_cred_total_lifetime_minutes: int = Field(default=65)
    
    # File Storage Configuration
    file_storage_path: str = Field(default="./storage")
    max_file_size_mb: int = Field(default=1024)
    transfer_speed_limit_kb: int = Field(default=0)  # 0 = no limit, otherwise KB/s
    # Hours a resumable chunked-upload session may live before it is considered
    # abandoned and its buffered chunks under _uploads/<sid>/ become eligible for
    # cleanup (periodic sweep + the operator maintenance endpoint). Operators can
    # shorten this to reclaim transient disk faster on tight volumes, or lengthen it
    # to allow longer multi-day resumes. Effective value is floored at 1h in code so a
    # mis-set 0/negative can't expire every session the instant it's created.
    chunk_session_ttl_hours: int = Field(default=24)
    
    # Rate Limiting
    rate_limit_login_attempts: int = Field(default=5)
    rate_limit_login_window_seconds: int = Field(default=300)
    # Per-IP throttle on SFTP SSH-public-key auth attempts (FAILED offers only), so a flood
    # of key offers from one source is bounded. Key auth is not password-guessable, so this
    # is a DoS / authorized-key-enumeration bound, not a credential-brute-force control —
    # generous, and fails OPEN on a Redis error (account lockout + is_active stay primary).
    rate_limit_sftp_key_attempts: int = Field(default=30)
    # Auto-unlock TTL (minutes) for an account locked by FAILED LOGINS — a time-boxed lock
    # instead of a permanent one, so 5 wrong passwords can't permanently DoS a known account.
    # An ADMIN lock (set via the API) stays permanent (locked_until is NULL). 0 disables the
    # auto-lock TTL (locks stay until cleared), preserving the old behaviour if ever wanted.
    account_lockout_minutes: int = Field(default=15)
    # Trust X-Forwarded-For ONLY when the immediate peer is one of these networks (CIDR /
    # bare IP, comma-separated). Empty (the default) => trust NO proxy: XFF is ignored and the
    # immediate peer is used (fail-closed — the shipped direct-port-mapped topology has no
    # fronting proxy, so a private-range default would let a direct client forge its IP). Behind
    # a genuine reverse proxy, set this to that proxy's network to get real client IPs. Set
    # trust_all_proxies=true to honour XFF from any peer (only behind a proxy that strips
    # client-supplied XFF).
    trusted_proxies: str = Field(default="")
    trust_all_proxies: bool = Field(default=False)
    # Optional Host-header allowlist (comma-separated hostnames; TrustedHostMiddleware supports
    # a leading '*.' wildcard). EMPTY (the default) => permissive ('*', no Host validation), since a
    # self-hosted vault's served hostname is deployment-specific and unknown at build time. Set it to
    # the served name(s) to reject a forged/unexpected Host / X-Forwarded-Host (the classic primitive
    # for link-poisoning / cache-poisoning). 'localhost'/'127.0.0.1' are always allowed in addition so
    # the container's own /health probe keeps working.
    allowed_hosts: str = Field(default="")
    rate_limit_vault_attempts: int = Field(default=5)  # Regular users
    rate_limit_vault_attempts_admin: int = Field(default=20)  # Admins get higher limit
    rate_limit_vault_window_seconds: int = Field(default=300)  # 5 minutes
    
    # API Rate Limiting (General)
    rate_limit_api_enabled: bool = Field(default=True)  # Enable general API rate limiting
    rate_limit_api_default: int = Field(default=100)  # Default requests per minute for all API endpoints
    rate_limit_api_default_window: int = Field(default=60)  # 1 minute window
    rate_limit_api_auth: int = Field(default=10)  # Auth endpoints (more restrictive)
    rate_limit_api_auth_window: int = Field(default=60)
    rate_limit_api_upload: int = Field(default=20)  # File uploads
    rate_limit_api_upload_window: int = Field(default=60)
    rate_limit_api_download: int = Field(default=50)  # File downloads
    rate_limit_api_download_window: int = Field(default=60)
    
    # Security Monitoring Configuration
    security_failed_login_warning: int = Field(default=5)  # Failed logins before WARNING alert
    security_failed_login_critical: int = Field(default=10)  # Failed logins before CRITICAL alert
    security_failed_login_window: int = Field(default=10)  # Time window in minutes
    security_bulk_deletion_threshold: int = Field(default=10)  # Files deleted in time window
    security_bulk_deletion_window: int = Field(default=60)  # Time window in seconds
    security_alert_retention_days: int = Field(default=90)  # How long to keep resolved alerts
    
    # Logging
    log_level: str = Field(default="INFO")
    log_file_path: str = Field(default="./logs/sftp_server.log")
    
    # Admin Configuration
    admin_username: str = Field(default="admin")
    admin_password: str = Field(
        default_factory=lambda: _credential_default('ADMIN_PASSWORD', ""),
        description="Admin password (encrypted)"
    )
    admin_email: str = Field(default="admin@example.com")
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        allowed_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in allowed_levels:
            raise ValueError(f'Log level must be one of {allowed_levels}')
        return v.upper()
    
    @validator('temp_cred_validity_minutes', 'temp_cred_session_grace_minutes', 'temp_cred_total_lifetime_minutes')
    def validate_positive_minutes(cls, v):
        """Validate that minute values are positive."""
        if v <= 0:
            raise ValueError('Time values must be positive')
        return v
    
    def ensure_directories(self):
        """Ensure required directories exist."""
        directories = [
            self.file_storage_path,
            Path(self.log_file_path).parent,
            Path(self.sftp_host_key_path).parent,
        ]
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)


# Pure import-time defaults. ``model_construct`` deliberately bypasses settings sources and
# validation so even malformed ambient environment cannot make helper imports active. Runtime
# bootstrap constructs and validates the real settings, then mutates this stable object in place.
settings = Settings.model_construct()

_runtime_lock = threading.Lock()
_runtime_initialized = False

_JWT_SECRET_PLACEHOLDERS = {
    "your_jwt_secret_key_here", "changeme", "change_this", "changethis", "change_me",
    "secret", "your_secret_key", "your-secret-key", "please_change_me", "jwt_secret",
}
_ADMIN_PASSWORD_SHIPPED_PLACEHOLDERS = {"replace_me"}
_ADMIN_PASSWORD_PLACEHOLDERS = {
    "replace_me", "change_this_secure_password", "changeme", "change_me", "change_this",
    "changethis", "password", "admin", "admin123", "your_admin_password", "your_password_here",
}
_ADMIN_PASSWORD_MIN_LENGTH = 12


def runtime_is_initialized() -> bool:
    """Return whether this process completed runtime initialization."""
    return _runtime_initialized


def _is_container_runtime() -> bool:
    marker = (os.getenv("DOCKER_CONTAINER") or "").strip().lower()
    return marker in {"1", "true", "yes", "on"} or Path("/.dockerenv").exists()


def load_runtime_environment(dotenv_path=None):
    """Load one explicit host dotenv without overriding the process environment.

    Container entrypoints already receive their environment from Compose/orchestration and
    never read a baked or mounted dotenv implicitly. On a host, the default is exactly
    ``cwd/.env``; no parent-directory search occurs. Supplying ``dotenv_path`` is explicit
    and is honored in either environment, which also makes the precedence contract testable.
    """
    if dotenv_path is None:
        if _is_container_runtime():
            return None
        path = Path.cwd() / ".env"
    else:
        path = Path(dotenv_path)
    if path.is_file():
        load_dotenv(dotenv_path=path, override=False)
        return path
    return None


def _validate_runtime_settings(candidate: Settings) -> None:
    required = {
        "DATABASE_URL": candidate.database_url,
        "ENCRYPTION_KEY": candidate.encryption_key,
        "JWT_SECRET_KEY": candidate.jwt_secret_key,
    }
    if any(not (value or "").strip() for value in required.values()):
        raise RuntimeBootstrapError(
            "required-secret-missing",
            "One or more required runtime credentials are unavailable.",
        )

    try:
        Fernet(candidate.encryption_key.encode())
    except Exception:
        raise RuntimeBootstrapError(
            "encryption-key-invalid",
            "The configured file-encryption key is invalid.",
        ) from None

    jwt_secret = (candidate.jwt_secret_key or "").strip()
    if len(jwt_secret) < 32 or jwt_secret.lower() in _JWT_SECRET_PLACEHOLDERS:
        raise RuntimeBootstrapError(
            "jwt-secret-weak",
            "The JWT signing secret is missing, too short, or a known placeholder.",
        )

    if (candidate.jwt_algorithm or "").strip() not in {"HS256", "HS384", "HS512"}:
        raise RuntimeBootstrapError(
            "jwt-algorithm-invalid",
            "The JWT algorithm must be an exact supported HMAC algorithm.",
        )

    admin_password = (candidate.admin_password or "").strip()
    if admin_password:
        lowered = admin_password.lower()
        strict = (candidate.environment or "").strip().lower() != "development"
        weak = lowered in _ADMIN_PASSWORD_SHIPPED_PLACEHOLDERS
        weak = weak or (strict and lowered in _ADMIN_PASSWORD_PLACEHOLDERS)
        weak = weak or (strict and len(admin_password) < _ADMIN_PASSWORD_MIN_LENGTH)
        if weak:
            raise RuntimeBootstrapError(
                "admin-bootstrap-password-weak",
                "The bootstrap administrator password is weak or a known placeholder.",
            )


def _install_settings(candidate: Settings) -> None:
    # Preserve object identity for the many modules that import ``settings`` directly.
    for field_name in Settings.model_fields:
        setattr(settings, field_name, getattr(candidate, field_name))


def initialize_runtime(*, dotenv_path=None, master_password=None, interactive=True) -> Settings:
    """Initialize credentials, validated settings, and runtime directories exactly once."""
    global _runtime_initialized
    with _runtime_lock:
        if _runtime_initialized:
            return settings

        load_runtime_environment(dotenv_path)
        try:
            credential_manager.unlock_or_raise(
                master_password=master_password,
                interactive=interactive,
            )
        except CredentialUnlockError as exc:
            raise RuntimeBootstrapError(exc.code, exc.safe_message) from None

        try:
            candidate = Settings()
        except ValidationError:
            raise RuntimeBootstrapError(
                "settings-invalid",
                "One or more runtime settings have an invalid value.",
            ) from None

        _validate_runtime_settings(candidate)
        try:
            candidate.ensure_directories()
        except OSError:
            raise RuntimeBootstrapError(
                "runtime-directory-unavailable",
                "A required runtime directory could not be created or accessed.",
            ) from None

        _install_settings(candidate)
        _runtime_initialized = True
        return settings


def bootstrap_entrypoint(component: str, *, dotenv_path=None, master_password=None) -> Settings:
    """Initialize one server process or exit nonzero with a sanitized operator error."""
    try:
        active = initialize_runtime(
            dotenv_path=dotenv_path,
            master_password=master_password,
            interactive=True,
        )
        # Import only after credentials/settings are installed; database.py is import-safe
        # and this explicit call constructs the SQLAlchemy/Redis consumers once.
        from app.core.database import initialize_consumers
        initialize_consumers()
    except RuntimeBootstrapError as exc:
        print(
            f"DockVault {component} startup failed [{exc.code}]: {exc.safe_message}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    if active.plan_log_pull and len((active.log_token_pepper or "").strip()) < 32:
        print(
            "DockVault startup warning: log-pull remains disabled until a strong token pepper is configured.",
            file=sys.stderr,
        )
    return active
