"""
Configuration management for the secure SFTP server.
Handles loading and validating environment variables.
"""
import os
import sys
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator
from dotenv import load_dotenv

# Load environment variables BEFORE importing credential manager
# In Docker, environment variables are already set by docker-compose
# Only load .env file if not running in Docker (to avoid conflicts)
is_docker = os.path.exists('/.dockerenv') or os.getenv('DOCKER_CONTAINER') == 'true'
if not is_docker:
    load_dotenv(override=False)
else:
    # In Docker mode, all config comes from environment variables
    # Don't load .env file to avoid conflicts with host machine's encrypted secrets
    pass

# Import and unlock credentials
from app.core.startup_security import credential_manager

# Only require master password if encrypted credentials are present
has_encrypted_creds = os.getenv("ENCRYPTED_ENCRYPTION_KEY") and os.getenv("MASTER_PASSWORD_HASH")
has_plain_creds = os.getenv("ENCRYPTION_KEY") and not has_encrypted_creds

if has_encrypted_creds or has_plain_creds:
    print("\n🔐 Initializing secure credential system...")
    if not credential_manager.unlock():
        print("\n❌ Failed to unlock credentials. Server cannot start.")
        if has_encrypted_creds:
            print("   Please ensure you have the correct master password.")
            print("\n💡 If you need to reset security:")
            print("   1. Restore .env from .env.backup")
            print("   2. Run: python scripts/setup_master_password.py")
        sys.exit(1)
    print("✅ Credentials unlocked successfully\n")
else:
    print("\n⚠️  WARNING: No credentials configured in environment!")
    print("   Please configure .env with required credentials.")
    print("   See .env.example for template.")
    sys.exit(1)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        case_sensitive=False,
        extra='ignore'  # Ignore encrypted_ fields and other extras
    )
    
    # Database Configuration (loaded from credential_manager)
    database_url: str = Field(
        default_factory=lambda: credential_manager.get('DATABASE_URL') or "",
        description="PostgreSQL connection URL (encrypted)"
    )
    
    # Redis Configuration
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)
    redis_password: Optional[str] = Field(
        default_factory=lambda: credential_manager.get('REDIS_PASSWORD'),
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
        default_factory=lambda: credential_manager.get('ENCRYPTION_KEY') or "",
        description="Fernet encryption key for file encryption (encrypted)"
    )
    jwt_secret_key: str = Field(
        default_factory=lambda: credential_manager.get('JWT_SECRET_KEY') or "",
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
        default_factory=lambda: credential_manager.get('ADMIN_PASSWORD') or "",
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


# Global settings instance
settings = Settings()
settings.ensure_directories()


# --- Fail closed on a weak / empty / placeholder JWT signing secret ---
# Token acceptance rests ENTIRELY on this HS256 secret (the algorithm is pinned in
# verify_access_token, so there is no alg-confusion fallback). An empty default or the
# copied .env.example placeholder would let anyone mint valid admin tokens offline. Reject
# it at startup, mirroring the "no credentials configured" hard-exit above.
_JWT_SECRET_PLACEHOLDERS = {
    "your_jwt_secret_key_here", "changeme", "change_this", "changethis", "change_me",
    "secret", "your_secret_key", "your-secret-key", "please_change_me", "jwt_secret",
}
_jwt_secret = (settings.jwt_secret_key or "").strip()
if len(_jwt_secret) < 32 or _jwt_secret.lower() in _JWT_SECRET_PLACEHOLDERS:
    print("\n❌ FATAL: JWT_SECRET_KEY is unset, too short (<32 chars), or a known placeholder.")
    print("   A weak signing secret allows offline forgery of admin session tokens.")
    print("   Generate a strong secret and set JWT_SECRET_KEY:  openssl rand -hex 32")
    sys.exit(1)


# --- Fail closed on a non-HMAC / mis-cased JWT algorithm ---
# Token verification pins algorithms=[jwt_algorithm] (a single-element allowlist) and this deployment
# is JWS-only — no RSA/EC verification key is configured. Require the EXACT canonical HMAC name: PyJWT
# looks algorithms up case-sensitively, so a mis-cased value like "hs256" would clear a loose check yet
# 500 at the first token mint. An exact allowlist fails closed at boot for BOTH an asymmetric algorithm
# (alg-confusion) and a mis-cased one — regardless of the JWT library.
if (settings.jwt_algorithm or "").strip() not in {"HS256", "HS384", "HS512"}:
    print(f"\n❌ FATAL: JWT_ALGORITHM must be exactly one of HS256/HS384/HS512; got {settings.jwt_algorithm!r}.")
    print("   This deployment is symmetric (JWS-only); an asymmetric or mis-cased algorithm is a forgery/500 risk.")
    sys.exit(1)


# --- Fail closed on a shipped sample / weak admin bootstrap password ---
# The first admin is seeded from ADMIN_PASSWORD; unlike the crypto-key placeholders (an invalid
# ENCRYPTION_KEY fails fast), the shipped sample admin password is a WORKING credential. A BLANK
# ADMIN_PASSWORD is deliberately NOT rejected — it is the legitimate post-bootstrap state (the admin
# exists; the seed is a no-op).
#
# Two tiers, so a PUBLICLY KNOWN credential can never seed an admin while a local dev stack stays
# convenient:
#   * ALWAYS (every environment): refuse the exact shipped .env.example placeholder. A bare
#     `docker compose up` that copies .env.example verbatim would otherwise seed admin/REPLACE_ME —
#     a credential published in this public repo — even in development on a plaintext listener. The
#     sibling JWT-secret guard above is likewise unconditional.
#   * ANY REACHABLE (non-"development") deploy additionally: reject the full known-weak blocklist AND
#     enforce a minimum length, mirroring the JWT guard, so a weak-but-unlisted value (e.g.
#     "vault2024", "Password1") can't boot the account that reads every non-ZK vault server-side.
#     Fail SAFE: only an explicit ENVIRONMENT=development is lenient — "production" (the default),
#     "staging", "prod", or a typo all get the strict tier, matching the plaintext-transport warning.
# `./setup-secure.sh` forces production, so it passes both tiers. A deployment that deliberately runs in
# `development` mode is opting into the lenient tier for a trusted/local environment (where the admin
# password is expected to be set out of band), so only the always-on placeholder check applies there.
_ADMIN_PASSWORD_SHIPPED_PLACEHOLDERS = {"replace_me"}
_ADMIN_PASSWORD_PLACEHOLDERS = {
    "replace_me", "change_this_secure_password", "changeme", "change_me", "change_this",
    "changethis", "password", "admin", "admin123", "your_admin_password", "your_password_here",
}
_ADMIN_PASSWORD_MIN_LENGTH = 12
_admin_pw = (settings.admin_password or "").strip()
if _admin_pw:
    _admin_pw_lower = _admin_pw.lower()
    _admin_pw_strict = (settings.environment or "").strip().lower() != "development"
    _admin_pw_reject = None
    if _admin_pw_lower in _ADMIN_PASSWORD_SHIPPED_PLACEHOLDERS:
        _admin_pw_reject = "is the shipped .env.example placeholder (a publicly known value)"
    elif _admin_pw_strict and _admin_pw_lower in _ADMIN_PASSWORD_PLACEHOLDERS:
        _admin_pw_reject = "is a known sample/weak value outside ENVIRONMENT=development"
    elif _admin_pw_strict and len(_admin_pw) < _ADMIN_PASSWORD_MIN_LENGTH:
        _admin_pw_reject = f"is shorter than {_ADMIN_PASSWORD_MIN_LENGTH} characters outside ENVIRONMENT=development"
    if _admin_pw_reject:
        print(f"\n❌ FATAL: ADMIN_PASSWORD {_admin_pw_reject}.")
        print("   The first admin would be created with a weak or publicly known credential.")
        print("   Set a strong ADMIN_PASSWORD:  openssl rand -base64 18")
        sys.exit(1)


# --- Warn (do NOT brick) on a weak/empty LOG_TOKEN_PEPPER when the plan enables log-pull ---
# The pepper hardens stored log-pull token hashes. It is only load-bearing when the
# endpoint can be reached. A DATA VAULT must never refuse to boot over a LOG-feature config
# problem (that would deny the customer access to their FILES), and the control plane may set
# PLAN_LOG_PULL a moment before the pepper reaches an existing/bundle container. So a
# weak/absent pepper does NOT exit — the EFFECTIVE ceiling (app/services/log_pull.py effective_ceiling, used by
# the endpoint) simply requires a strong pepper, DISABLING the endpoint (404) until one is set.
# Warn loudly so an operator notices the endpoint is off.
if settings.plan_log_pull:
    _log_pepper = (settings.log_token_pepper or "").strip()
    if len(_log_pepper) < 32:
        print("\n⚠️  WARNING: PLAN_LOG_PULL is on but LOG_TOKEN_PEPPER is unset or too short "
              "(<32 chars) — the log-pull endpoint is DISABLED until a strong pepper is set.")
        print("   Generate one and set LOG_TOKEN_PEPPER:  openssl rand -hex 32")
