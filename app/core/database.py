"""Import-safe database and cache consumer initialization."""

from contextlib import contextmanager
import threading

import redis
from redis.backoff import NoBackoff
from redis.retry import Retry
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import (
    RuntimeBootstrapError,
    RuntimeNotReady,
    initialize_runtime,
    runtime_is_initialized,
    settings,
)
from app.core.models import Base

_consumer_lock = threading.Lock()
# Server-side lock_timeout (ms) applied to every app connection via libpq options, so any statement
# that waits on a row lock longer than this fails with a clean error instead of blocking a request
# path forever. A backstop, not the mechanism: the app avoids holding contended locks in request
# paths. The boot-time DDL/migration transaction overrides this to 0 (SET LOCAL) because schema
# changes may legitimately wait on a lock; and the Postgres service also sets
# idle_in_transaction_session_timeout in the deploy composes as a second backstop. No env flag.
_LOCK_TIMEOUT_MS = 5000
# Every app connection's session runs in UTC. The timestamp columns hold UTC with no zone attached,
# and a zone-aware value bound into one (a write, or a comparison) is converted through the session's
# time zone, which is otherwise the database's: on a database set to another zone such values were off
# by its offset. Pinned here, they are UTC whatever the database is set to.
_CONNECT_OPTIONS = f"-c lock_timeout={_LOCK_TIMEOUT_MS} -c timezone=UTC"
# The pool keeps POOL_SIZE connections open and opens more when needed, up to pool_capacity().
POOL_SIZE = 10
# What the pool keeps for the requests the event loop is answering, beyond all the work handed to threads that
# holds a connection while it runs: every transfer the two ceilings admit (a download, an upload's completion, a
# copy or a move, each finished in a thread of app/core/off_loop.py on its request's connection) and every
# sign-in handed to app/core/auth_offload.py. When those could take every connection (a burst of copies, before
# copies were admitted), the next request's first query waited for one ON the event loop, which answers every
# request, for up to the pool's 30 s timeout.
LOOP_RESERVE = 10
# The least the pool holds, as it always held: 10 kept open and 20 more.
MIN_CAPACITY = 30


def pool_capacity(max_concurrent_transfers) -> int:
    """The most connections the pool opens, with the transfer ceiling configured as ``max_concurrent_transfers``:
    one for each transfer and sign-in that can run in a thread at once, and LOOP_RESERVE more."""
    from app.core.auth_offload import AUTH_OFFLOAD_LIMIT
    from app.core.transfer_admission import admitted_at_most
    return max(MIN_CAPACITY, admitted_at_most(max_concurrent_transfers) + AUTH_OFFLOAD_LIMIT + LOOP_RESERVE)


_engine = None
_session_factory = None
_redis_client = None


def initialize_consumers() -> None:
    """Construct process-local SQLAlchemy and Redis clients exactly once.

    Client construction does not open a network connection; schema creation and health
    checks remain explicit operations. Locals are assigned only after every constructor
    succeeds, so a partial failure cannot publish a half-initialized consumer set.
    """
    global _engine, _session_factory, _redis_client
    with _consumer_lock:
        if _engine is not None:
            return
        if not runtime_is_initialized():
            initialize_runtime(interactive=False)
        if not (settings.database_url or "").strip():
            raise RuntimeBootstrapError(
                "required-secret-missing",
                "The database credential is unavailable.",
            )
        try:
            engine = create_engine(
                settings.database_url,
                pool_pre_ping=True,
                pool_size=POOL_SIZE,
                max_overflow=pool_capacity(settings.max_concurrent_transfers) - POOL_SIZE,
                echo=settings.log_level == "DEBUG",
                # A database error's text, and the DEBUG echo, leave out the statement's bound values:
                # they are names typed at sign-in, addresses, file names, and an error is printed to
                # the container log. Nothing reads the values back out of an error.
                hide_parameters=True,
                connect_args={"connect_timeout": 5, "options": _CONNECT_OPTIONS},
            )
            factory = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=engine,
            )
            cache = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password if settings.redis_password else None,
                decode_responses=True,
                socket_connect_timeout=settings.redis_connect_timeout,
                socket_timeout=settings.redis_socket_timeout,
                socket_keepalive=True,
                health_check_interval=30,
                retry=Retry(NoBackoff(), 0),
            )
        except Exception:
            try:
                engine.dispose()
            except Exception:
                pass
            raise RuntimeBootstrapError(
                "consumer-initialization-failed",
                "Database or cache consumers could not be initialized.",
            ) from None
        # A committed audit row signals the Activity page (see app/core/audit_signal.py).
        from app.core import audit_signal
        audit_signal.install(factory)
        _engine = engine
        _session_factory = factory
        _redis_client = cache


def _require_engine():
    initialize_consumers()
    return _engine


def _require_session_factory():
    initialize_consumers()
    return _session_factory


def _require_redis_client():
    initialize_consumers()
    return _redis_client


class _RedisClientProxy:
    """Stable import target that resolves the explicitly initialized cache client."""

    def __getattr__(self, name):
        return getattr(_require_redis_client(), name)

    def __repr__(self):
        return "<DockVault Redis client>"


redis_client = _RedisClientProxy()


def SessionLocal():
    """Return a database session from the initialized process-local factory."""
    return _require_session_factory()()


def started_session():
    """A database session, once this process has initialized its runtime; RuntimeNotReady before.

    SessionLocal() initializes the runtime when nothing has yet, and that installs a newly read value of
    every setting over the shared settings object. Doing that is the process's own start's job, in its
    main thread (bootstrap_entrypoint, the web lifespan). Done from a background thread, it would
    overwrite, at a moment nobody chose, whatever the process has set since. So a background thread's
    turn (the managed-settings refresh, the SFTP version record) asks here, and a turn that is refused
    is skipped: the next one asks again.
    """
    if not runtime_is_initialized():
        raise RuntimeNotReady("this process has not initialized its runtime yet")
    return SessionLocal()


def init_db():
    """Create the database schema against the initialized engine."""
    Base.metadata.create_all(bind=_require_engine())


def get_db() -> Session:
    """FastAPI dependency yielding one database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """Transactional database-session context manager."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_db_connection() -> bool:
    """Check database availability without leaking connection details."""
    try:
        from sqlalchemy import text
        with _require_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        print("Database connection failed")
        return False


_redis_probe_client = None


def redis_probe_ping(timeout: float) -> None:
    """Ping Redis on a dedicated, short-timeout connection for the rate-limiter breaker's health
    probe. Raises on any failure.

    The breaker's probe runs off the request path in a background thread and must not linger, so it
    uses its own connection with a short connect/socket timeout rather than the main client's (whose
    socket timeout is deliberately longer for real work). Built once from the same settings as the
    main client; no health-check interval, since each call is a single one-shot ping."""
    global _redis_probe_client
    initialize_consumers()
    if _redis_probe_client is None:
        _redis_probe_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password if settings.redis_password else None,
            decode_responses=True,
            socket_connect_timeout=timeout,
            socket_timeout=timeout,
            socket_keepalive=True,
            retry=Retry(NoBackoff(), 0),
        )
    _redis_probe_client.ping()
