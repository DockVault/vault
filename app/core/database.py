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
# The web server's pool (pool_capacity) holds one connection for each piece of work that is bounded and holds a
# connection while it runs: every transfer the two ceilings admit (a download, an upload's completion, a copy or a
# move, each holding its request's connection; a transfer waiting for its slot holds none) and every sign-in
# handed to app/core/auth_offload.py. When those could take every connection (a burst of copies before copies were
# admitted; downloads waiting for a slot holding their read transaction), the next request's first query waited
# for one ON the event loop, which answers every request, for up to the pool's 30 s timeout.
#
# LOOP_RESERVE connections more are left for everything else together, which this does not count and nothing
# bounds below the pool:
# - the requests the event loop answers, each holding one while it queries;
# - the synchronous routes (82), which the framework runs in its own thread pool, up to 40 at once, each holding
#   its session's connection while it runs (the activity search and export, the compliance cases' reads, file
#   contents and exports);
# - the mail sent without the request waiting for it (a password reset, an email action), one thread per mail,
#   holding a session while the mail is sent; nothing bounds how many;
# - the background threads that use the database: maintenance, the owner notices, the recording levels and the
#   managed settings refreshers, and the last-opened writer (app/core/vault_access.py).
# So the ten are kept only while those need no more than ten at once. When they need more, the next query waits
# for one, on the loop if the loop asked: a burst of those is not prevented here.
LOOP_RESERVE = 10
# The least the pool holds, as it always held: 10 kept open and 20 more. A process that carries no transfers (the
# SFTP server, a command run in the container) keeps this: SFTP transfers are not on the ceiling.
MIN_CAPACITY = 30


def pool_capacity(max_concurrent_transfers) -> int:
    """The most connections the web server's pool opens, with the transfer ceiling configured as
    ``max_concurrent_transfers``: one for each transfer and sign-in that can run at once, and LOOP_RESERVE more for
    everything else (see the comment above: not a reserve for the event loop alone). 38 at the default ceiling of
    16; with the SFTP server's 30 that is 68, and 98 at a ceiling of 40 (connection_room says what the database
    lets the vault's role open)."""
    from app.core.auth_offload import AUTH_OFFLOAD_LIMIT
    from app.core.transfer_admission import admitted_at_most
    return max(MIN_CAPACITY, admitted_at_most(max_concurrent_transfers) + AUTH_OFFLOAD_LIMIT + LOOP_RESERVE)


# PostgreSQL accepts max_connections (100 unless it is told otherwise), and keeps superuser_reserved_connections of
# them (3 by default) for superusers: a role that is not one opens at most the rest, 97 by default (the role the
# shipped composes create is a superuser; one on a database of your own may not be), and fewer when the role has a
# connection limit of its own. Past what the role may open, the next connection is refused: a request fails, or the
# SFTP server cannot read a session. The web server's pool and the SFTP server's (pool_capacity and MIN_CAPACITY)
# fit in 97 up to a ceiling of 39 and in 100 up to 42; the management tool's commands run in the container open one
# or two more while they run.
_ROOM_SQL = ("SELECT current_setting('max_connections')::int, current_setting('superuser_reserved_connections')::int, "
             "r.rolsuper, r.rolconnlimit FROM pg_roles r WHERE r.rolname = current_user")


def connection_room(row, max_concurrent_transfers, runs_sftp: bool) -> dict:
    """What the pools may open at the transfer ceiling ``max_concurrent_transfers`` (the web server's, and the SFTP
    server's when ``runs_sftp``) against what the database lets the vault's role open, from ``row`` (_ROOM_SQL's
    answer: max_connections, superuser_reserved_connections, whether the role is a superuser, its own limit, -1 for
    none). ``highest_ceiling`` is the highest ceiling whose pools fit, 0 when none does."""
    max_connections, reserved, superuser, role_limit = (int(row[0]), int(row[1]), bool(row[2]), int(row[3]))
    usable = max_connections - (0 if superuser else reserved)
    if role_limit >= 0:
        usable = min(usable, role_limit)
    others = MIN_CAPACITY if runs_sftp else 0
    highest = 0
    for ceiling in range(1, 1001):
        if pool_capacity(ceiling) + others > usable:
            break
        highest = ceiling
    return {"needed": pool_capacity(max_concurrent_transfers) + others, "usable": usable,
            "max_connections": max_connections, "reserved": 0 if superuser else reserved, "superuser": superuser,
            "role_limit": role_limit, "highest_ceiling": highest}


def report_connection_room() -> None:
    """At the web server's start: say when the pools may open more connections than the database lets the vault's
    role open (connection_room), and what to change. Never raises: a database that cannot be asked is said, and the
    start goes on."""
    from sqlalchemy import text
    try:
        engine = _require_engine()
        if engine.dialect.name != "postgresql":
            return
        from app.core.sftp_versions import deployment_runs_sftp
        with engine.connect() as connection:
            row = connection.execute(text(_ROOM_SQL)).first()
        if row is None:
            return
        room = connection_room(row, settings.max_concurrent_transfers, deployment_runs_sftp())
    except Exception as exc:  # noqa: BLE001
        print(f"Warning: the database's connection limit was not checked ({type(exc).__name__})")
        return
    if room["needed"] <= room["usable"]:
        return
    kept = (f", {room['reserved']} of them kept for superusers" if room["reserved"] else "")
    print(f"Warning: at MAX_CONCURRENT_TRANSFERS={settings.max_concurrent_transfers} the database pools of the web "
          f"server and the SFTP server may open {room['needed']} connections, more than the database lets this "
          f"role open ({room['usable']}: max_connections {room['max_connections']}{kept}). When they are all in "
          f"use, the next request fails. Set MAX_CONCURRENT_TRANSFERS to {room['highest_ceiling']} or less, or raise "
          f"the database's max_connections.", flush=True)


_engine = None
_session_factory = None
_redis_client = None


def initialize_consumers(*, carries_transfers=False) -> None:
    """Construct process-local SQLAlchemy and Redis clients exactly once.

    Client construction does not open a network connection; schema creation and health
    checks remain explicit operations. Locals are assigned only after every constructor
    succeeds, so a partial failure cannot publish a half-initialized consumer set.

    ``carries_transfers``: the process carries the web transfers the ceiling admits (the web server), so its
    pool is sized from the ceiling (pool_capacity); any other process (the SFTP server, a command) keeps
    MIN_CAPACITY. Sized from the ceiling too, the SFTP server's pool and the web server's together passed
    PostgreSQL's 100 connections from a ceiling of about 25.
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
                max_overflow=(pool_capacity(settings.max_concurrent_transfers) if carries_transfers
                              else MIN_CAPACITY) - POOL_SIZE,
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
