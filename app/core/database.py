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
    initialize_runtime,
    runtime_is_initialized,
    settings,
)
from app.core.models import Base

_consumer_lock = threading.Lock()
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
                pool_size=10,
                max_overflow=20,
                echo=settings.log_level == "DEBUG",
                connect_args={"connect_timeout": 5},
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


def check_redis_connection() -> bool:
    """Check cache availability without leaking connection details."""
    try:
        _require_redis_client().ping()
        return True
    except Exception:
        print("Redis connection failed")
        return False
