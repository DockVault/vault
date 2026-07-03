"""
Database connection and session management.
Provides database connection pooling and session management utilities.
"""
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
import redis

from config import settings
from models import Base


# PostgreSQL Engine
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,  # Verify connections before using
    pool_size=10,
    max_overflow=20,
    echo=settings.log_level == "DEBUG",
    # Bound the initial TCP+auth connect so a black-holed DB (dropped route, not a clean
    # refuse) fails fast instead of hanging a request for the OS default (~2 min). Mirrors
    # the Redis socket_connect_timeout below. Callers that degrade gracefully on a DB
    # error — e.g. the public branding reads in app/routers/info.py, which fall back to
    # env defaults — then recover promptly instead of pinning a pooled connection.
    connect_args={"connect_timeout": 5},
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Redis Connection
#
# Short connect/socket timeouts so a Redis outage fails FAST: the login throttle is
# fail-closed (it falls back to a durable DB throttle when Redis is unavailable), but that
# fallback only helps if the Redis attempt gives up quickly — a 5s connect timeout per
# request made logins crawl during an outage. Paired with the rate-limiter circuit breaker,
# which trips after a few failures and skips Redis entirely for a short cooldown.
redis_client = redis.Redis(
    host=settings.redis_host,
    port=settings.redis_port,
    db=settings.redis_db,
    password=settings.redis_password if settings.redis_password else None,
    decode_responses=True,
    socket_connect_timeout=settings.redis_connect_timeout,
    socket_timeout=settings.redis_socket_timeout,
    socket_keepalive=True,
    health_check_interval=30
)


def init_db():
    """Initialize the database schema."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """
    Dependency function to get database session.
    Used with FastAPI's dependency injection.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database sessions.
    Use for non-FastAPI contexts.
    """
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
    """Check if database connection is working."""
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False


def check_redis_connection() -> bool:
    """Check if Redis connection is working."""
    try:
        redis_client.ping()
        return True
    except Exception as e:
        print(f"Redis connection failed: {e}")
        return False
