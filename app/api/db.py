"""database adapter: postgresql through DATABASE_URL (neon's pooled pgbouncer string on vercel,
docker locally). NullPool: one connection per request and no long-lived pool, as serverless
functions need; prepared statements are off for pgbouncer's transaction mode."""
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.api import settings

engine = None
maker = None


def get_engine():
    global engine, maker
    if engine is None:
        engine = create_engine(settings.db_url(), poolclass=NullPool, connect_args={"prepare_threshold": None},
                               future=True)
        maker = sessionmaker(engine, expire_on_commit=False)
    return engine


@contextmanager
def session():
    get_engine()
    s = maker()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def dep():
    """fastapi dependency: a session per request"""
    with session() as s:
        yield s
