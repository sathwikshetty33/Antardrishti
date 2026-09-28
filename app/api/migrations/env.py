"""alembic environment: migrations run by hand (the owner's machine or ci), never at function
start. uses DATABASE_URL_UNPOOLED when set (neon's direct connection), else DATABASE_URL."""
import os

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from app.api import settings
from app.api.models import base

target_metadata = base.metadata


def url():
    direct = os.environ.get("DATABASE_URL_UNPOOLED")
    if direct:
        os.environ["DATABASE_URL"] = direct
    return settings.db_url()


def run_offline():
    context.configure(url=url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_online():
    eng = create_engine(url(), poolclass=NullPool)
    with eng.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
