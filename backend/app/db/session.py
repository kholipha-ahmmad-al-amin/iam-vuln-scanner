"""
backend/app/db/session.py

SQLAlchemy 2.0 AsyncEngine, session factory, and database lifecycle management.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings
from app.db.base import Base


def create_engine_instance() -> AsyncEngine:
    """Creates configured async engine for PostgreSQL or SQLite."""
    db_url = settings.DATABASE_URL
    is_sqlite = "sqlite" in db_url

    connect_args = {}
    if is_sqlite:
        connect_args["check_same_thread"] = False

    return create_async_engine(
        db_url,
        echo=settings.DB_ECHO,
        future=True,
        pool_pre_ping=not is_sqlite,
        connect_args=connect_args,
    )


engine: AsyncEngine = create_engine_instance()

async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yields an active async session for database operations."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    """Initializes database tables during application lifespan startup."""
    # Import all models so that Base.metadata contains all table definitions
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Disposes database connection pool during shutdown."""
    await engine.dispose()
