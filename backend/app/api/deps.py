"""
backend/app/api/deps.py

FastAPI dependency injection providers.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Provides an isolated database session per request."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()
