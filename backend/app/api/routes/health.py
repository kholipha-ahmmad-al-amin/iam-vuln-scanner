"""
backend/app/api/routes/health.py

Health check and database connectivity verification endpoint.
"""

from datetime import datetime
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.config import settings

router = APIRouter()


@router.get("/health", summary="Service health and database connectivity check")
async def health_check(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """
    Verifies service liveness and checks active database connectivity.
    """
    db_status = "disconnected"
    status_code = "ok"

    try:
        result = await db.execute(text("SELECT 1"))
        if result.scalar() == 1:
            db_status = "connected"
    except Exception:
        status_code = "degraded"
        db_status = "disconnected"

    db_type = "sqlite" if "sqlite" in settings.DATABASE_URL else "postgresql"

    return {
        "status": status_code,
        "database": db_status,
        "database_type": db_type,
        "version": settings.VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
