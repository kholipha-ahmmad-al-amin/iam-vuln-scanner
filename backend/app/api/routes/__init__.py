"""
backend/app/api/routes/__init__.py

FastAPI API route modules package.
"""

from app.api.routes.health import router as health_router
from app.api.routes.policies import router as policies_router
from app.api.routes.rules import router as rules_router
from app.api.routes.scans import router as scans_router

__all__ = [
    "health_router",
    "policies_router",
    "rules_router",
    "scans_router",
]
