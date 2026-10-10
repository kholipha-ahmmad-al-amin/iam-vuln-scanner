"""
backend/app/main.py

FastAPI application factory, lifespan management, middleware, and router registration.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    health_router,
    policies_router,
    rules_router,
    scans_router,
)
from app.config import settings
from app.db.session import close_db, init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages application startup and shutdown events."""
    # Initialize database tables on startup
    await init_db()
    yield
    # Dispose connection pools on shutdown
    await close_db()


def create_application() -> FastAPI:
    """Builds and configures the FastAPI application instance."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="Automated AWS IAM vulnerability analysis, privilege escalation detection, and attack graph visualizer REST API.",
        lifespan=lifespan,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routers with /api prefix
    app.include_router(health_router, prefix=settings.API_V1_PREFIX, tags=["Health"])
    app.include_router(health_router, tags=["Health"])  # Also route /health directly
    app.include_router(rules_router, prefix=settings.API_V1_PREFIX, tags=["Rules"])
    app.include_router(policies_router, prefix=settings.API_V1_PREFIX, tags=["Policies"])
    app.include_router(scans_router, prefix=settings.API_V1_PREFIX, tags=["Scans"])

    return app


app = create_application()
