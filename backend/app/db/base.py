"""
backend/app/db/base.py

SQLAlchemy DeclarativeBase metadata definition.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass
