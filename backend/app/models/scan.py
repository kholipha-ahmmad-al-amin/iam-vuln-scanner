"""
backend/app/models/scan.py

SQLAlchemy 2.0 ORM model for Scan records and execution metadata.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import DateTime, Float, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.policy import Policy
    from app.models.vulnerability import DetectedVulnerability
    from app.models.graph import GraphNode, GraphEdge


class Scan(Base):
    """Scan execution session tracking aggregate risk metrics and results."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="COMPLETED",
        index=True,
    )
    source_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="JSON_UPLOAD",
    )
    total_policies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_statements: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    scan_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    graph_summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    # Relationships
    policies: Mapped[List["Policy"]] = relationship(
        "Policy",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    vulnerabilities: Mapped[List["DetectedVulnerability"]] = relationship(
        "DetectedVulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    graph_nodes: Mapped[List["GraphNode"]] = relationship(
        "GraphNode",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    graph_edges: Mapped[List["GraphEdge"]] = relationship(
        "GraphEdge",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
