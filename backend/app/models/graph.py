"""
backend/app/models/graph.py

SQLAlchemy 2.0 ORM models for Attack Graph Nodes and Edges.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class GraphNode(Base):
    """Graph vertex representing an IAM principal, policy, action, or target."""

    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_key: Mapped[str] = mapped_column(String(128), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="NONE")
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="graph_nodes")


class GraphEdge(Base):
    """Graph directed edge representing an IAM relationship or escalation link."""

    __tablename__ = "graph_edges"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    is_escalation_path: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )
    risk_weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="graph_edges")
