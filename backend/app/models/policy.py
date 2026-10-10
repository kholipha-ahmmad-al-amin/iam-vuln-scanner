"""
backend/app/models/policy.py

SQLAlchemy 2.0 ORM models for IAM Policies and Statements.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.vulnerability import DetectedVulnerability


class Policy(Base):
    """Parsed IAM policy document associated with a scan run."""

    __tablename__ = "policies"

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
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_arn: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    policy_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="MANAGED",
    )
    attached_entity_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    attached_entity_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="2012-10-17")
    raw_json: Mapped[str] = mapped_column(Text, nullable=False)
    is_vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="policies")
    statements: Mapped[List["PolicyStatement"]] = relationship(
        "PolicyStatement",
        back_populates="policy",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    vulnerabilities: Mapped[List["DetectedVulnerability"]] = relationship(
        "DetectedVulnerability",
        back_populates="policy",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class PolicyStatement(Base):
    """Normalized statement block extracted from an IAM policy."""

    __tablename__ = "policy_statements"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    policy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sid: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    effect: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    actions: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    not_actions: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    resources: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    not_resources: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    conditions: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    has_wildcard_action: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_wildcard_resource: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    policy: Mapped["Policy"] = relationship("Policy", back_populates="statements")
