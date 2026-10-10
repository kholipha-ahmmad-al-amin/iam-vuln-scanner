"""
backend/app/schemas/scan.py

Pydantic v2 schemas for Scan creation, summary, details, and history listings.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from app.schemas.policy import PolicySummary
from app.schemas.vulnerability import VulnerabilityDetail


class ScanPolicyInput(BaseModel):
    """Input policy payload within a batch scan request."""

    policy_name: Optional[str] = "Policy"
    policy_arn: Optional[str] = None
    policy_type: str = "MANAGED"
    attached_entity_type: Optional[str] = None
    attached_entity_name: Optional[str] = None
    policy_document: Optional[Dict[str, Any]] = None
    policy_json: Optional[Union[str, Dict[str, Any]]] = None


class ScanCreate(BaseModel):
    """Scan creation request body supporting single or batch policies."""

    title: Optional[str] = None
    name: Optional[str] = None  # Alias for title
    description: Optional[str] = None
    policy_json: Optional[Union[str, Dict[str, Any]]] = None
    policies: Optional[List[ScanPolicyInput]] = None
    principal_arn: Optional[str] = None

    def get_title(self) -> str:
        """Returns normalized title, preferring title over name."""
        return self.title or self.name or "IAM Policy Scan"


class ScanSummary(BaseModel):
    """Compact summary of a scan execution."""

    id: str
    title: str
    status: str
    total_policies: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = 0.0
    created_at: Optional[datetime] = None


class ScanDetail(BaseModel):
    """Detailed scan execution results."""

    id: str
    title: str
    description: Optional[str] = None
    status: str
    source_type: str = "JSON_UPLOAD"
    total_policies: int = 0
    total_statements: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = 0.0
    scan_duration_ms: Optional[int] = None
    policies: List[PolicySummary] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    findings: List[VulnerabilityDetail] = Field(default_factory=list)
    graph: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: List[ScanSummary] = Field(default_factory=list)
    total: int
    page: int
    page_size: int
    total_pages: int
