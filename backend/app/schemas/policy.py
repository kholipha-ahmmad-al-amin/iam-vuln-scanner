"""
backend/app/schemas/policy.py

Pydantic v2 schemas for IAM Policies, Statements, and Stateless Analysis requests/responses.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from app.schemas.vulnerability import VulnerabilityDetail


class StatementInput(BaseModel):
    """Raw or normalized statement input."""

    sid: Optional[str] = None
    effect: str = "Allow"
    action: Union[str, List[str]]
    resource: Union[str, List[str]] = "*"
    condition: Optional[Dict[str, Any]] = None


class PolicyInput(BaseModel):
    """IAM Policy input wrapper."""

    policy_name: Optional[str] = "Policy"
    policy_arn: Optional[str] = None
    policy_type: str = "MANAGED"
    attached_entity_type: Optional[str] = None
    attached_entity_name: Optional[str] = None
    policy_document: Optional[Dict[str, Any]] = None
    raw_json: Optional[str] = None


class PolicySummary(BaseModel):
    """Summary of a stored IAM policy document."""

    id: str
    policy_name: str
    policy_arn: Optional[str] = None
    policy_type: str = "MANAGED"
    attached_entity_type: Optional[str] = None
    attached_entity_name: Optional[str] = None
    is_vulnerable: bool = False
    created_at: Optional[datetime] = None


class PolicyDetail(PolicySummary):
    """Detailed view of a stored IAM policy document."""

    version: str = "2012-10-17"
    raw_json: str
    statements: List[Dict[str, Any]] = Field(default_factory=list)


class PolicyAnalyzeRequest(BaseModel):
    """Request payload for stateless policy analysis."""

    policy_name: Optional[str] = "StatelessPolicy"
    policy_json: Optional[Union[str, Dict[str, Any]]] = None
    policy_document: Optional[Dict[str, Any]] = None
    principal_arn: Optional[str] = None


class PolicyAnalyzeResponse(BaseModel):
    """Response payload for stateless policy analysis."""

    is_valid: bool = True
    is_vulnerable: bool = False
    risk_score: float = 0.0
    statement_count: int = 0
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    findings: List[VulnerabilityDetail] = Field(default_factory=list)
    graph: Optional[Dict[str, Any]] = None
    graph_data: Optional[Dict[str, Any]] = None
    allowed_actions_summary: List[str] = Field(default_factory=list)
    denied_actions_summary: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
