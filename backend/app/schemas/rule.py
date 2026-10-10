"""
backend/app/schemas/rule.py

Pydantic v2 schemas for Rule Catalog endpoints.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class RuleCatalogItem(BaseModel):
    """Schema for individual escalation detection rules in catalog."""

    id: str
    rule_id: str
    name: str
    severity: str
    category: str = "PRIVILEGE_ESCALATION"
    cvss_score: float = 7.5
    description: str
    attack_vector: str
    mitigation: str
    remediation_guidance: str
    required_actions: List[str] = Field(default_factory=list)
    compute_service: str
    mitre_attack_id: Optional[str] = None


class RuleCatalogResponse(BaseModel):
    """Catalog listing response wrapper."""

    total_rules: int
    rules: List[RuleCatalogItem] = Field(default_factory=list)
