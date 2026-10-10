"""
backend/app/core/ast_models.py

Pydantic v2 data models and abstract syntax tree (AST) representations for
AWS Identity and Access Management (IAM) policy documents.
"""

from __future__ import annotations

import fnmatch
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EffectEnum(str, Enum):
    """Normalized statement effects."""
    ALLOW = "Allow"
    DENY = "Deny"


class SeverityEnum(str, Enum):
    """Vulnerability severity levels according to CVSS framework."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConditionBlock(BaseModel):
    """
    Normalized representation of a single condition clause within an IAM statement.
    Example: operator='StringEquals', key='iam:PassedToService', values=['ec2.amazonaws.com']
    """
    model_config = ConfigDict(frozen=True)

    operator: str
    key: str
    values: List[str]

    def matches_value(self, target_value: str) -> bool:
        """Evaluates whether the target value matches any condition values."""
        target_lower = target_value.lower()
        for val in self.values:
            val_lower = val.lower()
            if val_lower == "*" or val_lower == target_lower:
                return True
            if "*" in val or "?" in val:
                if fnmatch.fnmatchcase(target_lower, val_lower):
                    return True
        return False


class Statement(BaseModel):
    """
    Represents a normalized AWS IAM policy statement.
    Handles polymorphic Action/Resource/Principal, case normalization, and condition blocks.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore",
        frozen=False
    )

    sid: Optional[str] = Field(default=None, alias="Sid")
    effect: Literal["Allow", "Deny"] = Field(..., alias="Effect")
    principal: Optional[Union[str, Dict[str, List[str]]]] = Field(default=None, alias="Principal")
    not_principal: Optional[Union[str, Dict[str, List[str]]]] = Field(default=None, alias="NotPrincipal")
    action: List[str] = Field(default_factory=list, alias="Action")
    not_action: List[str] = Field(default_factory=list, alias="NotAction")
    resource: List[str] = Field(default_factory=list, alias="Resource")
    not_resource: List[str] = Field(default_factory=list, alias="NotResource")
    condition: Dict[str, Dict[str, Any]] = Field(default_factory=dict, alias="Condition")

    @property
    def conditions(self) -> Dict[str, Dict[str, Any]]:
        """Alias for condition property compatibility."""
        return self.condition

    @field_validator("effect", mode="before")
    @classmethod
    def normalize_effect(cls, v: Any) -> str:
        """Coerce effect to capitalized 'Allow' or 'Deny' regardless of input casing."""
        if not isinstance(v, str):
            raise ValueError("Effect must be a string")
        v_clean = v.strip().capitalize()
        if v_clean not in ("Allow", "Deny"):
            raise ValueError(f"Effect must be 'Allow' or 'Deny', got '{v}'")
        return v_clean

    @field_validator("action", "not_action", mode="before")
    @classmethod
    def normalize_actions(cls, v: Any) -> List[str]:
        """Convert single strings to lists and lowercase all action identifiers."""
        if v is None:
            return []
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, (list, set, tuple)):
            raise ValueError("Action/NotAction must be a string or list of strings")
        result: List[str] = []
        for item in v:
            clean_item = str(item).strip().lower()
            if clean_item:
                result.append(clean_item)
        return result

    @field_validator("resource", "not_resource", mode="before")
    @classmethod
    def normalize_resources(cls, v: Any) -> List[str]:
        """Convert single strings to lists and trim whitespace, preserving ARN case."""
        if v is None:
            return []
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, (list, set, tuple)):
            raise ValueError("Resource/NotResource must be a string or list of strings")
        result: List[str] = []
        for item in v:
            clean_item = str(item).strip()
            if clean_item:
                result.append(clean_item)
        return result

    @field_validator("principal", "not_principal", mode="before")
    @classmethod
    def normalize_principals(cls, v: Any) -> Optional[Union[str, Dict[str, List[str]]]]:
        """Normalize Principal structure into dictionary with list values or wildcard string."""
        if v is None:
            return None
        if isinstance(v, str):
            v_clean = v.strip()
            if v_clean == "*":
                return "*"
            return {"AWS": [v_clean]}
        if isinstance(v, (list, tuple)):
            return {"AWS": [str(item).strip() for item in v if str(item).strip()]}
        if isinstance(v, dict):
            normalized: Dict[str, List[str]] = {}
            for key, val in v.items():
                if isinstance(val, str):
                    normalized[key] = [val.strip()]
                elif isinstance(val, (list, tuple)):
                    normalized[key] = [str(item).strip() for item in val if str(item).strip()]
                else:
                    normalized[key] = [str(val).strip()]
            return normalized
        return None

    @field_validator("condition", mode="before")
    @classmethod
    def normalize_condition(cls, v: Any) -> Dict[str, Dict[str, Any]]:
        """Ensure condition block is a valid dictionary structure."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Condition must be a dictionary")
        return v

    @model_validator(mode="after")
    def validate_statement_integrity(self) -> "Statement":
        """Enforce mutual exclusivity and presence of statement keys."""
        if not self.action and not self.not_action:
            raise ValueError("Statement must specify either Action or NotAction")
        if self.action and self.not_action:
            raise ValueError("Statement cannot specify both Action and NotAction simultaneously")
        if not self.resource and not self.not_resource and not self.principal:
            raise ValueError("Statement must specify Resource, NotResource, or Principal")
        if self.resource and self.not_resource:
            raise ValueError("Statement cannot specify both Resource and NotResource simultaneously")
        return self

    def parsed_conditions(self) -> List[ConditionBlock]:
        """Flattens nested condition dictionary into a list of ConditionBlock objects."""
        blocks: List[ConditionBlock] = []
        for operator, key_map in self.condition.items():
            if not isinstance(key_map, dict):
                continue
            for key, val in key_map.items():
                if isinstance(val, list):
                    val_list = [str(x) for x in val]
                else:
                    val_list = [str(val)]
                blocks.append(ConditionBlock(operator=operator, key=key, values=val_list))
        return blocks


# Compatible alias for tests
IAMStatement = Statement


class PolicyDocument(BaseModel):
    """
    Root model representing a full AWS IAM policy document.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        extra="ignore"
    )

    version: Optional[str] = Field(default="2012-10-17", alias="Version")
    id: Optional[str] = Field(default=None, alias="Id")
    statement: List[Statement] = Field(..., alias="Statement")

    @property
    def statements(self) -> List[Statement]:
        """Alias property for statement list compatibility."""
        return self.statement

    @field_validator("version", mode="before")
    @classmethod
    def normalize_version(cls, v: Any) -> str:
        if v is None:
            return "2012-10-17"
        v_str = str(v).strip()
        if not v_str:
            return "2012-10-17"
        return v_str

    @field_validator("statement", mode="before")
    @classmethod
    def normalize_statement_list(cls, v: Any) -> List[Any]:
        """Wrap single statement object into a list and validate presence."""
        if v is None:
            raise ValueError("Statement cannot be None")
        if isinstance(v, dict):
            return [v]
        if isinstance(v, list):
            return v
        raise ValueError("Statement must be a dictionary or a list of dictionaries")

    @model_validator(mode="after")
    def assign_fallback_sids(self) -> "PolicyDocument":
        """Assign deterministic fallback Sids to statements missing explicit Sid."""
        for idx, stmt in enumerate(self.statement, start=1):
            if not stmt.sid or not str(stmt.sid).strip():
                stmt.sid = f"stmt_{idx}"
        return self


# Compatible alias for tests
IAMPolicyDocument = PolicyDocument


class ActionSet:
    """
    High-performance utility wrapping a collection of normalized actions.
    Provides fast wildcard matching and set operations.
    """
    def __init__(self, actions: Optional[List[str]] = None):
        self._actions: List[str] = [a.strip().lower() for a in (actions or []) if a.strip()]
        self._has_all_wildcard: bool = "*" in self._actions

    @property
    def raw_actions(self) -> List[str]:
        return list(self._actions)

    def is_wildcard_all(self) -> bool:
        return self._has_all_wildcard

    def matches(self, target_action: str) -> bool:
        """
        Evaluates if target_action matches any pattern in the action set.
        Supports standard AWS wildcards (*, ?).
        """
        target = target_action.strip().lower()
        if self._has_all_wildcard:
            return True
        for pattern in self._actions:
            if pattern == target:
                return True
            if "*" in pattern or "?" in pattern:
                if fnmatch.fnmatchcase(target, pattern):
                    return True
        return False

    def matches_all(self, target_actions: List[str]) -> bool:
        """Returns True if every target action matches at least one pattern."""
        return all(self.matches(act) for act in target_actions)

    def matches_any(self, target_actions: List[str]) -> bool:
        """Returns True if at least one target action matches."""
        return any(self.matches(act) for act in target_actions)

    def filter_matching(self, target_actions: List[str]) -> List[str]:
        """Returns the subset of target_actions that match patterns in this set."""
        return [act for act in target_actions if self.matches(act)]


class ResourceSet:
    """
    Utility wrapping resource ARN patterns with wildcard matching.
    """
    def __init__(self, resources: Optional[List[str]] = None):
        self._resources: List[str] = [r.strip() for r in (resources or []) if r.strip()]
        self._has_all_wildcard: bool = "*" in self._resources

    @property
    def raw_resources(self) -> List[str]:
        return list(self._resources)

    def is_wildcard_all(self) -> bool:
        return self._has_all_wildcard

    def matches(self, target_resource: str) -> bool:
        """
        Evaluates whether target_resource matches any pattern in this resource set.
        """
        target = target_resource.strip()
        if self._has_all_wildcard:
            return True
        target_lower = target.lower()
        for pattern in self._resources:
            if pattern == target:
                return True
            pattern_lower = pattern.lower()
            if pattern_lower == target_lower:
                return True
            if "*" in pattern or "?" in pattern:
                if fnmatch.fnmatchcase(target_lower, pattern_lower):
                    return True
        return False


class VulnerabilityFinding(BaseModel):
    """
    Represents a detected security finding or privilege escalation vector.
    """
    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    severity: SeverityEnum
    cvss_score: float
    attack_vector: str
    affected_actions: List[str]
    affected_resources: List[str]
    statement_sids: List[str]
    remediation: str
    alt_id: Optional[str] = None
    compute_service: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    is_mitigated: bool = False


class EvaluationResult(BaseModel):
    """
    Top-level output of the policy evaluation engine.
    Satisfies contract between Core Evaluator, FastAPI service, and attack graph builder.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_valid: bool = True
    policy_version: Optional[str] = "2012-10-17"
    statement_count: int = 0
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    graph_data: Dict[str, Any] = Field(default_factory=lambda: {"nodes": [], "edges": []})
    allowed_actions_summary: List[str] = Field(default_factory=list)
    denied_actions_summary: List[str] = Field(default_factory=list)
    raw_policy: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)
