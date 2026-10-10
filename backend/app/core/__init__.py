"""
Core IAM analysis, evaluation, privilege escalation detection, and attack graph generation.
"""

from app.core.ast_models import (
    ActionSet,
    ConditionBlock,
    EffectEnum,
    EvaluationResult,
    IAMPolicyDocument,
    IAMStatement,
    PolicyDocument,
    ResourceSet,
    SeverityEnum,
    Statement,
    VulnerabilityFinding,
)
from app.core.evaluator import PolicyEvaluator, PolicyValidationError
from app.core.graph_builder import (
    AttackGraph,
    AttackGraphBuilder,
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    EdgeType,
    GraphBuilder,
    GraphSeverity,
    NodeType,
)
from app.core.rules_catalog import (
    RULES_BY_ID,
    RULES_CATALOG,
    EscalationRule,
    RuleSeverity,
    evaluate_actions_against_rules,
    get_all_rules,
    get_rule_by_id,
    get_rules_by_service,
    get_rules_by_severity,
)

__all__ = [
    "ActionSet",
    "ConditionBlock",
    "EffectEnum",
    "EvaluationResult",
    "IAMPolicyDocument",
    "IAMStatement",
    "PolicyDocument",
    "ResourceSet",
    "SeverityEnum",
    "Statement",
    "VulnerabilityFinding",
    "PolicyEvaluator",
    "PolicyValidationError",
    "AttackGraph",
    "AttackGraphBuilder",
    "AttackGraphEdge",
    "AttackGraphNode",
    "AttackPath",
    "EdgeType",
    "GraphBuilder",
    "GraphSeverity",
    "NodeType",
    "RULES_BY_ID",
    "RULES_CATALOG",
    "EscalationRule",
    "RuleSeverity",
    "evaluate_actions_against_rules",
    "get_all_rules",
    "get_rule_by_id",
    "get_rules_by_service",
    "get_rules_by_severity",
]
