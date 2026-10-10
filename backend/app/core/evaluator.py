"""
backend/app/core/evaluator.py

Core IAM policy evaluation engine implementing the 3-tier resolution algorithm
(Strict Deny > Allow > Default Deny) and orchestrating vulnerability detection.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union
from pydantic import ValidationError

from app.core.ast_models import (
    ActionSet,
    EffectEnum,
    EvaluationResult,
    PolicyDocument,
    ResourceSet,
    SeverityEnum,
    Statement,
    VulnerabilityFinding,
)
from app.core.rules_catalog import RULES_CATALOG, EscalationRule


class PolicyValidationError(Exception):
    """Raised when an IAM policy document cannot be parsed or validated."""
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or [message]


class PolicyEvaluator:
    """
    Evaluator executing AWS IAM evaluation logic and vulnerability detection.
    """

    def __init__(
        self,
        rules_catalog: Optional[Any] = None,
        graph_builder: Optional[Any] = None
    ):
        """
        Initializes evaluator with optional dependencies for rules catalog
        and attack graph generator, enabling clean mocking and test isolation.
        """
        self.rules_catalog = rules_catalog
        self.graph_builder = graph_builder

    def parse_policy(self, raw_input: Union[str, Dict[str, Any], PolicyDocument]) -> PolicyDocument:
        """
        Parses JSON string or dictionary into a validated PolicyDocument AST.
        """
        if isinstance(raw_input, PolicyDocument):
            return raw_input

        if isinstance(raw_input, str):
            try:
                data = json.loads(raw_input)
            except json.JSONDecodeError as err:
                raise PolicyValidationError(f"Invalid JSON format: {err.msg}", [str(err)])
        elif isinstance(raw_input, dict):
            data = raw_input
        else:
            raise PolicyValidationError("Policy input must be a JSON string, dict, or PolicyDocument")

        try:
            return PolicyDocument.model_validate(data)
        except ValidationError as err:
            error_msgs = [f"{e['loc']}: {e['msg']}" for e in err.errors()]
            raise PolicyValidationError("Policy document schema validation failed", error_msgs)

    @staticmethod
    def statement_matches_action(stmt: Statement, action: str) -> bool:
        """
        Determines whether a statement matches the target action,
        evaluating Action and NotAction clauses.
        """
        action_clean = action.strip().lower()
        if stmt.action:
            action_set = ActionSet(stmt.action)
            return action_set.matches(action_clean)
        elif stmt.not_action:
            not_action_set = ActionSet(stmt.not_action)
            # NotAction matches if action does NOT match any excluded pattern
            return not not_action_set.matches(action_clean)
        return False

    @staticmethod
    def statement_matches_resource(stmt: Statement, resource: str) -> bool:
        """
        Determines whether a statement matches the target resource,
        evaluating Resource and NotResource clauses.
        """
        resource_clean = resource.strip()
        if resource_clean == "*":
            # For wildcard query, an Allow statement matches if it grants permissions on any resource
            if stmt.effect == "Allow":
                return bool(stmt.resource or stmt.not_resource or stmt.principal)
            # A Deny statement on a wildcard query matches if it denies broadly on '*'
            if stmt.resource:
                return ResourceSet(stmt.resource).is_wildcard_all()
            if stmt.not_resource:
                return True
            return True

        if stmt.resource:
            resource_set = ResourceSet(stmt.resource)
            return resource_set.matches(resource_clean)
        elif stmt.not_resource:
            not_resource_set = ResourceSet(stmt.not_resource)
            # NotResource matches if resource does NOT match any excluded pattern
            return not not_resource_set.matches(resource_clean)
        # If neither Resource nor NotResource is set, matches all by default
        return True

    def evaluate_action(
        self,
        policy: PolicyDocument,
        action: str,
        resource: str = "*",
        service_context: Optional[str] = None
    ) -> EffectEnum:
        """
        Evaluates an action against a policy document following 3-tier logic:
        1. Explicit Deny: returns DENY if any matching Deny statement exists.
        2. Explicit Allow: returns ALLOW if any matching Allow statement exists.
        3. Default Deny: returns DENY if no statements match.
        """
        action_clean = action.strip().lower()

        # Step 1: Explicit Deny Check
        for stmt in policy.statement:
            if stmt.effect == "Deny":
                if self.statement_matches_action(stmt, action_clean) and self.statement_matches_resource(stmt, resource):
                    return EffectEnum.DENY

        # Step 2: Explicit Allow Check
        for stmt in policy.statement:
            if stmt.effect == "Allow":
                if self.statement_matches_action(stmt, action_clean) and self.statement_matches_resource(stmt, resource):
                    # Check condition restriction if service_context provided
                    if service_context and not self._check_condition_context(stmt, service_context):
                        continue
                    return EffectEnum.ALLOW

        # Step 3: Default Deny
        return EffectEnum.DENY

    def is_action_allowed(
        self,
        policy: PolicyDocument,
        action: str,
        resource: str = "*",
        service_context: Optional[str] = None
    ) -> bool:
        """Convenience method returning True if action evaluation resolves to ALLOW."""
        return self.evaluate_action(policy, action, resource, service_context) == EffectEnum.ALLOW

    def evaluate_permission(
        self,
        policy_input: Union[str, Dict[str, Any], PolicyDocument],
        action: str,
        resource: str = "*",
        service_context: Optional[str] = None
    ) -> bool:
        """
        Public evaluation method taking arbitrary policy input (dict, json str, PolicyDocument)
        and returning True if allowed, False otherwise.
        """
        try:
            policy = self.parse_policy(policy_input)
        except PolicyValidationError:
            return False
        return self.is_action_allowed(policy, action, resource, service_context)

    def are_actions_allowed(
        self,
        policy: PolicyDocument,
        actions: List[str],
        resource: str = "*",
        service_context: Optional[str] = None
    ) -> bool:
        """Evaluates whether ALL listed actions resolve to ALLOW."""
        return all(self.is_action_allowed(policy, act, resource, service_context) for act in actions)

    def get_effective_allowed_actions(
        self,
        policy: PolicyDocument,
        candidate_actions: List[str],
        resource: str = "*"
    ) -> List[str]:
        """Returns the subset of candidate actions that resolve to ALLOW."""
        return [act for act in candidate_actions if self.is_action_allowed(policy, act, resource)]

    def is_full_admin(self, policy: PolicyDocument) -> bool:
        """Returns True if the policy allows wildcard '*' on resource '*' without Deny."""
        return self.is_action_allowed(policy, "*", "*")

    def _check_condition_context(self, stmt: Statement, service_context: str) -> bool:
        """
        Evaluates condition blocks for service delegation constraints.
        Example: iam:PassedToService constraint for PassRole actions.
        """
        passed_services = self.get_passed_to_services(stmt)
        if passed_services is not None:
            # Condition is present; service_context must match
            return any(
                srv == "*" or srv.lower() == service_context.lower()
                for srv in passed_services
            )
        return True

    @staticmethod
    def get_passed_to_services(stmt: Statement) -> Optional[List[str]]:
        """
        Extracts services from iam:PassedToService condition key if present.
        Returns None if no such condition exists.
        """
        for block in stmt.parsed_conditions():
            if block.key.lower() == "iam:passedtoservice":
                return block.values
        return None

    def calculate_risk_score(self, findings: List[VulnerabilityFinding]) -> int:
        """
        Calculates aggregate risk score from 0 to 100 based on finding severities.
        """
        if not findings:
            return 0

        score = 0
        has_critical = False
        has_wildcard_admin = False
        has_high = False
        has_medium = False
        has_low = False

        for f in findings:
            if getattr(f, "is_mitigated", False):
                # Mitigated findings contribute minor risk
                score += 5
                continue

            if f.severity == SeverityEnum.CRITICAL:
                score += 35
                has_critical = True
                if f.rule_id in ("PRIV_ESC_025", "RULE_CRIT_001"):
                    has_wildcard_admin = True
            elif f.severity == SeverityEnum.HIGH:
                score += 20
                has_high = True
            elif f.severity == SeverityEnum.MEDIUM:
                score += 10
                has_medium = True
            elif f.severity == SeverityEnum.LOW:
                score += 3
                has_low = True

        if has_wildcard_admin:
            score = max(score, 95)
        elif has_critical:
            score = max(score, 85)
        elif has_high:
            score = max(score, 75)
        elif has_medium:
            score = max(score, 40)
        elif has_low:
            score = max(score, 15)

        return min(score, 100)

    def evaluate_policy(
        self,
        raw_input: Union[str, Dict[str, Any], PolicyDocument],
        principal_arn: Optional[str] = None
    ) -> EvaluationResult:
        """
        Main entry point. Ingests policy document, evaluates detection rules,
        builds attack graph data, and returns an EvaluationResult.
        """
        try:
            policy = self.parse_policy(raw_input)
        except PolicyValidationError as err:
            return EvaluationResult(
                is_valid=False,
                errors=err.errors,
                risk_score=0,
                vulnerabilities=[]
            )

        if not policy.statement:
            # Empty statement array yields 0 findings and 0 score
            return EvaluationResult(
                is_valid=True,
                policy_version=policy.version,
                statement_count=0,
                vulnerabilities=[],
                risk_score=0,
                graph_data={"nodes": [], "edges": []},
                allowed_actions_summary=[],
                denied_actions_summary=[],
                raw_policy=raw_input if isinstance(raw_input, dict) else {},
                errors=[]
            )

        # Run privilege escalation detection rules
        findings = self._evaluate_all_rules(policy)
        risk_score = self.calculate_risk_score(findings)

        # Generate attack graph data if graph builder available or import default
        graph_data: Dict[str, Any] = {"nodes": [], "edges": []}
        if self.graph_builder is not None:
            if hasattr(self.graph_builder, "build_graph"):
                graph_data = self.graph_builder.build_graph(
                    policy_doc=policy.model_dump(by_alias=True),
                    vulnerabilities=[f.model_dump() for f in findings],
                    principal_arn=principal_arn
                )
            elif hasattr(self.graph_builder, "build_from_evaluation"):
                graph = self.graph_builder.build_from_evaluation(
                    policy_name="EvaluatedPolicy",
                    statements=[s.model_dump(by_alias=True) for s in policy.statement],
                    vulnerabilities=[f.model_dump() for f in findings]
                )
                from app.core.graph_builder import AttackGraphBuilder
                graph_data = AttackGraphBuilder.to_react_flow(graph)
        else:
            # Inline attack graph generation
            try:
                from app.core.graph_builder import AttackGraphBuilder
                builder = AttackGraphBuilder(principal_arn=principal_arn)
                graph = builder.build_from_evaluation(
                    policy_name="EvaluatedPolicy",
                    statements=[s.model_dump(by_alias=True) for s in policy.statement],
                    vulnerabilities=[f.model_dump() for f in findings]
                )
                graph_data = AttackGraphBuilder.to_react_flow(graph)
            except Exception:
                graph_data = {"nodes": [], "edges": []}

        # Compute summary actions
        summary_candidates = [
            "iam:passrole", "iam:createpolicyversion", "iam:putuserpolicy",
            "iam:attachuserpolicy", "ec2:runinstances", "lambda:createfunction",
            "sts:assumerole", "*"
        ]
        allowed_summary = self.get_effective_allowed_actions(policy, summary_candidates)
        denied_summary = [act for act in summary_candidates if not self.is_action_allowed(policy, act)]

        raw_dict = raw_input if isinstance(raw_input, dict) else (
            json.loads(raw_input) if isinstance(raw_input, str) else policy.model_dump(by_alias=True)
        )

        return EvaluationResult(
            is_valid=True,
            policy_version=policy.version,
            statement_count=len(policy.statement),
            vulnerabilities=findings,
            risk_score=risk_score,
            graph_data=graph_data,
            allowed_actions_summary=allowed_summary,
            denied_actions_summary=denied_summary,
            raw_policy=raw_dict,
            errors=[]
        )

    def _evaluate_all_rules(self, policy: PolicyDocument) -> List[VulnerabilityFinding]:
        """
        Evaluates the policy document against all 25 escalation rules.
        """
        findings: List[VulnerabilityFinding] = []
        rules = getattr(self.rules_catalog, "get_all_rules", lambda: RULES_CATALOG)()

        for rule in rules:
            if self._is_rule_triggered(policy, rule):
                matched_sids = self._get_matching_sids(policy, rule)
                is_mitigated = self._check_rule_mitigation(policy, rule)

                findings.append(VulnerabilityFinding(
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=SeverityEnum(rule.severity.value),
                    cvss_score=rule.cvss_score,
                    attack_vector=rule.attack_vector,
                    affected_actions=rule.required_actions,
                    affected_resources=rule.required_resources,
                    statement_sids=matched_sids or ["stmt_1"],
                    remediation=rule.remediation_guidance,
                    alt_id=rule.alt_id,
                    compute_service=rule.compute_service,
                    mitre_attack_id=rule.mitre_attack_id,
                    is_mitigated=is_mitigated
                ))

        return findings

    def _is_rule_triggered(self, policy: PolicyDocument, rule: EscalationRule) -> bool:
        """
        Checks whether all required actions and conditions for a rule are satisfied.
        """
        # Rule 25: Full Administrator Wildcard Access
        if rule.rule_id in ("PRIV_ESC_025", "RULE_CRIT_001"):
            return self.is_action_allowed(policy, "*", "*") and any(
                s.effect == "Allow" and "*" in s.action and "*" in s.resource for s in policy.statement
            )

        # Service delegation context mapping for PassRole rules
        service_context_map = {
            "PRIV_ESC_014": "ec2.amazonaws.com",
            "PRIV_ESC_015": "lambda.amazonaws.com",
            "PRIV_ESC_016": "lambda.amazonaws.com",
            "PRIV_ESC_018": "glue.amazonaws.com",
            "PRIV_ESC_019": "cloudformation.amazonaws.com",
            "PRIV_ESC_020": "datapipeline.amazonaws.com",
            "PRIV_ESC_021": "codebuild.amazonaws.com",
            "PRIV_ESC_022": "ecs-tasks.amazonaws.com",
            "PRIV_ESC_023": "sagemaker.amazonaws.com",
        }
        service_context = service_context_map.get(rule.rule_id)

        # If rule defines action_groups (e.g. glue, cloudformation, ecs)
        if rule.action_groups:
            for group in rule.action_groups:
                group_allowed = False
                for action in group:
                    ctx = service_context if action.lower() == "iam:passrole" else None
                    if self.is_action_allowed(policy, action, service_context=ctx):
                        group_allowed = True
                        break
                if not group_allowed:
                    return False
            return True

        # Default required actions check
        for action in rule.required_actions:
            ctx = service_context if action.lower() == "iam:passrole" else None
            if not self.is_action_allowed(policy, action, service_context=ctx):
                return False

        return True

    def _get_matching_sids(self, policy: PolicyDocument, rule: EscalationRule) -> List[str]:
        """Extracts statement SIDs that grant the actions for this rule."""
        matched_sids = []
        required_lower = [a.lower() for a in rule.required_actions]
        for stmt in policy.statement:
            if stmt.effect == "Allow":
                if "*" in stmt.action:
                    matched_sids.append(stmt.sid)
                else:
                    stmt_actions_lower = [a.lower() for a in stmt.action]
                    if any(ActionSet(stmt_actions_lower).matches(req) for req in required_lower):
                        matched_sids.append(stmt.sid)
        return list(dict.fromkeys(matched_sids))

    def _check_rule_mitigation(self, policy: PolicyDocument, rule: EscalationRule) -> bool:
        """
        Determines whether conditions in the policy mitigate the finding risk
        (e.g., scoping AttachUserPolicy to ReadOnlyAccess).
        """
        if rule.rule_id in ("PRIV_ESC_006", "RULE_CRIT_006"):
            for stmt in policy.statement:
                if stmt.effect == "Allow" and ActionSet(stmt.action).matches("iam:attachuserpolicy"):
                    for cond in stmt.parsed_conditions():
                        key_lower = cond.key.lower()
                        if "policyarn" in key_lower:
                            for val in cond.values:
                                if "readonly" in val.lower() or "viewonly" in val.lower():
                                    return True
        return False
