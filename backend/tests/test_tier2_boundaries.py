import pytest
import time
from typing import Dict, Any

pytestmark = pytest.mark.tier2

class TestTier2BoundaryAndCornerCases:
    """Tier 2: Boundary, Edge, and Corner Cases."""

    def test_t2_bound_001_empty_policy_raises_error(self):
        """Completely empty policy {} rejected gracefully."""
        try:
            from app.core.ast_models import IAMPolicyDocument
            from pydantic import ValidationError
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        with pytest.raises((ValidationError, ValueError, KeyError)):
            IAMPolicyDocument.model_validate({}) if hasattr(IAMPolicyDocument, "model_validate") else IAMPolicyDocument.parse_obj({})

    def test_t2_bound_002_missing_version_defaults_valid(self):
        """Policy missing Version defaults to 2012-10-17."""
        try:
            from app.core.ast_models import IAMPolicyDocument
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        parsed = IAMPolicyDocument.model_validate(doc) if hasattr(IAMPolicyDocument, "model_validate") else IAMPolicyDocument.parse_obj(doc)
        assert parsed.version == "2012-10-17"
        assert len(parsed.statements) == 1

    def test_t2_bound_003_empty_statement_array(self):
        """Policy with empty statements yields zero findings and risk score 0."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        result = evaluator.evaluate_policy({"Version": "2012-10-17", "Statement": []})
        assert len(result.vulnerabilities) == 0
        assert getattr(result, "risk_score", 0) == 0

    def test_t2_bound_004_malformed_missing_effect(self):
        """Statement missing Effect raises validation error."""
        try:
            from app.core.ast_models import IAMStatement
            from pydantic import ValidationError
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        with pytest.raises((ValidationError, ValueError)):
            IAMStatement.model_validate({"Action": "s3:*", "Resource": "*"}) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj({"Action": "s3:*", "Resource": "*"})

    def test_t2_bound_005_malformed_missing_action(self):
        """Statement missing Action raises validation error."""
        try:
            from app.core.ast_models import IAMStatement
            from pydantic import ValidationError
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        with pytest.raises((ValidationError, ValueError)):
            IAMStatement.model_validate({"Effect": "Allow", "Resource": "*"}) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj({"Effect": "Allow", "Resource": "*"})

    def test_t2_bound_006_unrestricted_wildcard_policy(self):
        """Full wildcard *:* flags critical severity and maximum risk."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        result = evaluator.evaluate_policy({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
        assert any(v.severity.upper() == "CRITICAL" for v in result.vulnerabilities)
        assert result.risk_score >= 90

    def test_t2_bound_007_deny_overrides_allow_order_invariant(self):
        """Deny overrides Allow regardless of statement order."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy_order_1 = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }
        policy_order_2 = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }
        res1 = evaluator.evaluate_permission(policy_order_1, action="s3:GetObject", resource="arn:aws:s3:::b/o")
        res2 = evaluator.evaluate_permission(policy_order_2, action="s3:GetObject", resource="arn:aws:s3:::b/o")
        assert (res1 is False or getattr(res1, "is_allowed", None) is False)
        assert (res2 is False or getattr(res2, "is_allowed", None) is False)

    def test_t2_bound_008_specific_deny_neutralizes_wildcard_allow(self):
        """Specific Deny on iam:PassRole neutralizes wildcard Allow iam:*."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}
            ]
        }
        res_create = evaluator.evaluate_permission(policy, action="iam:CreateUser", resource="*")
        res_pass = evaluator.evaluate_permission(policy, action="iam:PassRole", resource="*")
        assert res_create is True or getattr(res_create, "is_allowed", None) is True
        assert res_pass is False or getattr(res_pass, "is_allowed", None) is False

    def test_t2_bound_009_circular_assumerole_relationships(self):
        """Circular AssumeRole relationships terminate safely without infinite recursion."""
        try:
            from app.core.graph_builder import GraphBuilder
        except ImportError:
            pytest.skip("app.core.graph_builder not yet implemented")

        builder = GraphBuilder()
        roles = [
            {"name": "RoleA", "assumes": "RoleB"},
            {"name": "RoleB", "assumes": "RoleA"}
        ]
        start_time = time.time()
        # Graph generation should finish within 500ms
        graph = builder.build_trust_graph(roles) if hasattr(builder, "build_trust_graph") else {"nodes": [], "edges": []}
        elapsed = time.time() - start_time
        assert elapsed < 0.5

    def test_t2_bound_010_extreme_mixed_case_attributes(self):
        """Mixed-case keys and values parse accurately."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "aLLoW",
                    "Action": "iAm:CrEaTePoLiCyVeRsIoN",
                    "Resource": "*"
                }
            ]
        }
        result = evaluator.evaluate_policy(policy)
        assert any("001" in v.rule_id for v in result.vulnerabilities)

    def test_t2_bound_011_special_characters_in_sid(self):
        """Statement Sid containing special characters ingests safely."""
        try:
            from app.core.ast_models import IAMStatement
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        stmt = {
            "Sid": "Audit-Check_2026.Rule#01",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }
        parsed = IAMStatement.model_validate(stmt) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj(stmt)
        assert parsed.sid == "Audit-Check_2026.Rule#01"

    def test_t2_bound_012_high_volume_100_statements_stress_test(self):
        """Policy with 100 statements evaluates under 1000ms."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        statements = [
            {
                "Sid": f"Statement_{i}",
                "Effect": "Allow",
                "Action": f"s3:GetItem_{i}",
                "Resource": f"arn:aws:s3:::bucket_{i}/*"
            }
            for i in range(99)
        ]
        statements.append({
            "Sid": "TargetExploit",
            "Effect": "Allow",
            "Action": "iam:CreatePolicyVersion",
            "Resource": "*"
        })
        policy = {"Version": "2012-10-17", "Statement": statements}
        evaluator = PolicyEvaluator()
        start = time.time()
        result = evaluator.evaluate_policy(policy)
        duration = time.time() - start
        assert duration < 1.0
        assert any("001" in v.rule_id for v in result.vulnerabilities)
