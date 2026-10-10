import pytest
from typing import Dict, Any

# Marker for Tier 1 tests
pytestmark = pytest.mark.tier1

class TestTier1ASTIngestion:
    """Feature 1: IAM Policy AST Ingestion & Normalization."""

    def test_t1_ast_001_single_statement_object_normalization(self):
        """Single Statement object normalized to list."""
        try:
            from app.core.ast_models import IAMPolicyDocument
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        doc = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }
        }
        parsed = IAMPolicyDocument.model_validate(doc) if hasattr(IAMPolicyDocument, "model_validate") else IAMPolicyDocument.parse_obj(doc)
        assert isinstance(parsed.statements, list)
        assert len(parsed.statements) == 1
        assert parsed.statements[0].effect.lower() == "allow"

    def test_t1_ast_002_single_action_and_resource_string_normalization(self):
        """Single string action and resource normalized to lists."""
        try:
            from app.core.ast_models import IAMStatement
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        raw_stmt = {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*"
        }
        stmt = IAMStatement.model_validate(raw_stmt) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj(raw_stmt)
        assert isinstance(stmt.action, list)
        assert len(stmt.action) == 1
        assert stmt.action[0].lower() == "iam:passrole"
        assert isinstance(stmt.resource, list)
        assert stmt.resource[0] == "*"

    def test_t1_ast_003_case_insensitive_action_normalization(self):
        """Action names normalized to lowercase for comparison."""
        try:
            from app.core.ast_models import IAMStatement
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        raw_stmt = {
            "Effect": "Allow",
            "Action": ["IAM:PassRole", "EC2:RunInstances", "s3:GETOBJECT"],
            "Resource": "*"
        }
        stmt = IAMStatement.model_validate(raw_stmt) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj(raw_stmt)
        actions = [a.lower() for a in stmt.action]
        assert "iam:passrole" in actions
        assert "ec2:runinstances" in actions
        assert "s3:getobject" in actions

    def test_t1_ast_004_polymorphic_principal_parsing(self):
        """Polymorphic Principal formats parse accurately."""
        try:
            from app.core.ast_models import IAMStatement
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        test_cases = [
            {"Effect": "Allow", "Principal": "arn:aws:iam::123456789012:root", "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": ["arn:aws:iam::123:user/a", "arn:aws:iam::123:user/b"], "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ]
        for tc in test_cases:
            stmt = IAMStatement.model_validate(tc) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj(tc)
            assert stmt.principal is not None

    def test_t1_ast_005_condition_block_normalization(self):
        """Condition block parsed into structured representation."""
        try:
            from app.core.ast_models import IAMStatement
        except ImportError:
            pytest.skip("app.core.ast_models not yet implemented")

        raw_stmt = {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": "ec2.amazonaws.com"
                }
            }
        }
        stmt = IAMStatement.model_validate(raw_stmt) if hasattr(IAMStatement, "model_validate") else IAMStatement.parse_obj(raw_stmt)
        assert stmt.conditions is not None or stmt.condition is not None


class TestTier1EvaluationEngine:
    """Feature 2: 3-Tier Evaluation Engine."""

    def test_t1_eval_001_explicit_allow(self):
        """Explicit Allow yields allow decision."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }
        result = evaluator.evaluate_permission(policy, action="s3:GetObject", resource="arn:aws:s3:::bucket/obj")
        assert result is True or getattr(result, "is_allowed", None) is True

    def test_t1_eval_002_explicit_deny_overrides_allow(self):
        """Explicit Deny overrides Allow on identical action and resource."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }
        result = evaluator.evaluate_permission(policy, action="s3:GetObject", resource="arn:aws:s3:::bucket/obj")
        assert result is False or getattr(result, "is_allowed", None) is False

    def test_t1_eval_003_default_deny(self):
        """Unmatched action defaults to deny decision."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }
        result = evaluator.evaluate_permission(policy, action="s3:PutObject", resource="arn:aws:s3:::bucket/obj")
        assert result is False or getattr(result, "is_allowed", None) is False

    def test_t1_eval_004_wildcard_action_matching(self):
        """Wildcard s3:* allows all s3 actions, denies others."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
        }
        for act in ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]:
            res = evaluator.evaluate_permission(policy, action=act, resource="*")
            assert res is True or getattr(res, "is_allowed", None) is True
        res_ec2 = evaluator.evaluate_permission(policy, action="ec2:DescribeInstances", resource="*")
        assert res_ec2 is False or getattr(res_ec2, "is_allowed", None) is False

    def test_t1_eval_005_prefix_wildcard_matching(self):
        """ec2:Describe* allows all describe actions, denies ec2:RunInstances."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]
        }
        res_desc = evaluator.evaluate_permission(policy, action="ec2:DescribeInstances", resource="*")
        assert res_desc is True or getattr(res_desc, "is_allowed", None) is True
        res_run = evaluator.evaluate_permission(policy, action="ec2:RunInstances", resource="*")
        assert res_run is False or getattr(res_run, "is_allowed", None) is False

    def test_t1_eval_006_notaction_semantics(self):
        """Effect Allow with NotAction iam:* allows non-IAM and denies IAM."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]
        }
        res_s3 = evaluator.evaluate_permission(policy, action="s3:GetObject", resource="*")
        assert res_s3 is True or getattr(res_s3, "is_allowed", None) is True
        res_iam = evaluator.evaluate_permission(policy, action="iam:PassRole", resource="*")
        assert res_iam is False or getattr(res_iam, "is_allowed", None) is False

    def test_t1_eval_007_notresource_semantics(self):
        """Effect Allow with NotResource allows all except specified resource."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "NotResource": "arn:aws:s3:::secret-bucket/*"
            }]
        }
        res_pub = evaluator.evaluate_permission(policy, action="s3:GetObject", resource="arn:aws:s3:::public-bucket/file")
        assert res_pub is True or getattr(res_pub, "is_allowed", None) is True
        res_sec = evaluator.evaluate_permission(policy, action="s3:GetObject", resource="arn:aws:s3:::secret-bucket/file")
        assert res_sec is False or getattr(res_sec, "is_allowed", None) is False


class TestTier1PrivilegeEscalationRules:
    """Feature 3 & 4: Privilege Escalation Vectors."""

    def test_t1_rule_001_create_policy_version(self):
        """PRIV_ESC_001 detected for iam:CreatePolicyVersion."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("001" in r for r in rule_ids)

    def test_t1_rule_002_set_default_policy_version(self):
        """PRIV_ESC_002 detected for iam:SetDefaultPolicyVersion."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:SetDefaultPolicyVersion", "Resource": "*"}]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("002" in r for r in rule_ids)

    def test_t1_rule_003_create_access_key(self):
        """PRIV_ESC_003 detected for iam:CreateAccessKey."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("003" in r for r in rule_ids)

    def test_t1_rule_004_create_login_profile(self):
        """PRIV_ESC_004 detected for iam:CreateLoginProfile."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:CreateLoginProfile", "Resource": "*"}]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("004" in r for r in rule_ids)

    def test_t1_rule_005_update_login_profile(self):
        """PRIV_ESC_005 detected for iam:UpdateLoginProfile."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:UpdateLoginProfile", "Resource": "*"}]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("005" in r for r in rule_ids)

    def test_t1_rule_006_attach_user_policy(self):
        """PRIV_ESC_006 detected for iam:AttachUserPolicy."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("006" in r for r in rule_ids)

    def test_t1_pass_001_passrole_ec2(self):
        """PRIV_ESC_014 detected for iam:PassRole + ec2:RunInstances."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole", "ec2:RunInstances"],
                "Resource": "*"
            }]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("014" in r for r in rule_ids)

    def test_t1_pass_002_passrole_lambda(self):
        """PRIV_ESC_015 detected for iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                "Resource": "*"
            }]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("015" in r for r in rule_ids)


class TestTier1AttackGraphAndAPI:
    """Feature 6 & 7: Attack Graph Generation & REST API."""

    def test_t1_graph_001_graph_nodes_and_edges(self):
        """Attack graph builder produces nodes and directed edges."""
        try:
            from app.core.graph_builder import GraphBuilder
        except ImportError:
            pytest.skip("app.core.graph_builder not yet implemented")

        builder = GraphBuilder()
        graph_data = builder.build_graph(
            policy_doc={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]},
            vulnerabilities=[]
        )
        assert "nodes" in graph_data
        assert "edges" in graph_data
        assert isinstance(graph_data["nodes"], list)
        assert isinstance(graph_data["edges"], list)

    @pytest.mark.asyncio
    async def test_t1_api_001_health_endpoint(self):
        """GET /api/health returns status ok."""
        from app.main import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["database"] == "connected"
