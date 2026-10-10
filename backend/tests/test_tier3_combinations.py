import pytest
from typing import Dict, Any

pytestmark = pytest.mark.tier3

class TestTier3CrossFeatureCombinations:
    """Tier 3: Pairwise and Cross-Feature Combinations."""

    def test_t3_comb_001_multi_statement_distributed_passrole_lambda(self):
        """PassRole in Statement 1 and Lambda in Statement 2 triggers PRIV_ESC_015."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "GrantPassRole",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*"
                },
                {
                    "Sid": "GrantLambdaCompute",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:CreateFunction",
                        "lambda:InvokeFunction"
                    ],
                    "Resource": "*"
                }
            ]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("015" in r for r in rule_ids)

    def test_t3_comb_002_condition_suppression_attach_user_policy(self):
        """AttachUserPolicy with condition restricting to read-only policy downgrades risk."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedAttachUserPolicy",
                    "Effect": "Allow",
                    "Action": "iam:AttachUserPolicy",
                    "Resource": "*",
                    "Condition": {
                        "ArnEquals": {
                            "iam:PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
                        }
                    }
                }
            ]
        }
        result = evaluator.evaluate_policy(policy)
        # If finding is generated, its severity or risk score should reflect condition mitigation
        for v in result.vulnerabilities:
            if "006" in v.rule_id:
                assert getattr(v, "is_mitigated", False) or result.risk_score < 90

    def test_t3_comb_003_deny_statement_prunes_passrole_combo(self):
        """Deny on ec2:RunInstances prevents PRIV_ESC_014 despite PassRole."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPassRoleAndEC2",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "ec2:RunInstances"],
                    "Resource": "*"
                },
                {
                    "Sid": "ExplicitDenyEC2Run",
                    "Effect": "Deny",
                    "Action": "ec2:RunInstances",
                    "Resource": "*"
                }
            ]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert not any("014" in r for r in rule_ids)

    def test_t3_comb_004_combined_create_and_set_default_policy_version(self):
        """Both PRIV_ESC_001 and PRIV_ESC_002 triggered in same scan."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VersionVectors",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreatePolicyVersion",
                        "iam:SetDefaultPolicyVersion"
                    ],
                    "Resource": "*"
                }
            ]
        }
        result = evaluator.evaluate_policy(policy)
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any("001" in r for r in rule_ids)
        assert any("002" in r for r in rule_ids)

    def test_t3_comb_005_path_restricted_user_actions(self):
        """Access key creation allowed on dev path, denied on admin path."""
        try:
            from app.core.evaluator import PolicyEvaluator
        except ImportError:
            pytest.skip("app.core.evaluator not yet implemented")

        evaluator = PolicyEvaluator()
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDevKeys",
                    "Effect": "Allow",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "arn:aws:iam::123:user/dev/*"
                },
                {
                    "Sid": "DenyAdminKeys",
                    "Effect": "Deny",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "arn:aws:iam::123:user/admin/*"
                }
            ]
        }
        dev_res = evaluator.evaluate_permission(policy, action="iam:CreateAccessKey", resource="arn:aws:iam::123:user/dev/alice")
        admin_res = evaluator.evaluate_permission(policy, action="iam:CreateAccessKey", resource="arn:aws:iam::123:user/admin/root")
        assert dev_res is True or getattr(dev_res, "is_allowed", None) is True
        assert admin_res is False or getattr(admin_res, "is_allowed", None) is False

    @pytest.mark.asyncio
    async def test_t3_comb_007_api_persistent_scan_lifecycle(self):
        """Full scan lifecycle: create scan -> get scan -> get graph -> verify consistency."""
        from app.main import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create scan
            create_payload = {
                "title": "Lifecycle Test Scan",
                "policy_json": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "iam:CreatePolicyVersion",
                        "Resource": "*"
                    }]
                }
            }
            create_resp = await client.post("/api/scans", json=create_payload)
            assert create_resp.status_code in (200, 201)

            scan_data = create_resp.json()
            scan_id = scan_data.get("id") or scan_data.get("scan_id")
            assert scan_id is not None

            # 2. Retrieve scan
            get_resp = await client.get(f"/api/scans/{scan_id}")
            assert get_resp.status_code == 200
            get_data = get_resp.json()
            assert (get_data.get("id") or get_data.get("scan_id")) == scan_id

            # 3. Retrieve graph
            graph_resp = await client.get(f"/api/scans/{scan_id}/graph")
            assert graph_resp.status_code == 200
            graph_data = graph_resp.json()
            assert "nodes" in graph_data
            assert "edges" in graph_data
