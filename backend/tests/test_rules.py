"""
backend/tests/test_rules.py

Unit tests verifying the 25 Privilege Escalation Detection Rules.
"""

import json
from pathlib import Path
import pytest
from app.core.rules_catalog import (
    RuleSeverity,
    EscalationRule,
    get_all_rules,
    get_rule_by_id,
    get_rules_by_severity,
    get_rules_by_service,
    evaluate_actions_against_rules,
)


class TestRulesCatalogIntegrity:
    """Verifies that all 25 rules conform to data constraints."""

    def test_total_rule_count(self):
        rules = get_all_rules()
        assert len(rules) == 25, f"Expected exactly 25 rules, found {len(rules)}"

    def test_unique_rule_ids(self):
        rules = get_all_rules()
        rule_ids = [r.rule_id for r in rules]
        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule_id detected in catalog"

    def test_required_metadata_fields(self):
        for r in get_all_rules():
            assert r.rule_id, "rule_id cannot be empty"
            assert r.name, f"{r.rule_id} missing name"
            assert isinstance(r.severity, RuleSeverity), f"{r.rule_id} invalid severity"
            assert 0.0 <= r.cvss_score <= 10.0, f"{r.rule_id} CVSS score out of range"
            assert r.description, f"{r.rule_id} missing description"
            assert r.attack_vector, f"{r.rule_id} missing attack_vector"
            assert len(r.required_actions) > 0, f"{r.rule_id} required_actions cannot be empty"
            assert len(r.required_resources) > 0, f"{r.rule_id} required_resources cannot be empty"
            assert r.compute_service, f"{r.rule_id} missing compute_service"
            assert r.remediation_guidance, f"{r.rule_id} missing remediation_guidance"

    def test_severity_breakdown(self):
        critical_rules = get_rules_by_severity(RuleSeverity.CRITICAL)
        high_rules = get_rules_by_severity(RuleSeverity.HIGH)
        medium_rules = get_rules_by_severity(RuleSeverity.MEDIUM)

        assert len(critical_rules) == 10, f"Expected 10 Critical rules, found {len(critical_rules)}"
        assert len(high_rules) == 14, f"Expected 14 High rules, found {len(high_rules)}"
        assert len(medium_rules) == 1, f"Expected 1 Medium rule, found {len(medium_rules)}"


class TestRuleMatchingLogic:
    """Verifies rule triggering behavior on positive, negative, and wildcard inputs."""

    def test_rule_crit_001_admin_wildcard(self):
        rule = get_rule_by_id("RULE_CRIT_001")
        assert rule is not None
        assert rule.is_action_satisfied({"*"})
        assert not rule.is_action_satisfied({"s3:GetObject", "ec2:DescribeInstances"})

    def test_rule_crit_002_create_policy_version_exact(self):
        rule = get_rule_by_id("RULE_CRIT_002")
        assert rule is not None
        assert rule.is_action_satisfied({"iam:CreatePolicyVersion"})
        assert rule.is_action_satisfied({"iam:*"})
        assert rule.is_action_satisfied({"*"})
        assert not rule.is_action_satisfied({"iam:GetPolicy", "iam:ListPolicies"})

    def test_rule_high_005_ec2_run_instances_passrole(self):
        rule = get_rule_by_id("RULE_HIGH_005")
        assert rule is not None
        # Satisfied when both are present
        assert rule.is_action_satisfied({"iam:PassRole", "ec2:RunInstances"})
        assert rule.is_action_satisfied({"iam:*", "ec2:*"})
        assert rule.is_action_satisfied({"*"})
        # Not satisfied when either action is missing
        assert not rule.is_action_satisfied({"iam:PassRole"})
        assert not rule.is_action_satisfied({"ec2:RunInstances"})

    def test_rule_high_006_lambda_create_invoke_passrole(self):
        rule = get_rule_by_id("RULE_HIGH_006")
        assert rule is not None
        assert rule.is_action_satisfied({"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"})
        assert not rule.is_action_satisfied({"iam:PassRole", "lambda:CreateFunction"})
        assert not rule.is_action_satisfied({"iam:PassRole", "lambda:InvokeFunction"})

    def test_rule_high_009_glue_dev_endpoint_alternatives(self):
        rule = get_rule_by_id("RULE_HIGH_009")
        assert rule is not None
        # Matches CreateDevEndpoint or UpdateDevEndpoint with PassRole
        assert rule.is_action_satisfied({"iam:PassRole", "glue:CreateDevEndpoint"})
        assert rule.is_action_satisfied({"iam:PassRole", "glue:UpdateDevEndpoint"})
        assert not rule.is_action_satisfied({"glue:CreateDevEndpoint"})
        assert not rule.is_action_satisfied({"iam:PassRole"})

    def test_rule_high_013_ecs_task_passrole(self):
        rule = get_rule_by_id("RULE_HIGH_013")
        assert rule is not None
        assert rule.is_action_satisfied({"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"})
        assert rule.is_action_satisfied({"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:StartTask"})
        assert not rule.is_action_satisfied({"iam:PassRole", "ecs:RegisterTaskDefinition"})

    def test_benign_policies_yield_no_findings(self):
        benign_auditor_actions = {
            "iam:GetAccountSummary", "iam:GetPolicy", "iam:GetRole",
            "iam:ListUsers", "iam:ListRoles", "ec2:DescribeInstances", "cloudtrail:LookupEvents"
        }
        triggered = evaluate_actions_against_rules(benign_auditor_actions)
        assert len(triggered) == 0, f"Expected 0 findings for benign auditor, found {len(triggered)}"

        benign_s3_actions = {"s3:GetObject", "s3:ListBucket"}
        triggered_s3 = evaluate_actions_against_rules(benign_s3_actions)
        assert len(triggered_s3) == 0, f"Expected 0 findings for benign S3, found {len(triggered_s3)}"


class TestSamplePolicyFixtures:
    """Verifies that all 25 sample JSON fixtures trigger their designated rule."""

    @pytest.mark.parametrize("rule_lookup_id,sample_file", [
        ("RULE_CRIT_001", "sample_rule_crit_001_admin_wildcard.json"),
        ("RULE_CRIT_002", "sample_rule_crit_002_create_policy_version.json"),
        ("RULE_CRIT_003", "sample_rule_crit_003_put_user_policy.json"),
        ("RULE_CRIT_004", "sample_rule_crit_004_put_group_policy.json"),
        ("RULE_CRIT_005", "sample_rule_crit_005_put_role_policy.json"),
        ("RULE_CRIT_006", "sample_rule_crit_006_attach_user_policy.json"),
        ("RULE_CRIT_007", "sample_rule_crit_007_attach_group_policy.json"),
        ("RULE_CRIT_008", "sample_rule_crit_008_attach_role_policy.json"),
        ("RULE_CRIT_009", "sample_rule_crit_009_add_user_to_group.json"),
        ("RULE_CRIT_010", "sample_rule_crit_010_update_assume_role_policy.json"),
        ("RULE_HIGH_001", "sample_rule_high_001_set_default_policy_version.json"),
        ("RULE_HIGH_002", "sample_rule_high_002_create_access_key.json"),
        ("RULE_HIGH_003", "sample_rule_high_003_create_login_profile.json"),
        ("RULE_HIGH_004", "sample_rule_high_004_update_login_profile.json"),
        ("RULE_HIGH_005", "sample_rule_high_005_ec2_run_instances_passrole.json"),
        ("RULE_HIGH_006", "sample_rule_high_006_lambda_create_invoke_passrole.json"),
        ("RULE_HIGH_007", "sample_rule_high_007_lambda_eventsource_passrole.json"),
        ("RULE_HIGH_008", "sample_rule_high_008_lambda_update_function_code.json"),
        ("RULE_HIGH_009", "sample_rule_high_009_glue_dev_endpoint_passrole.json"),
        ("RULE_HIGH_010", "sample_rule_high_010_cloudformation_create_stack_passrole.json"),
        ("RULE_HIGH_011", "sample_rule_high_011_datapipeline_passrole.json"),
        ("RULE_HIGH_012", "sample_rule_high_012_codebuild_passrole.json"),
        ("RULE_HIGH_013", "sample_rule_high_013_ecs_task_passrole.json"),
        ("RULE_HIGH_014", "sample_rule_high_014_sagemaker_notebook_passrole.json"),
        ("RULE_MED_001", "sample_rule_med_001_sts_assume_role.json"),
    ])
    def test_fixture_triggers_designated_rule(self, rule_lookup_id, sample_file, samples_dir):
        file_path = samples_dir / sample_file
        assert file_path.exists(), f"Sample fixture {sample_file} not found"

        with open(file_path, "r", encoding="utf-8") as f:
            policy_doc = json.load(f)

        actions = set()
        for stmt in policy_doc.get("Statement", []):
            raw_action = stmt.get("Action", [])
            if isinstance(raw_action, str):
                actions.add(raw_action)
            elif isinstance(raw_action, list):
                actions.update(raw_action)

        triggered_rules = evaluate_actions_against_rules(actions)
        matched_target_rule = get_rule_by_id(rule_lookup_id)
        assert matched_target_rule is not None
        assert matched_target_rule in triggered_rules, (
            f"Fixture {sample_file} failed to trigger {rule_lookup_id}. Triggered: {[r.rule_id for r in triggered_rules]}"
        )
