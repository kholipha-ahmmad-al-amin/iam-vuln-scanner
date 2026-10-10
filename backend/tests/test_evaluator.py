"""
backend/tests/test_evaluator.py

Unit tests for IAM Policy Evaluator Core and 3-tier resolution engine.
"""

import pytest
from app.core.ast_models import EffectEnum, PolicyDocument, SeverityEnum
from app.core.evaluator import PolicyEvaluator, PolicyValidationError


@pytest.fixture
def evaluator():
    return PolicyEvaluator()


def test_evaluator_explicit_deny_overrides_allow(evaluator):
    """Verifies that an explicit Deny statement strictly overrides an Allow statement."""
    policy_data = {
        "Statement": [
            {
                "Sid": "AllowPassRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*"
            },
            {
                "Sid": "DenyPassRole",
                "Effect": "Deny",
                "Action": "iam:PassRole",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    decision = evaluator.evaluate_action(policy, "iam:passrole")
    assert decision == EffectEnum.DENY
    assert evaluator.is_action_allowed(policy, "iam:passrole") is False


def test_evaluator_wildcard_deny_overrides_specific_allow(evaluator):
    """Verifies that a broad wildcard Deny overrides a specific Allow."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:CreatePolicyVersion",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "iam:*",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    assert evaluator.is_action_allowed(policy, "iam:createpolicyversion") is False


def test_evaluator_specific_deny_preserves_other_allows(evaluator):
    """Verifies that a specific Deny only blocks targeted actions, leaving other Allowed actions valid."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "iam:CreatePolicyVersion",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    assert evaluator.is_action_allowed(policy, "iam:createpolicyversion") is False
    assert evaluator.is_action_allowed(policy, "iam:passrole") is True
    assert evaluator.is_action_allowed(policy, "iam:createuser") is True


def test_evaluator_default_deny(evaluator):
    """Verifies that unmentioned actions default to DENY."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    assert evaluator.evaluate_action(policy, "iam:passrole") == EffectEnum.DENY
    assert evaluator.is_action_allowed(policy, "iam:passrole") is False


def test_evaluator_case_insensitive_matching(evaluator):
    """Verifies action queries match regardless of casing."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "IAM:PassRole",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    assert evaluator.is_action_allowed(policy, "iam:passrole") is True
    assert evaluator.is_action_allowed(policy, "IAM:PassRole") is True


def test_evaluator_not_action_with_allow(evaluator):
    """
    Verifies NotAction in an Allow statement grants everything EXCEPT excluded actions.
    """
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    assert evaluator.is_action_allowed(policy, "s3:getobject") is True
    assert evaluator.is_action_allowed(policy, "ec2:runinstances") is True
    assert evaluator.is_action_allowed(policy, "iam:passrole") is False
    assert evaluator.is_action_allowed(policy, "iam:createpolicyversion") is False


def test_evaluator_not_action_with_deny(evaluator):
    """
    Verifies NotAction in a Deny statement denies everything EXCEPT excluded actions.
    """
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "NotAction": "s3:*",
                "Resource": "*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    # S3 actions are exempt from Deny and granted by Allow
    assert evaluator.is_action_allowed(policy, "s3:getobject") is True
    # Non-S3 actions are matched by NotAction and therefore denied
    assert evaluator.is_action_allowed(policy, "iam:passrole") is False


def test_evaluator_not_resource_filtering(evaluator):
    """Verifies NotResource behavior in statements."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::secret-bucket/*"
            }
        ]
    }
    policy = evaluator.parse_policy(policy_data)
    assert evaluator.is_action_allowed(policy, "s3:getobject", "arn:aws:s3:::public-bucket/file.txt") is True
    assert evaluator.is_action_allowed(policy, "s3:getobject", "arn:aws:s3:::secret-bucket/file.txt") is False


def test_evaluate_policy_benign_policy(evaluator):
    """Verifies evaluation of a benign S3 read-only policy yields 0 risk score."""
    policy_data = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadOnlyS3",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::company-app/*"
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    assert len(result.vulnerabilities) == 0
    assert result.risk_score == 0


def test_evaluate_policy_critical_wildcard_admin(evaluator):
    """Verifies detection of Full Administrator Wildcard (*:*)."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    assert len(result.vulnerabilities) >= 1
    assert any(v.rule_id in ("PRIV_ESC_025", "RULE_CRIT_001") for v in result.vulnerabilities)
    assert result.risk_score >= 85


def test_evaluate_policy_privesc_create_policy_version(evaluator):
    """Verifies detection of CreatePolicyVersion privilege escalation."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:CreatePolicyVersion",
                "Resource": "*"
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    assert any("001" in v.rule_id for v in result.vulnerabilities)
    assert result.risk_score >= 85


def test_evaluate_policy_multi_action_ec2_passrole(evaluator):
    """Verifies detection of EC2 PassRole combination."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "ec2:RunInstances"],
                "Resource": "*"
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    assert any("014" in v.rule_id for v in result.vulnerabilities)
    assert result.risk_score >= 20


def test_evaluate_policy_multi_action_missing_dependency(evaluator):
    """Verifies that missing one action in a combination suppresses the rule."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*"
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    # EC2 RunInstances rule requires ec2:RunInstances, so it must not trigger
    assert not any("014" in v.rule_id for v in result.vulnerabilities)


def test_evaluate_policy_explicit_deny_suppresses_vulnerability(evaluator):
    """Verifies that explicit Deny suppresses false-positive findings."""
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "iam:CreatePolicyVersion",
                "Resource": "*"
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    assert not any("001" in v.rule_id for v in result.vulnerabilities)


def test_evaluate_policy_condition_passed_service_filtering(evaluator):
    """
    Verifies that iam:PassedToService condition restricts PassRole applicability.
    """
    policy_data = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "ec2:RunInstances"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "iam:PassedToService": "lambda.amazonaws.com"
                    }
                }
            }
        ]
    }
    result = evaluator.evaluate_policy(policy_data)
    assert result.is_valid is True
    # PassRole is constrained to lambda, so EC2 PassRole rule must be suppressed
    assert not any("014" in v.rule_id for v in result.vulnerabilities)


def test_evaluate_policy_invalid_json(evaluator):
    """Verifies handling of invalid JSON input string."""
    result = evaluator.evaluate_policy("{ invalid json }")
    assert result.is_valid is False
    assert len(result.errors) > 0
    assert result.risk_score == 0
