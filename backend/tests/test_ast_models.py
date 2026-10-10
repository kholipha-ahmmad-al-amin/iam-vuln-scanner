"""
backend/tests/test_ast_models.py

Unit tests for IAM Policy AST models and normalization logic.
"""

import pytest
from pydantic import ValidationError
from app.core.ast_models import (
    ActionSet,
    ConditionBlock,
    EffectEnum,
    PolicyDocument,
    ResourceSet,
    Statement,
)


def test_parse_standard_policy():
    """Verifies parsing of a standard multi-statement policy."""
    policy_data = {
        "Version": "2012-10-17",
        "Id": "Policy01",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::mybucket/*"]
            }
        ]
    }
    doc = PolicyDocument.model_validate(policy_data)
    assert doc.version == "2012-10-17"
    assert doc.id == "Policy01"
    assert len(doc.statement) == 1
    stmt = doc.statement[0]
    assert stmt.sid == "AllowS3Read"
    assert stmt.effect == "Allow"
    assert stmt.action == ["s3:getobject", "s3:listbucket"]
    assert stmt.resource == ["arn:aws:s3:::mybucket/*"]


def test_statement_single_object_coercion():
    """Verifies single Statement object is coerced to a 1-element list."""
    policy_data = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }
    }
    doc = PolicyDocument.model_validate(policy_data)
    assert isinstance(doc.statement, list)
    assert len(doc.statement) == 1
    assert doc.statement[0].sid == "stmt_1"
    assert doc.statement[0].action == ["s3:getobject"]
    assert doc.statement[0].resource == ["*"]


def test_action_and_resource_scalar_coercion():
    """Verifies scalar string Action and Resource are coerced to lists."""
    stmt_data = {
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "arn:aws:iam::123456789012:role/WorkerRole"
    }
    stmt = Statement.model_validate(stmt_data)
    assert stmt.action == ["iam:passrole"]
    assert stmt.resource == ["arn:aws:iam::123456789012:role/WorkerRole"]


def test_action_casing_normalization():
    """Verifies all actions are normalized to lowercase."""
    stmt_data = {
        "Effect": "Allow",
        "Action": ["IAM:PassRole", "EC2:RunInstances", "s3:GETOBJECT"],
        "Resource": "*"
    }
    stmt = Statement.model_validate(stmt_data)
    assert stmt.action == ["iam:passrole", "ec2:runinstances", "s3:getobject"]


def test_effect_casing_normalization():
    """Verifies Effect is capitalized correctly regardless of input case."""
    for raw_effect, expected in [("allow", "Allow"), ("ALLOW", "Allow"), ("deny", "Deny"), ("DENY", "Deny")]:
        stmt = Statement.model_validate({
            "Effect": raw_effect,
            "Action": "s3:GetObject",
            "Resource": "*"
        })
        assert stmt.effect == expected


def test_invalid_effect_raises_validation_error():
    """Verifies invalid Effect values raise ValidationError."""
    with pytest.raises(ValidationError):
        Statement.model_validate({
            "Effect": "Permit",
            "Action": "s3:GetObject",
            "Resource": "*"
        })


def test_missing_sid_fallback_assignment():
    """Verifies statements without Sid receive sequential identifiers."""
    policy_data = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}
        ]
    }
    doc = PolicyDocument.model_validate(policy_data)
    assert doc.statement[0].sid == "stmt_1"
    assert doc.statement[1].sid == "stmt_2"


def test_existing_sid_preserved():
    """Verifies pre-existing Sids are preserved."""
    policy_data = {
        "Statement": [
            {"Sid": "CustomSidAlpha", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    doc = PolicyDocument.model_validate(policy_data)
    assert doc.statement[0].sid == "CustomSidAlpha"


def test_principal_normalization_wildcard():
    """Verifies Principal '*' normalization."""
    stmt = Statement.model_validate({
        "Effect": "Allow",
        "Principal": "*",
        "Action": "sts:AssumeRole",
        "Resource": "*"
    })
    assert stmt.principal == "*"


def test_principal_normalization_dictionary():
    """Verifies Principal dictionary with scalar or list values."""
    stmt = Statement.model_validate({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "sts:AssumeRole",
        "Resource": "*"
    })
    assert stmt.principal == {"AWS": ["arn:aws:iam::123456789012:root"]}


def test_not_action_parsing_and_mutual_exclusion():
    """Verifies NotAction parsing and rejection when both Action and NotAction exist."""
    stmt = Statement.model_validate({
        "Effect": "Allow",
        "NotAction": ["iam:*", "ec2:*"],
        "Resource": "*"
    })
    assert stmt.not_action == ["iam:*", "ec2:*"]
    assert stmt.action == []

    # Both Action and NotAction in one statement must fail
    with pytest.raises(ValidationError):
        Statement.model_validate({
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "NotAction": "iam:*",
            "Resource": "*"
        })


def test_not_resource_parsing_and_mutual_exclusion():
    """Verifies NotResource parsing and rejection when both Resource and NotResource exist."""
    stmt = Statement.model_validate({
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "NotResource": "arn:aws:s3:::top-secret/*"
    })
    assert stmt.not_resource == ["arn:aws:s3:::top-secret/*"]
    assert stmt.resource == []

    # Both Resource and NotResource in one statement must fail
    with pytest.raises(ValidationError):
        Statement.model_validate({
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "NotResource": "arn:aws:s3:::top-secret/*"
        })


def test_condition_block_parsing():
    """Verifies Condition block parsing into structured ConditionBlock objects."""
    stmt = Statement.model_validate({
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "*",
        "Condition": {
            "StringEquals": {
                "iam:PassedToService": ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]
            }
        }
    })
    conds = stmt.parsed_conditions()
    assert len(conds) == 1
    assert conds[0].operator == "StringEquals"
    assert conds[0].key == "iam:PassedToService"
    assert conds[0].values == ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]
    assert conds[0].matches_value("ec2.amazonaws.com") is True
    assert conds[0].matches_value("lambda.amazonaws.com") is False


def test_action_set_wildcard_matching():
    """Verifies ActionSet wildcard and globbing logic."""
    action_set = ActionSet(["iam:*", "ec2:run*", "s3:getobject"])
    assert action_set.matches("iam:passrole") is True
    assert action_set.matches("iam:createpolicyversion") is True
    assert action_set.matches("ec2:runinstances") is True
    assert action_set.matches("ec2:terminateinstances") is False
    assert action_set.matches("s3:getobject") is True
    assert action_set.matches("s3:putobject") is False

    star_set = ActionSet(["*"])
    assert star_set.is_wildcard_all() is True
    assert star_set.matches("any:action") is True


def test_resource_set_matching():
    """Verifies ResourceSet wildcard ARN matching."""
    res_set = ResourceSet(["arn:aws:s3:::company-bucket/*", "arn:aws:iam::123:role/Admin*"])
    assert res_set.matches("arn:aws:s3:::company-bucket/file.txt") is True
    assert res_set.matches("arn:aws:s3:::other-bucket/file.txt") is False
    assert res_set.matches("arn:aws:iam::123:role/AdminRole") is True
    assert res_set.matches("arn:aws:iam::123:role/DevRole") is False

    star_res = ResourceSet(["*"])
    assert star_res.matches("anything") is True
