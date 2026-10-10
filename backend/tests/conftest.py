import asyncio
import pytest
from typing import AsyncGenerator, Dict, Any

# Reusable sample test IAM policies
@pytest.fixture
def sample_policies() -> Dict[str, Dict[str, Any]]:
    return {
        "admin_wildcard": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "FullAdminAccess",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        },
        "passrole_ec2": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EC2RunInstancesPassRole",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:RunInstances",
                        "iam:PassRole"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "passrole_lambda": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LambdaPassRoleCombo",
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole",
                        "lambda:CreateFunction",
                        "lambda:InvokeFunction"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "create_policy_version": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PolicyVersionExploit",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreatePolicyVersion"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "attach_user_policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AttachPolicyToSelf",
                    "Effect": "Allow",
                    "Action": [
                        "iam:AttachUserPolicy"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "benign_s3_readonly": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3ReadOnlyAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        "arn:aws:s3:::company-app-assets",
                        "arn:aws:s3:::company-app-assets/*"
                    ]
                }
            ]
        },
        "explicit_deny_conflict": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BroadAllowIAM",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "*"
                },
                {
                    "Sid": "ExplicitDenyPrivEsc",
                    "Effect": "Deny",
                    "Action": [
                        "iam:CreatePolicyVersion",
                        "iam:PassRole"
                    ],
                    "Resource": "*"
                }
            ]
        }
    }


@pytest.fixture
def samples_dir():
    from pathlib import Path
    return Path(__file__).parent.parent / "samples"
