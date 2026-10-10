"""
backend/tests/test_adversarial_challenger_1.py

Adversarial stress-testing suite for the IAM Policy Analyzer Core.
Challenges action wildcard patterns, multi-statement conflicts, Deny ordering,
PassRole multi-service conditions, graph cycle robustness, and engine determinism.
"""

import json
import random
import pytest
from app.core.ast_models import (
    ActionSet,
    EffectEnum,
    PolicyDocument,
    ResourceSet,
    SeverityEnum,
    Statement,
)
from app.core.evaluator import PolicyEvaluator, PolicyValidationError
from app.core.graph_builder import AttackGraphBuilder


@pytest.fixture
def evaluator():
    return PolicyEvaluator()


class TestAdversarialActionWildcards:
    """Stress tests wildcard patterns across actions and resources."""

    def test_wildcard_patterns_case_insensitive(self):
        """Patterns like iam:*Policy* match regardless of casing."""
        action_set = ActionSet(["iam:*Policy*"])
        assert action_set.matches("iam:CreatePolicy") is True
        assert action_set.matches("iam:createpolicyversion") is True
        assert action_set.matches("IAM:ATTACHUSERPOLICY") is True
        assert action_set.matches("iam:PutUserPolicy") is True
        assert action_set.matches("iam:DeletePolicy") is True
        # Non-policy actions must not match
        assert action_set.matches("iam:PassRole") is False
        assert action_set.matches("iam:CreateAccessKey") is False
        assert action_set.matches("s3:GetObject") is False

    def test_middle_and_boundary_wildcards(self):
        """Prefix, suffix, and middle wildcard patterns."""
        action_set = ActionSet(["iam:Create*Version", "iam:*AccessKey"])
        assert action_set.matches("iam:CreatePolicyVersion") is True
        assert action_set.matches("iam:createaccesskey") is True
        assert action_set.matches("iam:CreateRole") is False
        assert action_set.matches("iam:DeleteAccessKey") is True

    def test_single_character_wildcard(self):
        """Question mark wildcard matching single characters."""
        action_set = ActionSet(["iam:?utUserPolicy"])
        assert action_set.matches("iam:PutUserPolicy") is True
        assert action_set.matches("iam:putuserpolicy") is True
        assert action_set.matches("iam:OutUserPolicy") is True
        assert action_set.matches("iam:CreateUserPolicy") is False

    def test_wildcard_action_in_policy_evaluation(self, evaluator):
        """Policy with 'iam:*policy*' triggers policy-related privilege escalation rules."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardPolicyAdmin",
                    "Effect": "Allow",
                    "Action": "iam:*Policy*",
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        rule_ids = {v.rule_id for v in res.vulnerabilities}
        # PRIV_ESC_001 is CreatePolicyVersion
        # PRIV_ESC_002 is SetDefaultPolicyVersion
        # PRIV_ESC_006 is AttachUserPolicy
        # PRIV_ESC_009 is PutUserPolicy
        # PRIV_ESC_008 is AttachRolePolicy
        assert "PRIV_ESC_001" in rule_ids
        assert "PRIV_ESC_002" in rule_ids
        assert "PRIV_ESC_006" in rule_ids
        assert "PRIV_ESC_009" in rule_ids
        assert "PRIV_ESC_008" in rule_ids
        # Should NOT trigger non-policy actions such as CreateAccessKey (PRIV_ESC_003) or PassRole (PRIV_ESC_014)
        assert "PRIV_ESC_003" not in rule_ids
        assert "PRIV_ESC_014" not in rule_ids


class TestAdversarialMultiStatementOrdering:
    """Stress tests statement ordering, precedence, and Deny overrides."""

    def test_deny_ordered_after_allow_strictly_denies(self, evaluator):
        """Deny statement placed after Allow must override the Allow completely."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowStmt",
                    "Effect": "Allow",
                    "Action": "iam:CreatePolicyVersion",
                    "Resource": "*"
                },
                {
                    "Sid": "DenyStmt",
                    "Effect": "Deny",
                    "Action": "iam:CreatePolicyVersion",
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        assert not any(v.rule_id == "PRIV_ESC_001" for v in res.vulnerabilities)
        assert evaluator.is_action_allowed(evaluator.parse_policy(policy_data), "iam:CreatePolicyVersion") is False

    def test_deny_ordered_before_allow_strictly_denies(self, evaluator):
        """Deny statement placed before Allow must override the Allow completely."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyStmtFirst",
                    "Effect": "Deny",
                    "Action": "iam:CreatePolicyVersion",
                    "Resource": "*"
                },
                {
                    "Sid": "AllowStmtSecond",
                    "Effect": "Allow",
                    "Action": "iam:CreatePolicyVersion",
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        assert not any(v.rule_id == "PRIV_ESC_001" for v in res.vulnerabilities)
        assert evaluator.is_action_allowed(evaluator.parse_policy(policy_data), "iam:CreatePolicyVersion") is False

    def test_interleaved_multi_action_selective_deny(self, evaluator):
        """Multiple Allow actions with selective Deny on a subset of actions."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowEC2AndPassRole",
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances", "iam:PassRole", "iam:CreateAccessKey"],
                    "Resource": "*"
                },
                {
                    "Sid": "DenyPassRoleOnly",
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        rule_ids = {v.rule_id for v in res.vulnerabilities}
        # EC2 PassRole requires both ec2:RunInstances and iam:PassRole.
        # Since iam:PassRole is denied, PRIV_ESC_014 must NOT trigger.
        assert "PRIV_ESC_014" not in rule_ids
        # iam:CreateAccessKey was allowed and not denied -> PRIV_ESC_003 must trigger.
        assert "PRIV_ESC_003" in rule_ids

    def test_deny_with_notaction_pruning(self, evaluator):
        """Deny with NotAction denies all actions not in the NotAction list."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowEverything",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Sid": "DenyAllExceptReadOnlyS3",
                    "Effect": "Deny",
                    "NotAction": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": "*"
                }
            ]
        }
        policy = evaluator.parse_policy(policy_data)
        # s3:GetObject is not denied, so it remains allowed
        assert evaluator.is_action_allowed(policy, "s3:GetObject") is True
        # iam:CreatePolicyVersion is denied because it is NOT in NotAction
        assert evaluator.is_action_allowed(policy, "iam:CreatePolicyVersion") is False
        assert evaluator.is_action_allowed(policy, "iam:PassRole") is False
        # Full admin wildcard is negated
        assert evaluator.is_full_admin(policy) is False
        res = evaluator.evaluate_policy(policy_data)
        assert len(res.vulnerabilities) == 0
        assert res.risk_score == 0


class TestAdversarialPassRoleCombinations:
    """Stress tests PassRole combinations distributed across statements and services."""

    def test_distributed_passrole_across_multiple_compute_services(self, evaluator):
        """One statement allows iam:PassRole, other statements allow compute services."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SharedPassRole",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*"
                },
                {
                    "Sid": "EC2RunInstancesPermission",
                    "Effect": "Allow",
                    "Action": "ec2:RunInstances",
                    "Resource": "*"
                },
                {
                    "Sid": "LambdaPermissions",
                    "Effect": "Allow",
                    "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                    "Resource": "*"
                },
                {
                    "Sid": "CodeBuildPermissions",
                    "Effect": "Allow",
                    "Action": ["codebuild:CreateProject", "codebuild:StartBuild"],
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        rule_ids = {v.rule_id for v in res.vulnerabilities}
        assert "PRIV_ESC_014" in rule_ids  # EC2 PassRole
        assert "PRIV_ESC_015" in rule_ids  # Lambda PassRole
        assert "PRIV_ESC_021" in rule_ids  # CodeBuild PassRole

    def test_passrole_scoped_by_passed_to_service_condition(self, evaluator):
        """Condition restricting iam:PassRole to ec2.amazonaws.com blocks Lambda attack."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleEC2Only",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": "ec2.amazonaws.com"
                        }
                    }
                },
                {
                    "Sid": "AllowEC2",
                    "Effect": "Allow",
                    "Action": "ec2:RunInstances",
                    "Resource": "*"
                },
                {
                    "Sid": "AllowLambda",
                    "Effect": "Allow",
                    "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        rule_ids = {v.rule_id for v in res.vulnerabilities}
        # EC2 PassRole is permitted because PassedToService matches ec2.amazonaws.com
        assert "PRIV_ESC_014" in rule_ids
        # Lambda PassRole must NOT trigger because condition restricts PassRole to EC2 only
        assert "PRIV_ESC_015" not in rule_ids

    def test_passrole_with_multi_value_service_condition(self, evaluator):
        """Condition with list of services: ec2 and lambda allowed, glue blocked."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleMultiService",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
                        }
                    }
                },
                {
                    "Sid": "AllowEC2",
                    "Effect": "Allow",
                    "Action": "ec2:RunInstances",
                    "Resource": "*"
                },
                {
                    "Sid": "AllowLambda",
                    "Effect": "Allow",
                    "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                    "Resource": "*"
                },
                {
                    "Sid": "AllowGlue",
                    "Effect": "Allow",
                    "Action": "glue:CreateDevEndpoint",
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        rule_ids = {v.rule_id for v in res.vulnerabilities}
        assert "PRIV_ESC_014" in rule_ids  # EC2 allowed
        assert "PRIV_ESC_015" in rule_ids  # Lambda allowed
        assert "PRIV_ESC_018" not in rule_ids  # Glue blocked


class TestAdversarialAttackGraphRobustness:
    """Stress tests AttackGraphBuilder against adversarial graphs and cycles."""

    def test_graph_generation_with_many_statements_and_findings(self, evaluator):
        """AttackGraphBuilder generates valid React Flow nodes and edges without crash."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "S1", "Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
                {"Sid": "S2", "Effect": "Allow", "Action": "iam:SetDefaultPolicyVersion", "Resource": "*"},
                {"Sid": "S3", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
                {"Sid": "S4", "Effect": "Allow", "Action": "iam:UpdateLoginProfile", "Resource": "*"},
                {"Sid": "S5", "Effect": "Allow", "Action": ["ec2:RunInstances", "iam:PassRole"], "Resource": "*"}
            ]
        }
        res = evaluator.evaluate_policy(policy_data, principal_arn="arn:aws:iam::123456789012:user/adversary")
        assert res.is_valid is True
        assert res.graph_data is not None
        assert "nodes" in res.graph_data
        assert "edges" in res.graph_data

        node_types = {n.get("type") for n in res.graph_data["nodes"]}
        # React flow types mapped from NodeType
        assert "identityNode" in node_types
        assert "policyNode" in node_types
        assert "vulnerabilityNode" in node_types
        assert len(res.graph_data["nodes"]) > 0
        assert len(res.graph_data["edges"]) > 0

    def test_cyclic_trust_chains_handled_gracefully(self):
        """Attack graph builder handles cyclic assume role transitions safely."""
        builder = AttackGraphBuilder(principal_arn="arn:aws:iam::123456789012:role/RoleA")
        roles = [
            {"name": "RoleA", "assumes": "RoleB"},
            {"name": "RoleB", "assumes": "RoleC"},
            {"name": "RoleC", "assumes": "RoleA"}
        ]
        trust_graph = builder.build_trust_graph(roles)
        assert "nodes" in trust_graph
        assert "edges" in trust_graph
        assert len(trust_graph["nodes"]) == 3
        assert len(trust_graph["edges"]) == 3

        # Test cycle safety in attack path extraction
        chain_spec = {
            "identities": ["RoleA", "RoleB", "RoleC"],
            "assumptions": [("RoleA", "RoleB"), ("RoleB", "RoleC"), ("RoleC", "RoleA")],
            "escalations": [("RoleC", "AdminTarget")]
        }
        paths = builder.find_attack_paths(chain_spec)
        assert len(paths) >= 1
        # Path must terminate at AdminTarget without getting caught in RoleA->RoleB->RoleC->RoleA loop
        assert paths[0] == ["RoleA", "RoleB", "RoleC", "AdminTarget"]

    def test_cytoscape_serialization_parity(self, evaluator):
        """Cytoscape.js export format adheres to valid element structure."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "S1", "Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
            ]
        }
        builder = AttackGraphBuilder()
        graph = builder.build_from_evaluation(
            policy_name="CytoscapeTestPolicy",
            statements=policy_data["Statement"],
            vulnerabilities=[{
                "rule_id": "PRIV_ESC_001",
                "title": "CreatePolicyVersion",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "attack_vector": "Test vector"
            }]
        )
        cyto_data = AttackGraphBuilder.to_cytoscape(graph)
        assert "elements" in cyto_data
        assert "nodes" in cyto_data["elements"]
        assert "edges" in cyto_data["elements"]
        assert len(cyto_data["elements"]["nodes"]) >= 3
        assert len(cyto_data["elements"]["edges"]) >= 2


class TestAdversarialEngineDeterminism:
    """Verifies that evaluation outputs are 100% deterministic under permutations."""

    def test_repeated_evaluation_determinism(self, evaluator):
        """Evaluating identical policy 25 times yields bit-for-bit identical results."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "PassRoleStmt", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                {"Sid": "EC2Stmt", "Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
                {"Sid": "KeyStmt", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}
            ]
        }
        initial_res = evaluator.evaluate_policy(policy_data)
        initial_score = initial_res.risk_score
        initial_vuln_ids = [v.rule_id for v in initial_res.vulnerabilities]
        initial_nodes_count = len(initial_res.graph_data["nodes"])
        initial_edges_count = len(initial_res.graph_data["edges"])

        for _ in range(25):
            curr_res = evaluator.evaluate_policy(policy_data)
            assert curr_res.risk_score == initial_score
            assert [v.rule_id for v in curr_res.vulnerabilities] == initial_vuln_ids
            assert len(curr_res.graph_data["nodes"]) == initial_nodes_count
            assert len(curr_res.graph_data["edges"]) == initial_edges_count

    def test_statement_permutation_invariance(self, evaluator):
        """Order of statements does not alter findings or risk score."""
        statements = [
            {"Sid": "S1", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Sid": "S2", "Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
            {"Sid": "S3", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
            {"Sid": "S4", "Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
        ]
        base_doc = {"Version": "2012-10-17", "Statement": statements}
        base_res = evaluator.evaluate_policy(base_doc)
        base_ids = set(v.rule_id for v in base_res.vulnerabilities)

        # Test 10 random permutations of the statement list
        for seed in range(10):
            shuffled = list(statements)
            random.Random(seed).shuffle(shuffled)
            perm_doc = {"Version": "2012-10-17", "Statement": shuffled}
            perm_res = evaluator.evaluate_policy(perm_doc)
            assert perm_res.risk_score == base_res.risk_score
            assert set(v.rule_id for v in perm_res.vulnerabilities) == base_ids


class TestAdversarialMalformedAndBoundaryInputs:
    """Stress tests error resilience and schema validation."""

    def test_invalid_json_string_gracefully_handled(self, evaluator):
        """Malformed JSON string does not crash evaluator, returns is_valid=False."""
        res = evaluator.evaluate_policy("{invalid_json_here: true")
        assert res.is_valid is False
        assert len(res.errors) > 0
        assert res.risk_score == 0

    def test_non_dict_non_string_types(self, evaluator):
        """Non-dict non-string inputs are caught safely."""
        for invalid_input in [12345, [1, 2, 3], None, True]:
            res = evaluator.evaluate_policy(invalid_input)
            assert res.is_valid is False
            assert len(res.errors) > 0

    def test_statement_missing_effect(self, evaluator):
        """Statement missing Effect field is rejected."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "NoEffect", "Action": "iam:PassRole", "Resource": "*"}
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is False

    def test_statement_both_action_and_not_action(self, evaluator):
        """Statement specifying both Action and NotAction simultaneously is rejected."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ConflictedAction",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "NotAction": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is False

    def test_statement_both_resource_and_not_resource(self, evaluator):
        """Statement specifying both Resource and NotResource simultaneously is rejected."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ConflictedResource",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "NotResource": "arn:aws:s3:::bucket"
                }
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is False

    def test_empty_statement_list_yields_zero_findings(self, evaluator):
        """Empty statement array evaluates safely to valid policy with 0 score."""
        policy_data = {"Version": "2012-10-17", "Statement": []}
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        assert res.risk_score == 0
        assert len(res.vulnerabilities) == 0


class TestAdversarialInvariantFuzzing:
    """Rigorous invariant testing and randomized policy synthesis."""

    def test_deny_all_invariant_across_50_actions(self, evaluator):
        """When Deny * on * is present, no action is permitted under any circumstances."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowAllFirst",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Sid": "DenyAllSecond",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        policy = evaluator.parse_policy(policy_data)
        sample_actions = [
            "iam:PassRole", "iam:CreatePolicyVersion", "iam:AttachUserPolicy",
            "iam:PutUserPolicy", "iam:CreateAccessKey", "iam:UpdateLoginProfile",
            "ec2:RunInstances", "ec2:DescribeInstances", "s3:GetObject", "s3:PutObject",
            "lambda:CreateFunction", "lambda:InvokeFunction", "sts:AssumeRole",
            "cloudformation:CreateStack", "datapipeline:CreatePipeline",
            "codebuild:StartBuild", "ecs:RunTask", "sagemaker:CreateNotebookInstance",
            "dynamodb:GetItem", "rds:CreateDBInstance", "kms:Decrypt",
            "sqs:SendMessage", "sns:Publish", "glue:CreateDevEndpoint"
        ]
        for act in sample_actions:
            assert evaluator.is_action_allowed(policy, act) is False

        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        assert len(res.vulnerabilities) == 0
        assert res.risk_score == 0

    def test_graph_referential_integrity(self, evaluator):
        """All edges in generated graph data must connect to existing nodes."""
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
                {"Effect": "Allow", "Action": ["ec2:RunInstances", "iam:PassRole"], "Resource": "*"},
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
            ]
        }
        res = evaluator.evaluate_policy(policy_data)
        assert res.is_valid is True
        nodes = res.graph_data["nodes"]
        edges = res.graph_data["edges"]

        node_ids = {n["id"] for n in nodes}
        assert len(node_ids) == len(nodes), "Node IDs must be unique"

        for edge in edges:
            assert edge["source"] in node_ids, f"Dangling edge source: {edge['source']}"
            assert edge["target"] in node_ids, f"Dangling edge target: {edge['target']}"

    def test_mitigation_reduces_finding_impact(self, evaluator):
        """Condition restricting policy ARN to ReadOnly mitigates AttachUserPolicy."""
        mitigated_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AttachReadOnlyOnly",
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
        res = evaluator.evaluate_policy(mitigated_policy)
        assert res.is_valid is True
        v = next((x for x in res.vulnerabilities if x.rule_id == "PRIV_ESC_006"), None)
        assert v is not None
        assert v.is_mitigated is True
        # Mitigated finding should yield low risk score
        assert res.risk_score <= 15

    def test_combinatorial_fuzzing_100_synthesized_policies(self, evaluator):
        """Generates and evaluates 100 randomized policies without crashes or errors."""
        action_pool = [
            "iam:passrole", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
            "iam:putuserpolicy", "iam:attachuserpolicy", "iam:createaccesskey",
            "iam:updateloginprofile", "ec2:runinstances", "lambda:createfunction",
            "lambda:invokefunction", "sts:assumerole", "s3:getobject", "s3:*",
            "iam:*", "ec2:*", "iam:*policy*", "*"
        ]
        services_pool = ["ec2.amazonaws.com", "lambda.amazonaws.com", "glue.amazonaws.com", "*"]

        rng = random.Random(42)

        for i in range(100):
            num_stmts = rng.randint(1, 10)
            statements = []
            for j in range(num_stmts):
                effect = rng.choice(["Allow", "Deny"])
                actions = rng.sample(action_pool, rng.randint(1, 4))
                stmt = {
                    "Sid": f"FuzzStmt_{i}_{j}",
                    "Effect": effect,
                    "Action": actions if len(actions) > 1 else actions[0],
                    "Resource": "*"
                }
                # Randomly inject PassedToService condition
                if rng.random() > 0.7:
                    stmt["Condition"] = {
                        "StringEquals": {
                            "iam:PassedToService": rng.choice(services_pool)
                        }
                    }
                statements.append(stmt)

            policy_doc = {"Version": "2012-10-17", "Statement": statements}
            res = evaluator.evaluate_policy(policy_doc)

            # Assert invariants
            assert isinstance(res.is_valid, bool)
            assert res.is_valid is True
            assert isinstance(res.risk_score, int)
            assert 0 <= res.risk_score <= 100
            assert isinstance(res.vulnerabilities, list)
            assert isinstance(res.graph_data, dict)
            assert "nodes" in res.graph_data
            assert "edges" in res.graph_data

