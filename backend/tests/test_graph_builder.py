"""
backend/tests/test_graph_builder.py

Unit test suite for Attack Graph Generator and Risk Scoring Engine.
"""

import pytest
from app.core.graph_builder import (
    AttackGraphBuilder,
    EdgeType,
    GraphSeverity,
    NodeType,
)


def test_empty_evaluation_graph():
    """Verifies that an evaluation with 0 findings generates base nodes and score 0."""
    builder = AttackGraphBuilder(principal_arn="arn:aws:iam::123456789012:user/auditor")
    graph = builder.build_from_evaluation(
        policy_name="BenignPolicy",
        statements=[{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        vulnerabilities=[],
    )
    assert graph.risk_score == 0
    assert len(graph.attack_paths) == 0
    assert len(graph.nodes) == 2  # Principal and Policy nodes
    assert len(graph.edges) == 1  # ATTACHED_TO


def test_single_vulnerability_graph():
    """Verifies graph generation with a single critical vulnerability."""
    builder = AttackGraphBuilder(principal_arn="arn:aws:iam::123456789012:user/dev")
    vulnerabilities = [
        {
            "rule_id": "PRIV_ESC_001",
            "title": "CreatePolicyVersion Escalation",
            "severity": "CRITICAL",
            "target_resource": "AdministratorAccess",
            "cvss_score": 9.8,
            "attack_vector": "Creates new default policy version with full admin privileges",
            "remediation": "Restrict iam:CreatePolicyVersion",
        }
    ]
    graph = builder.build_from_evaluation(
        policy_name="DevVulnPolicy",
        statements=[],
        vulnerabilities=vulnerabilities,
    )
    assert graph.risk_score >= 75
    assert len(graph.attack_paths) == 1
    path = graph.attack_paths[0]
    assert path.length == 3  # Identity -> Policy -> Vuln -> Target
    assert "AdministratorAccess" in path.description


def test_multi_action_passrole_graph():
    """Verifies graph generation with EC2 PassRole vulnerability."""
    builder = AttackGraphBuilder(principal_arn="arn:aws:iam::123456789012:user/infra")
    vulnerabilities = [
        {
            "rule_id": "PRIV_ESC_014",
            "title": "EC2 RunInstances PassRole Escalation",
            "severity": "HIGH",
            "target_resource": "EC2_Instance_Profile",
            "cvss_score": 8.8,
            "attack_vector": "Attacker launches EC2 instance with high privilege IAM role",
            "remediation": "Restrict iam:PassRole with iam:PassedToService condition",
        }
    ]
    graph = builder.build_from_evaluation(
        policy_name="InfraPolicy",
        statements=[],
        vulnerabilities=vulnerabilities,
    )
    assert len(graph.nodes) == 4  # Identity, Policy, Vuln, Target
    assert len(graph.edges) == 3  # ATTACHED_TO, GRANTS, CAN_ESCALATE_TO
    escalate_edges = [e for e in graph.edges if e.label == EdgeType.CAN_ESCALATE_TO]
    assert len(escalate_edges) == 1
    assert escalate_edges[0].animated is True


def test_react_flow_serialization_contract():
    """Verifies React Flow export format structure."""
    builder = AttackGraphBuilder()
    vulnerabilities = [
        {
            "rule_id": "PRIV_ESC_001",
            "title": "CreatePolicyVersion",
            "severity": "CRITICAL",
            "target_resource": "Admin",
        }
    ]
    graph = builder.build_from_evaluation(
        policy_name="TestPolicy",
        statements=[],
        vulnerabilities=vulnerabilities,
    )
    flow_data = AttackGraphBuilder.to_react_flow(graph)
    assert "nodes" in flow_data
    assert "edges" in flow_data
    for node in flow_data["nodes"]:
        assert "id" in node
        assert "type" in node
        assert "position" in node
        assert "data" in node
    for edge in flow_data["edges"]:
        assert "id" in edge
        assert "source" in edge
        assert "target" in edge
        assert "style" in edge


def test_cytoscape_serialization_contract():
    """Verifies Cytoscape.js export format structure."""
    builder = AttackGraphBuilder()
    vulnerabilities = [
        {
            "rule_id": "PRIV_ESC_002",
            "title": "SetDefaultPolicyVersion",
            "severity": "HIGH",
            "target_resource": "Admin",
        }
    ]
    graph = builder.build_from_evaluation(
        policy_name="TestPolicy",
        statements=[],
        vulnerabilities=vulnerabilities,
    )
    cy_data = AttackGraphBuilder.to_cytoscape(graph)
    assert "elements" in cy_data
    assert "nodes" in cy_data["elements"]
    assert "edges" in cy_data["elements"]
    for node in cy_data["elements"]["nodes"]:
        assert "data" in node
        assert "id" in node["data"]
    for edge in cy_data["elements"]["edges"]:
        assert "data" in edge
        assert "source" in edge["data"]
        assert "target" in edge["data"]


@pytest.mark.parametrize(
    "crit,high,med,low,min_score,max_score",
    [
        (1, 0, 0, 0, 75, 100),
        (0, 1, 0, 0, 50, 74),
        (0, 0, 1, 0, 25, 49),
        (0, 0, 0, 1, 5, 24),
        (0, 0, 0, 0, 0, 0),
    ],
)
def test_risk_score_bands(crit, high, med, low, min_score, max_score):
    """Verifies calibrated risk score tiers."""
    score = AttackGraphBuilder.compute_risk_score(
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        escalation_path_lengths=[2] if (crit + high + med + low) > 0 else [],
    )
    assert min_score <= score <= max_score


def test_cyclic_graph_safeguard():
    """Verifies that cyclical trust assumptions terminate safely without recursion."""
    builder = AttackGraphBuilder()
    roles = [
        {"name": "RoleAlpha", "assumes": "RoleBeta"},
        {"name": "RoleBeta", "assumes": "RoleAlpha"},
    ]
    trust_graph = builder.build_trust_graph(roles)
    assert len(trust_graph["nodes"]) == 2
    assert len(trust_graph["edges"]) == 2
