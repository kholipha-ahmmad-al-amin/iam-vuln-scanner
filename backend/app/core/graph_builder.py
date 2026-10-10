"""
backend/app/core/graph_builder.py

Attack Graph Generator and Risk Scoring Engine.
Generates typed nodes and directed edges, finds cycle-safe exploitation paths,
and provides dual serialization (React Flow and Cytoscape.js).
"""

from __future__ import annotations

from collections import deque
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    IDENTITY = "identity"
    POLICY = "policy"
    ACTION = "action"
    TARGET = "target"
    VULNERABILITY = "vulnerability"


class EdgeType(str, Enum):
    ATTACHED_TO = "ATTACHED_TO"
    GRANTS = "GRANTS"
    TARGETS = "TARGETS"
    CAN_ASSUME = "CAN_ASSUME"
    CAN_ESCALATE_TO = "CAN_ESCALATE_TO"


class GraphSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"


class AttackGraphNode(BaseModel):
    id: str
    label: str
    type: NodeType
    severity: GraphSeverity = GraphSeverity.NONE
    data: Dict[str, Any] = Field(default_factory=dict)
    position: Optional[Dict[str, float]] = None


class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: EdgeType
    animated: bool = False
    severity: GraphSeverity = GraphSeverity.NONE
    data: Dict[str, Any] = Field(default_factory=dict)
    style: Optional[Dict[str, Any]] = None


class AttackPath(BaseModel):
    path_id: str
    title: str
    severity: GraphSeverity
    length: int
    node_ids: List[str]
    description: str


class AttackGraph(BaseModel):
    nodes: List[AttackGraphNode] = Field(default_factory=list)
    edges: List[AttackGraphEdge] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    risk_score: int = 0
    stats: Dict[str, int] = Field(default_factory=dict)


class AttackGraphBuilder:
    """
    Constructs typed attack graph models from IAM evaluation results,
    extracts escalation attack chains, and serializes into visualization formats.
    """

    def __init__(self, principal_arn: Optional[str] = None):
        self.principal_arn = principal_arn or "arn:aws:iam::123456789012:user/caller"
        self.nodes: Dict[str, AttackGraphNode] = {}
        self.edges: Dict[str, AttackGraphEdge] = {}
        self.adjacency: Dict[str, List[str]] = {}

    def _add_node(
        self,
        node_id: str,
        label: str,
        node_type: NodeType,
        severity: GraphSeverity = GraphSeverity.NONE,
        data: Optional[Dict[str, Any]] = None,
        position: Optional[Dict[str, float]] = None,
    ) -> AttackGraphNode:
        if node_id not in self.nodes:
            node = AttackGraphNode(
                id=node_id,
                label=label,
                type=node_type,
                severity=severity,
                data=data or {},
                position=position,
            )
            self.nodes[node_id] = node
            self.adjacency[node_id] = []
        return self.nodes[node_id]

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        severity: GraphSeverity = GraphSeverity.NONE,
        animated: bool = False,
        data: Optional[Dict[str, Any]] = None,
    ) -> AttackGraphEdge:
        edge_id = f"edge_{source_id}_to_{target_id}_{edge_type.value}"
        if edge_id not in self.edges:
            stroke_color = "#64748b"
            stroke_width = 1.5
            if edge_type == EdgeType.GRANTS:
                stroke_color = "#0ea5e9"
                stroke_width = 2.0
            elif edge_type == EdgeType.TARGETS:
                stroke_color = "#f59e0b"
                stroke_width = 2.0
            elif edge_type == EdgeType.CAN_ASSUME:
                stroke_color = "#a855f7"
                stroke_width = 2.0
                animated = True
            elif edge_type == EdgeType.CAN_ESCALATE_TO:
                stroke_color = "#ef4444"
                stroke_width = 3.0
                animated = True

            style = {"stroke": stroke_color, "strokeWidth": stroke_width}

            edge = AttackGraphEdge(
                id=edge_id,
                source=source_id,
                target=target_id,
                label=edge_type,
                animated=animated,
                severity=severity,
                data=data or {},
                style=style,
            )
            self.edges[edge_id] = edge
            if source_id in self.adjacency:
                self.adjacency[source_id].append(target_id)
        return self.edges[edge_id]

    def build_from_evaluation(
        self,
        policy_name: str,
        statements: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
    ) -> AttackGraph:
        """
        Builds the complete attack graph from policy statements and detected findings.
        """
        # 1. Identity Node
        principal_suffix = self.principal_arn.split("/")[-1] if "/" in self.principal_arn else self.principal_arn
        principal_id = f"identity:{principal_suffix}"
        principal_label = f"Principal: {principal_suffix}"
        self._add_node(
            node_id=principal_id,
            label=principal_label,
            node_type=NodeType.IDENTITY,
            severity=GraphSeverity.NONE,
            data={"arn": self.principal_arn, "category": "user"},
        )

        # 2. Policy Node
        policy_id = f"policy:{policy_name}"
        self._add_node(
            node_id=policy_id,
            label=f"Policy: {policy_name}",
            node_type=NodeType.POLICY,
            severity=GraphSeverity.NONE,
            data={"statement_count": len(statements)},
        )
        self._add_edge(
            source_id=principal_id,
            target_id=policy_id,
            edge_type=EdgeType.ATTACHED_TO,
        )

        # 3. Actions and Findings
        for idx, vuln in enumerate(vulnerabilities):
            rule_id = vuln.get("rule_id", f"RULE_{idx}")
            vuln_title = vuln.get("title", rule_id)
            raw_sev = str(vuln.get("severity", "MEDIUM")).upper()
            try:
                vuln_sev = GraphSeverity(raw_sev)
            except ValueError:
                vuln_sev = GraphSeverity.MEDIUM
            vuln_id = f"vuln:{rule_id}:{idx}"

            self._add_node(
                node_id=vuln_id,
                label=vuln_title,
                node_type=NodeType.VULNERABILITY,
                severity=vuln_sev,
                data={
                    "rule_id": rule_id,
                    "cvss_score": vuln.get("cvss_score", 7.5),
                    "attack_vector": vuln.get("attack_vector", ""),
                    "remediation": vuln.get("remediation", ""),
                },
            )

            # Link Policy -> Vuln
            self._add_edge(
                source_id=policy_id,
                target_id=vuln_id,
                edge_type=EdgeType.GRANTS,
                severity=vuln_sev,
            )

            # Target Node
            target_name = vuln.get("target_resource") or "AdministratorAccess"
            target_id = f"target:{target_name.replace(':', '_').replace('/', '_')}"
            self._add_node(
                node_id=target_id,
                label=f"Target: {target_name}",
                node_type=NodeType.TARGET,
                severity=vuln_sev,
                data={"target_name": target_name},
            )

            # Link Vuln -> Target
            self._add_edge(
                source_id=vuln_id,
                target_id=target_id,
                edge_type=EdgeType.CAN_ESCALATE_TO,
                severity=vuln_sev,
                animated=True,
            )

        # Calculate escalation paths via BFS
        attack_paths = self._find_escalation_paths(principal_id)
        path_lengths = [p.length for p in attack_paths]

        # Calculate severity counts
        crit_count = sum(1 for v in vulnerabilities if str(v.get("severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if str(v.get("severity", "")).upper() == "HIGH")
        med_count = sum(1 for v in vulnerabilities if str(v.get("severity", "")).upper() == "MEDIUM")
        low_count = sum(1 for v in vulnerabilities if str(v.get("severity", "")).upper() == "LOW")

        risk_score = self.compute_risk_score(
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            escalation_path_lengths=path_lengths,
        )

        return AttackGraph(
            nodes=list(self.nodes.values()),
            edges=list(self.edges.values()),
            attack_paths=attack_paths,
            risk_score=risk_score,
            stats={
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "vulnerabilities_count": len(vulnerabilities),
                "critical_count": crit_count,
                "high_count": high_count,
                "medium_count": med_count,
                "low_count": low_count,
            },
        )

    def build_graph(
        self,
        policy_doc: Optional[Any] = None,
        vulnerabilities: Optional[List[Any]] = None,
        principal_arn: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Public method that ingests policy and vulnerabilities and returns React Flow graph format.
        """
        if principal_arn:
            self.principal_arn = principal_arn

        raw_stmts: List[Dict[str, Any]] = []
        policy_name = "TargetPolicy"

        if isinstance(policy_doc, dict):
            raw_stmts = policy_doc.get("Statement", [])
            if isinstance(raw_stmts, dict):
                raw_stmts = [raw_stmts]
            policy_name = policy_doc.get("Id", "TargetPolicy")
        elif hasattr(policy_doc, "statement"):
            raw_stmts = [s.model_dump(by_alias=True) for s in policy_doc.statement]
            policy_name = getattr(policy_doc, "id", "TargetPolicy") or "TargetPolicy"

        vuln_dicts: List[Dict[str, Any]] = []
        for v in (vulnerabilities or []):
            if isinstance(v, dict):
                vuln_dicts.append(v)
            elif hasattr(v, "model_dump"):
                vuln_dicts.append(v.model_dump())
            elif hasattr(v, "__dict__"):
                vuln_dicts.append(v.__dict__)

        graph = self.build_from_evaluation(
            policy_name=policy_name,
            statements=raw_stmts,
            vulnerabilities=vuln_dicts
        )
        return self.to_react_flow(graph)

    def build_trust_graph(self, roles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Constructs a trust graph for AssumeRole chains with cycle safety.
        """
        self.nodes.clear()
        self.edges.clear()
        self.adjacency.clear()

        for role in roles:
            role_name = role.get("name", "UnknownRole")
            role_id = f"identity:role:{role_name}"
            self._add_node(
                node_id=role_id,
                label=f"Role: {role_name}",
                node_type=NodeType.IDENTITY,
                severity=GraphSeverity.NONE,
                data={"name": role_name}
            )

        for role in roles:
            role_name = role.get("name", "UnknownRole")
            assumes = role.get("assumes")
            if assumes:
                source_id = f"identity:role:{role_name}"
                target_id = f"identity:role:{assumes}"
                # Ensure target exists
                if target_id not in self.nodes:
                    self._add_node(
                        node_id=target_id,
                        label=f"Role: {assumes}",
                        node_type=NodeType.IDENTITY,
                        severity=GraphSeverity.NONE,
                        data={"name": assumes}
                    )
                self._add_edge(
                    source_id=source_id,
                    target_id=target_id,
                    edge_type=EdgeType.CAN_ASSUME,
                    severity=GraphSeverity.MEDIUM,
                    animated=True
                )

        graph = AttackGraph(
            nodes=list(self.nodes.values()),
            edges=list(self.edges.values()),
            attack_paths=[],
            risk_score=0,
            stats={"total_nodes": len(self.nodes), "total_edges": len(self.edges)}
        )
        return self.to_react_flow(graph)

    def find_attack_paths(self, chain_spec: Dict[str, Any]) -> List[List[str]]:
        """
        Identifies directed attack paths given a multi-hop chain specification.
        Format: {"identities": [...], "assumptions": [("a", "b")], "escalations": [("b", "target")]}
        """
        adj: Dict[str, List[str]] = {}
        identities = chain_spec.get("identities", [])
        for ident in identities:
            adj[ident] = []

        for src, dst in chain_spec.get("assumptions", []):
            adj.setdefault(src, []).append(dst)

        for src, dst in chain_spec.get("escalations", []):
            adj.setdefault(src, []).append(dst)

        if not identities:
            return []

        start_node = identities[0]
        results: List[List[str]] = []
        queue = deque([[start_node]])

        while queue:
            current_path = queue.popleft()
            curr = current_path[-1]

            neighbors = adj.get(curr, [])
            if not neighbors:
                # Leaf node, check if it terminates at target
                if len(current_path) > 1:
                    results.append(current_path)
                continue

            for neighbor in neighbors:
                if neighbor not in current_path:  # Cycle prevention
                    queue.append(current_path + [neighbor])

        return results

    def _find_escalation_paths(self, start_node_id: str) -> List[AttackPath]:
        """
        Executes Breadth-First Search (BFS) to identify all directed paths
        from the principal identity to target resource nodes.
        """
        paths: List[AttackPath] = []
        queue = deque([[start_node_id]])
        visited_paths = set()

        while queue:
            current_path = queue.popleft()
            curr_node_id = current_path[-1]

            curr_node = self.nodes.get(curr_node_id)
            if curr_node and curr_node.type == NodeType.TARGET:
                path_tuple = tuple(current_path)
                if path_tuple not in visited_paths:
                    visited_paths.add(path_tuple)
                    path_id = f"path_{len(paths) + 1}"
                    paths.append(
                        AttackPath(
                            path_id=path_id,
                            title=f"Escalation Chain to {curr_node.label}",
                            severity=curr_node.severity,
                            length=len(current_path) - 1,
                            node_ids=current_path,
                            description=" -> ".join(
                                self.nodes[n].label for n in current_path if n in self.nodes
                            ),
                        )
                    )
                continue

            for neighbor_id in self.adjacency.get(curr_node_id, []):
                if neighbor_id not in current_path:  # Cycle prevention
                    queue.append(current_path + [neighbor_id])

        return paths

    @staticmethod
    def compute_risk_score(
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        escalation_path_lengths: List[int],
    ) -> int:
        total_findings = critical_count + high_count + medium_count + low_count
        if total_findings == 0:
            return 0

        raw_score = (
            (critical_count * 25.0)
            + (high_count * 15.0)
            + (medium_count * 8.0)
            + (low_count * 3.0)
        )

        path_bonus = 0.0
        if escalation_path_lengths:
            for length in escalation_path_lengths:
                hop_count = max(1, length)
                path_bonus += 10.0 / hop_count
            path_bonus = min(20.0, path_bonus)

        composite = raw_score + path_bonus

        if critical_count > 0:
            score = max(75.0, min(100.0, composite))
        elif high_count > 0:
            score = max(50.0, min(74.0, composite))
        elif medium_count > 0:
            score = max(25.0, min(49.0, composite))
        else:
            score = max(5.0, min(24.0, composite))

        return int(round(score))

    @staticmethod
    def to_react_flow(graph: AttackGraph) -> Dict[str, Any]:
        """
        Formats graph for React Flow (@xyflow/react).
        """
        react_nodes = []
        flow_type_map = {
            NodeType.IDENTITY: "identityNode",
            NodeType.POLICY: "policyNode",
            NodeType.ACTION: "actionNode",
            NodeType.TARGET: "targetNode",
            NodeType.VULNERABILITY: "vulnerabilityNode",
        }

        for idx, node in enumerate(graph.nodes):
            react_nodes.append({
                "id": node.id,
                "type": flow_type_map.get(node.type, "default"),
                "position": node.position or {"x": (idx % 4) * 280, "y": (idx // 4) * 150},
                "data": {
                    "label": node.label,
                    "type": node.type.value,
                    "severity": node.severity.value,
                    **node.data,
                },
            })

        react_edges = []
        for edge in graph.edges:
            react_edge_obj = {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "label": edge.label.value,
                "type": "smoothstep",
                "animated": edge.animated,
                "style": edge.style or {"stroke": "#64748b", "strokeWidth": 2},
            }
            if edge.label == EdgeType.CAN_ESCALATE_TO:
                react_edge_obj["markerEnd"] = {
                    "type": "arrowclosed",
                    "color": "#ef4444",
                }
            react_edges.append(react_edge_obj)

        return {"nodes": react_nodes, "edges": react_edges}

    @staticmethod
    def to_cytoscape(graph: AttackGraph) -> Dict[str, Any]:
        """
        Formats graph for Cytoscape.js.
        """
        cy_nodes = []
        for node in graph.nodes:
            cy_nodes.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.type.value,
                    "severity": node.severity.value,
                    **node.data,
                }
            })

        cy_edges = []
        for edge in graph.edges:
            cy_edges.append({
                "data": {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "label": edge.label.value,
                    "relationship": edge.label.value,
                    "severity": edge.severity.value,
                    **edge.data,
                }
            })

        return {"elements": {"nodes": cy_nodes, "edges": cy_edges}}


# Compatible alias for test imports
GraphBuilder = AttackGraphBuilder
