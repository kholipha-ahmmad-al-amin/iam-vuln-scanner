"""
backend/app/schemas/graph.py

Pydantic v2 schemas for Attack Graph visualization payloads (React Flow and Cytoscape).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNodeSchema(BaseModel):
    """Schema for graph node representation."""

    id: str
    label: str
    type: str
    risk_level: Optional[str] = "NONE"
    severity: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    properties: Optional[Dict[str, Any]] = None
    position: Optional[Dict[str, float]] = None


class GraphEdgeSchema(BaseModel):
    """Schema for graph directed edge representation."""

    id: str
    source: str
    target: str
    label: Optional[str] = None
    relationship: Optional[str] = None
    type: Optional[str] = "smoothstep"
    animated: bool = False
    is_escalation_path: bool = False
    severity: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    style: Optional[Dict[str, Any]] = None


class AttackPathSchema(BaseModel):
    """Schema for detected privilege escalation attack paths."""

    path_id: str
    title: str
    severity: str
    length: int
    node_ids: List[str]
    description: str


class AttackGraphResponse(BaseModel):
    """Complete graph payload schema for UI visualization."""

    scan_id: str
    summary: Dict[str, Any] = Field(default_factory=dict)
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    links: Optional[List[Dict[str, Any]]] = None
    attack_paths: List[Dict[str, Any]] = Field(default_factory=list)
    cytoscape: Optional[Dict[str, Any]] = None
