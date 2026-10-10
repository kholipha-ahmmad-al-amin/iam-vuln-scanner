"""
backend/app/api/routes/scans.py

Scan lifecycle management: creation, persistent evaluation, history listings,
detail inspection, attack graph delivery, and deletion.
"""

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.ast_models import PolicyDocument
from app.core.evaluator import PolicyEvaluator
from app.core.graph_builder import AttackGraphBuilder
from app.models.graph import GraphEdge, GraphNode
from app.models.policy import Policy, PolicyStatement
from app.models.scan import Scan
from app.models.vulnerability import DetectedVulnerability, RemediationRecommendation
from app.schemas.graph import AttackGraphResponse
from app.schemas.policy import PolicySummary
from app.schemas.scan import (
    ScanCreate,
    ScanDetail,
    ScanListResponse,
    ScanPolicyInput,
    ScanSummary,
)
from app.schemas.vulnerability import RemediationDetail, VulnerabilityDetail

router = APIRouter()


@router.post(
    "/scans",
    response_model=ScanDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create and execute a new IAM policy scan",
)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
) -> ScanDetail:
    """
    Ingests IAM policy documents, evaluates detection rules, builds attack graph,
    and persists all scan records into the database.
    """
    start_time = time.time()

    # Normalize policies list from payload
    raw_policies: List[ScanPolicyInput] = []
    if payload.policies:
        raw_policies.extend(payload.policies)
    elif payload.policy_json is not None:
        raw_policies.append(
            ScanPolicyInput(
                policy_name="UploadedPolicy",
                policy_json=payload.policy_json,
            )
        )
    else:
        raise HTTPException(
            status_code=422,
            detail="Either 'policies' list or 'policy_json' must be provided",
        )

    scan_id = str(uuid.uuid4())
    evaluator = PolicyEvaluator()
    graph_builder = AttackGraphBuilder(principal_arn=payload.principal_arn)

    total_statements = 0
    all_findings: List[Any] = []
    policy_db_models: List[Policy] = []
    vuln_db_models: List[DetectedVulnerability] = []
    policy_summaries: List[PolicySummary] = []
    vulnerability_details: List[VulnerabilityDetail] = []

    for idx, p_input in enumerate(raw_policies):
        # Extract raw policy dict or string
        doc_raw: Union[str, Dict[str, Any]]
        if p_input.policy_document is not None:
            doc_raw = p_input.policy_document
        elif p_input.policy_json is not None:
            doc_raw = p_input.policy_json
        else:
            continue

        policy_name = p_input.policy_name or f"Policy_{idx + 1}"
        eval_result = evaluator.evaluate_policy(doc_raw, principal_arn=payload.principal_arn)

        if not eval_result.is_valid:
            continue

        total_statements += eval_result.statement_count
        policy_id = str(uuid.uuid4())
        raw_json_str = (
            json.dumps(doc_raw)
            if isinstance(doc_raw, (dict, list))
            else str(doc_raw)
        )

        policy_is_vuln = len(eval_result.vulnerabilities) > 0
        policy_obj = Policy(
            id=policy_id,
            scan_id=scan_id,
            policy_name=policy_name,
            policy_arn=p_input.policy_arn,
            policy_type=p_input.policy_type or "MANAGED",
            attached_entity_type=p_input.attached_entity_type or "Role",
            attached_entity_name=p_input.attached_entity_name or policy_name,
            version=eval_result.policy_version,
            raw_json=raw_json_str,
            is_vulnerable=policy_is_vuln,
        )

        # Parse statements for persistence
        parsed_doc: Optional[PolicyDocument] = None
        try:
            parsed_doc = evaluator.parse_policy(doc_raw)
        except Exception:
            pass

        if parsed_doc and parsed_doc.statement:
            for s in parsed_doc.statement:
                stmt_obj = PolicyStatement(
                    id=str(uuid.uuid4()),
                    policy_id=policy_id,
                    sid=s.sid,
                    effect=s.effect,
                    actions=s.action,
                    not_actions=s.not_action if s.not_action else None,
                    resources=s.resource,
                    not_resources=s.not_resource if s.not_resource else None,
                    conditions=s.condition,
                    has_wildcard_action=any("*" in a for a in s.action),
                    has_wildcard_resource=any("*" in r for r in s.resource),
                )
                policy_obj.statements.append(stmt_obj)

        policy_db_models.append(policy_obj)
        policy_summaries.append(
            PolicySummary(
                id=policy_id,
                policy_name=policy_name,
                policy_arn=p_input.policy_arn,
                policy_type=p_input.policy_type or "MANAGED",
                attached_entity_type=p_input.attached_entity_type,
                attached_entity_name=p_input.attached_entity_name,
                is_vulnerable=policy_is_vuln,
            )
        )

        # Record findings for this policy
        for f in eval_result.vulnerabilities:
            all_findings.append(f)
            vuln_id = str(uuid.uuid4())
            remed_text = f.remediation or "Enforce least privilege permissions boundaries"

            remed_obj = RemediationRecommendation(
                id=str(uuid.uuid4()),
                vulnerability_id=vuln_id,
                title=f"Remediate {f.rule_id}",
                summary=remed_text,
                remediation_type="RESTRICT_PERMISSIONS",
            )

            aff_res = ", ".join(f.affected_resources) if getattr(f, "affected_resources", None) else "*"
            vuln_obj = DetectedVulnerability(
                id=vuln_id,
                scan_id=scan_id,
                policy_id=policy_id,
                rule_id=f.rule_id,
                rule_name=f.title,
                severity=f.severity.value,
                category="PRIVILEGE_ESCALATION",
                title=f.title,
                description=f.attack_vector or f.title,
                exploitation_vector=f.attack_vector or "",
                affected_resource=aff_res,
                matched_actions=f.affected_actions,
                mitre_attack_id=getattr(f, "mitre_attack_id", None),
            )
            vuln_obj.remediations.append(remed_obj)
            vuln_db_models.append(vuln_obj)

            vulnerability_details.append(
                VulnerabilityDetail(
                    id=vuln_id,
                    rule_id=f.rule_id,
                    rule_name=f.title,
                    title=f.title,
                    severity=f.severity.value,
                    category="PRIVILEGE_ESCALATION",
                    description=f.attack_vector or f.title,
                    attack_vector=f.attack_vector,
                    exploitation_vector=f.attack_vector,
                    affected_resource=aff_res,
                    matched_actions=f.affected_actions,
                    affected_actions=f.affected_actions,
                    mitre_attack_id=getattr(f, "mitre_attack_id", None),
                    remediation=remed_text,
                    remediations=[
                        RemediationDetail(
                            id=remed_obj.id,
                            title=remed_obj.title,
                            summary=remed_obj.summary,
                            remediation_type=remed_obj.remediation_type,
                        )
                    ],
                    cvss_score=getattr(f, "cvss_score", 7.5),
                )
            )

    # Compute risk score and severities
    crit_count = sum(1 for v in vulnerability_details if v.severity == "CRITICAL")
    high_count = sum(1 for v in vulnerability_details if v.severity == "HIGH")
    med_count = sum(1 for v in vulnerability_details if v.severity == "MEDIUM")
    low_count = sum(1 for v in vulnerability_details if v.severity == "LOW")

    risk_score = evaluator.calculate_risk_score(all_findings)

    # Generate complete attack graph
    primary_statements: List[Dict[str, Any]] = []
    for p_obj in policy_db_models:
        for s in p_obj.statements:
            primary_statements.append({
                "Sid": s.sid,
                "Effect": s.effect,
                "Action": s.actions,
                "Resource": s.resources,
                "Condition": s.conditions,
            })

    raw_finding_dicts = [
        {
            "rule_id": v.rule_id,
            "title": v.title,
            "severity": v.severity,
            "target_resource": v.affected_resource,
            "cvss_score": v.cvss_score,
            "attack_vector": v.attack_vector,
            "remediation": v.remediation,
        }
        for v in vulnerability_details
    ]

    graph_model = graph_builder.build_from_evaluation(
        policy_name=payload.get_title(),
        statements=primary_statements,
        vulnerabilities=raw_finding_dicts,
    )
    react_flow_graph = AttackGraphBuilder.to_react_flow(graph_model)
    cytoscape_graph = AttackGraphBuilder.to_cytoscape(graph_model)

    links_payload = [
        {
            "id": e.id,
            "source": e.source,
            "target": e.target,
            "relationship": e.label.value,
            "is_escalation_path": e.animated,
            "severity": e.severity.value,
        }
        for e in graph_model.edges
    ]

    attack_paths_payload = [
        {
            "path_id": p.path_id,
            "title": p.title,
            "severity": p.severity.value,
            "length": p.length,
            "node_ids": p.node_ids,
            "description": p.description,
        }
        for p in graph_model.attack_paths
    ]

    graph_summary: Dict[str, Any] = {
        "scan_id": scan_id,
        "summary": {
            "total_nodes": len(graph_model.nodes),
            "total_edges": len(graph_model.edges),
            "escalation_paths_count": len(graph_model.attack_paths),
        },
        "nodes": react_flow_graph.get("nodes", []),
        "edges": react_flow_graph.get("edges", []),
        "links": links_payload,
        "attack_paths": attack_paths_payload,
        "cytoscape": cytoscape_graph,
    }

    # Persist graph nodes and edges
    graph_node_models: List[GraphNode] = []
    for n in graph_model.nodes:
        graph_node_models.append(
            GraphNode(
                id=f"{scan_id}:{n.id}",
                scan_id=scan_id,
                node_key=n.id,
                label=n.label,
                node_type=n.type.value,
                risk_level=n.severity.value,
                metadata_json=n.data,
            )
        )

    graph_edge_models: List[GraphEdge] = []
    for e in graph_model.edges:
        graph_edge_models.append(
            GraphEdge(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                source_node_id=f"{scan_id}:{e.source}",
                target_node_id=f"{scan_id}:{e.target}",
                relationship_type=e.label.value,
                is_escalation_path=e.animated,
                risk_weight=1.0,
                metadata_json=e.data,
            )
        )

    duration_ms = int((time.time() - start_time) * 1000)

    scan_obj = Scan(
        id=scan_id,
        title=payload.get_title(),
        description=payload.description,
        status="COMPLETED",
        source_type="JSON_UPLOAD",
        total_policies=len(policy_db_models),
        total_statements=total_statements,
        total_vulnerabilities=len(vulnerability_details),
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        low_count=low_count,
        risk_score=float(risk_score),
        scan_duration_ms=duration_ms,
        graph_summary=graph_summary,
    )
    scan_obj.policies = policy_db_models
    scan_obj.vulnerabilities = vuln_db_models
    scan_obj.graph_nodes = graph_node_models
    scan_obj.graph_edges = graph_edge_models

    db.add(scan_obj)
    await db.commit()
    await db.refresh(scan_obj)

    return ScanDetail(
        id=scan_obj.id,
        title=scan_obj.title,
        description=scan_obj.description,
        status=scan_obj.status,
        source_type=scan_obj.source_type,
        total_policies=scan_obj.total_policies,
        total_statements=scan_obj.total_statements,
        total_vulnerabilities=scan_obj.total_vulnerabilities,
        critical_count=scan_obj.critical_count,
        high_count=scan_obj.high_count,
        medium_count=scan_obj.medium_count,
        low_count=scan_obj.low_count,
        risk_score=scan_obj.risk_score,
        scan_duration_ms=scan_obj.scan_duration_ms,
        policies=policy_summaries,
        vulnerabilities=vulnerability_details,
        findings=vulnerability_details,
        graph=graph_summary,
        created_at=scan_obj.created_at,
        updated_at=scan_obj.updated_at,
    )


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List historical scans with pagination",
)
async def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    """
    Returns paginated historical scans ordered by creation date descending.
    """
    query = select(Scan)
    count_query = select(func.count(Scan.id))

    if status_filter:
        query = query.where(Scan.status == status_filter.upper())
        count_query = count_query.where(Scan.status == status_filter.upper())

    total_count_res = await db.execute(count_query)
    total = total_count_res.scalar() or 0

    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    query = query.order_by(Scan.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    scans = result.scalars().all()

    items = [
        ScanSummary(
            id=s.id,
            title=s.title,
            status=s.status,
            total_policies=s.total_policies,
            total_vulnerabilities=s.total_vulnerabilities,
            critical_count=s.critical_count,
            high_count=s.high_count,
            medium_count=s.medium_count,
            low_count=s.low_count,
            risk_score=s.risk_score,
            created_at=s.created_at,
        )
        for s in scans
    ]

    return ScanListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetail,
    summary="Retrieve full scan results and findings",
)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanDetail:
    """
    Returns comprehensive scan details including parsed policies and detected vulnerabilities.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    policy_summaries = [
        PolicySummary(
            id=p.id,
            policy_name=p.policy_name,
            policy_arn=p.policy_arn,
            policy_type=p.policy_type,
            attached_entity_type=p.attached_entity_type,
            attached_entity_name=p.attached_entity_name,
            is_vulnerable=p.is_vulnerable,
            created_at=p.created_at,
        )
        for p in scan.policies
    ]

    vulnerability_details = [
        VulnerabilityDetail(
            id=v.id,
            rule_id=v.rule_id,
            rule_name=v.rule_name,
            title=v.title,
            severity=v.severity,
            category=v.category,
            description=v.description,
            exploitation_vector=v.exploitation_vector,
            attack_vector=v.exploitation_vector,
            affected_resource=v.affected_resource,
            matched_actions=v.matched_actions,
            affected_actions=v.matched_actions,
            mitre_attack_id=v.mitre_attack_id,
            remediations=[
                RemediationDetail(
                    id=r.id,
                    title=r.title,
                    summary=r.summary,
                    remediation_type=r.remediation_type,
                    recommended_policy_snippet=r.recommended_policy_snippet,
                    cli_command_fix=r.cli_command_fix,
                    documentation_url=r.documentation_url,
                    created_at=r.created_at,
                )
                for r in v.remediations
            ],
            created_at=v.created_at,
        )
        for v in scan.vulnerabilities
    ]

    return ScanDetail(
        id=scan.id,
        title=scan.title,
        description=scan.description,
        status=scan.status,
        source_type=scan.source_type,
        total_policies=scan.total_policies,
        total_statements=scan.total_statements,
        total_vulnerabilities=scan.total_vulnerabilities,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        risk_score=scan.risk_score,
        scan_duration_ms=scan.scan_duration_ms,
        policies=policy_summaries,
        vulnerabilities=vulnerability_details,
        findings=vulnerability_details,
        graph=scan.graph_summary,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
    )


@router.get(
    "/scans/{scan_id}/graph",
    response_model=AttackGraphResponse,
    summary="Retrieve attack graph payload for UI visualizer",
)
async def get_scan_graph(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> AttackGraphResponse:
    """
    Returns graph visualization payload including React Flow nodes and edges, Cytoscape data,
    and attack path sequences.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    graph_data = scan.graph_summary or {}

    return AttackGraphResponse(
        scan_id=scan.id,
        summary=graph_data.get("summary", {}),
        nodes=graph_data.get("nodes", []),
        edges=graph_data.get("edges", []),
        links=graph_data.get("links", []),
        attack_paths=graph_data.get("attack_paths", []),
        cytoscape=graph_data.get("cytoscape"),
    )


@router.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan and all associated records",
)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Deletes scan record with cascading deletion of policies, vulnerabilities, and graph entities.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )

    await db.delete(scan)
    await db.commit()
