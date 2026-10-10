"""
backend/app/api/routes/policies.py

Stateless IAM policy analysis endpoint without persistent database writes.
"""

import json
from typing import Any, Dict, List, Union
from fastapi import APIRouter, HTTPException, status

from app.core.evaluator import PolicyEvaluator
from app.schemas.policy import PolicyAnalyzeRequest, PolicyAnalyzeResponse
from app.schemas.vulnerability import RemediationDetail, VulnerabilityDetail

router = APIRouter()


@router.post(
    "/policies/analyze",
    response_model=PolicyAnalyzeResponse,
    summary="Stateless ad-hoc IAM policy evaluation",
)
async def analyze_policy_stateless(
    payload: PolicyAnalyzeRequest,
) -> PolicyAnalyzeResponse:
    """
    Evaluates an IAM policy against privilege escalation rules and returns findings and attack graph
    without writing records to the database.
    """
    raw_doc: Union[str, Dict[str, Any]]

    if payload.policy_json is not None:
        raw_doc = payload.policy_json
    elif payload.policy_document is not None:
        raw_doc = payload.policy_document
    else:
        raise HTTPException(
            status_code=422,
            detail="Either 'policy_json' or 'policy_document' must be provided",
        )

    evaluator = PolicyEvaluator()
    result = evaluator.evaluate_policy(raw_doc, principal_arn=payload.principal_arn)

    if not result.is_valid:
        raise HTTPException(
            status_code=422,
            detail=result.errors or ["Invalid IAM policy document format"],
        )

    vulnerability_details: List[VulnerabilityDetail] = []
    for f in result.vulnerabilities:
        remed_text = f.remediation or "Enforce least-privilege permissions boundaries"
        remediations = [
            RemediationDetail(
                title=f"Remediation for {f.rule_id}",
                summary=remed_text,
                remediation_type="RESTRICT_PERMISSIONS",
            )
        ]
        vulnerability_details.append(
            VulnerabilityDetail(
                rule_id=f.rule_id,
                rule_name=f.title,
                title=f.title,
                severity=f.severity.value,
                category="PRIVILEGE_ESCALATION",
                description=f.attack_vector or f.title,
                attack_vector=f.attack_vector,
                exploitation_vector=f.attack_vector,
                affected_resource=", ".join(f.affected_resources) if getattr(f, "affected_resources", None) else "*",
                matched_actions=f.affected_actions,
                affected_actions=f.affected_actions,
                mitre_attack_id=getattr(f, "mitre_attack_id", None),
                remediation=remed_text,
                remediations=remediations,
                cvss_score=getattr(f, "cvss_score", 7.5),
            )
        )

    graph_payload = result.graph_data or {"nodes": [], "edges": []}

    return PolicyAnalyzeResponse(
        is_valid=True,
        is_vulnerable=len(vulnerability_details) > 0,
        risk_score=float(result.risk_score),
        statement_count=result.statement_count,
        vulnerabilities=vulnerability_details,
        findings=vulnerability_details,
        graph=graph_payload,
        graph_data=graph_payload,
        allowed_actions_summary=result.allowed_actions_summary,
        denied_actions_summary=result.denied_actions_summary,
        errors=[],
    )
