"""
backend/app/api/routes/rules.py

Detection rules catalog discovery endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.core.rules_catalog import get_all_rules, get_rule_by_id
from app.schemas.rule import RuleCatalogItem

router = APIRouter()


@router.get(
    "/rules",
    response_model=List[RuleCatalogItem],
    summary="List all detection rules from the security catalog",
)
async def list_rules(
    severity: Optional[str] = Query(None, description="Filter rules by severity"),
    service: Optional[str] = Query(None, description="Filter rules by compute service"),
) -> List[RuleCatalogItem]:
    """
    Returns registered privilege escalation detection rules, optionally filtered.
    """
    rules = get_all_rules()

    if severity:
        rules = [r for r in rules if r.severity.value.upper() == severity.upper()]
    if service:
        rules = [r for r in rules if r.compute_service.upper() == service.upper()]

    return [
        RuleCatalogItem(
            id=r.rule_id,
            rule_id=r.rule_id,
            name=r.name,
            severity=r.severity.value,
            category="PRIVILEGE_ESCALATION",
            cvss_score=r.cvss_score,
            description=r.description,
            attack_vector=r.attack_vector,
            mitigation=r.remediation_guidance,
            remediation_guidance=r.remediation_guidance,
            required_actions=r.required_actions,
            compute_service=r.compute_service,
            mitre_attack_id=r.mitre_attack_id,
        )
        for r in rules
    ]


@router.get(
    "/rules/{rule_id}",
    response_model=RuleCatalogItem,
    summary="Get details for a specific detection rule",
)
async def get_rule(rule_id: str) -> RuleCatalogItem:
    """
    Returns single rule documentation by rule_id or alternative rule ID.
    Supports canonical ID (PRIV_ESC_001), rule alias (RULE_CRIT_002),
    or hyphenated identifiers (IAM-ESC-001, PRIV-ESC-001).
    """
    norm_id = rule_id.upper().strip()
    rule = get_rule_by_id(norm_id)

    if not rule:
        # Try replacing hyphens with underscores
        underscore_id = norm_id.replace("-", "_")
        rule = get_rule_by_id(underscore_id)

    if not rule and norm_id.startswith(("IAM-ESC-", "IAM_ESC-", "IAM_ESC_")):
        # Map IAM-ESC-XXX to PRIV_ESC_XXX
        suffix = norm_id.split("-")[-1].split("_")[-1]
        try:
            num = int(suffix)
            mapped_id = f"PRIV_ESC_{num:03d}"
            rule = get_rule_by_id(mapped_id)
        except ValueError:
            pass

    if not rule:
        # Scan through all rules for matching rule_id, alt_id, or name
        for r in get_all_rules():
            if (
                r.rule_id.upper() == norm_id
                or (r.alt_id and r.alt_id.upper() == norm_id)
                or (r.alt_id and r.alt_id.upper() == norm_id.replace("-", "_"))
            ):
                rule = r
                break

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found",
        )

    return RuleCatalogItem(
        id=rule.rule_id,
        rule_id=rule.rule_id,
        name=rule.name,
        severity=rule.severity.value,
        category="PRIVILEGE_ESCALATION",
        cvss_score=rule.cvss_score,
        description=rule.description,
        attack_vector=rule.attack_vector,
        mitigation=rule.remediation_guidance,
        remediation_guidance=rule.remediation_guidance,
        required_actions=rule.required_actions,
        compute_service=rule.compute_service,
        mitre_attack_id=rule.mitre_attack_id,
    )
