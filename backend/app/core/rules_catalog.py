"""
backend/app/core/rules_catalog.py

Authoritative catalog of 25 AWS IAM privilege escalation detection rules.
Covers all 21 Rhino Security Labs methods plus 4 critical modern cloud extensions.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from app.core.ast_models import SeverityEnum, VulnerabilityFinding


class RuleSeverity(str, Enum):
    """Normalized rule severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class EscalationRule:
    """Represents a privilege escalation detection rule."""
    rule_id: str
    name: str
    severity: RuleSeverity
    cvss_score: float
    description: str
    attack_vector: str
    required_actions: List[str]
    required_resources: List[str]
    compute_service: str
    remediation_guidance: str
    alt_id: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    action_groups: List[List[str]] = field(default_factory=list)

    def is_action_satisfied(self, granted_actions: Set[str]) -> bool:
        """
        Evaluates whether a set of granted actions satisfies this rule.
        Supports wildcard expansion (e.g., 'iam:*' satisfies 'iam:CreatePolicyVersion',
        '*' satisfies all actions, but specific actions do not satisfy '*:*').
        """
        def action_matches(granted: str, target: str) -> bool:
            g = granted.lower().strip()
            t = target.lower().strip()
            if g == "*":
                return True
            if t == "*":
                return g == "*"
            return fnmatch.fnmatch(t, g)

        # If action_groups is defined, each group must have at least one match
        if self.action_groups:
            for group in self.action_groups:
                group_matched = False
                for req in group:
                    if any(action_matches(granted, req) for granted in granted_actions):
                        group_matched = True
                        break
                if not group_matched:
                    return False
            return True

        # Default: all required_actions must be matched
        for req in self.required_actions:
            if not any(action_matches(granted, req) for granted in granted_actions):
                return False
        return True


# The authoritative 25 Privilege Escalation Rules
RULES_CATALOG: List[EscalationRule] = [
    # 1. Method 1 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_001",
        name="IAM CreatePolicyVersion Privilege Escalation",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to create a new version of an existing managed policy granting administrator privileges and set it as default.",
        attack_vector="Attacker creates a new version of an attached managed policy with Action: * and Resource: * and sets it as the default version.",
        required_actions=["iam:CreatePolicyVersion"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Disallow iam:CreatePolicyVersion for standard users. Restrict this permission to audited IAM governance automation and enforce permissions boundaries.",
        alt_id="RULE_CRIT_002",
        mitre_attack_id="T1098"
    ),

    # 2. Method 2 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_002",
        name="IAM SetDefaultPolicyVersion Privilege Escalation",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to switch the active default version of a managed policy to an older, potentially more privileged version.",
        attack_vector="Attacker discovers an older version of an attached policy that granted higher privileges and sets it as default.",
        required_actions=["iam:SetDefaultPolicyVersion"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Delete older unused managed policy versions using iam:DeletePolicyVersion and deny iam:SetDefaultPolicyVersion for general users.",
        alt_id="RULE_HIGH_001",
        mitre_attack_id="T1098"
    ),

    # 3. Method 3 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_003",
        name="IAM CreateAccessKey Impersonation",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create a new access key pair for another IAM user, receiving credentials in the API response.",
        attack_vector="Attacker targets a privileged IAM user with fewer than 2 active keys, creates an access key, and logs in using the credentials.",
        required_actions=["iam:CreateAccessKey"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Restrict iam:CreateAccessKey to the caller's own user ARN using resource condition arn:aws:iam::*:user/${aws:username}.",
        alt_id="RULE_HIGH_002",
        mitre_attack_id="T1078.004"
    ),

    # 4. Method 4 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_004",
        name="IAM CreateLoginProfile Console Access Hijacking",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create a console password for an existing IAM user who currently does not have console access.",
        attack_vector="Attacker targets a privileged API user without console access, sets a password, and logs into the AWS Management Console.",
        required_actions=["iam:CreateLoginProfile"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Deny iam:CreateLoginProfile for non-admin identities and enforce Multi-Factor Authentication (MFA) requirements.",
        alt_id="RULE_HIGH_003",
        mitre_attack_id="T1078.004"
    ),

    # 5. Method 5 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_005",
        name="IAM UpdateLoginProfile Console Password Reset",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to overwrite the console password for an existing IAM user who already has console login enabled.",
        attack_vector="Attacker resets the console password of an existing administrator and accesses the AWS Management Console.",
        required_actions=["iam:UpdateLoginProfile"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Restrict iam:UpdateLoginProfile to allow users to update only their own password using arn:aws:iam::*:user/${aws:username}.",
        alt_id="RULE_HIGH_004",
        mitre_attack_id="T1078.004"
    ),

    # 6. Method 6 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_006",
        name="IAM AttachUserPolicy Direct Privilege Escalation",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to attach an existing managed policy such as AdministratorAccess directly to an IAM user.",
        attack_vector="Attacker attaches AdministratorAccess policy to their own user identity, immediately escalating privileges.",
        required_actions=["iam:AttachUserPolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Revoke iam:AttachUserPolicy from general users and attach strict IAM permissions boundaries to all user identities.",
        alt_id="RULE_CRIT_006",
        mitre_attack_id="T1098"
    ),

    # 7. Method 7 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_007",
        name="IAM AttachGroupPolicy Group-Level Privilege Escalation",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to attach an administrative managed policy to any IAM group.",
        attack_vector="Attacker attaches an administrative managed policy to a group they belong to, escalating privileges for all members.",
        required_actions=["iam:AttachGroupPolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Restrict iam:AttachGroupPolicy to IAM administration roles and prohibit ad-hoc policy attachments.",
        alt_id="RULE_CRIT_007",
        mitre_attack_id="T1098"
    ),

    # 8. Method 8 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_008",
        name="IAM AttachRolePolicy Role Modification Escalation",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to attach an administrative managed policy to an IAM role.",
        attack_vector="Attacker attaches AdministratorAccess to a role they can assume or pass to a service, then assumes or passes that role.",
        required_actions=["iam:AttachRolePolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Deny iam:AttachRolePolicy for non-administrative users and audit existing role attachment configurations.",
        alt_id="RULE_CRIT_008",
        mitre_attack_id="T1098"
    ),

    # 9. Method 9 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_009",
        name="IAM PutUserPolicy Inline Policy Injection",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to write or overwrite an inline policy document directly inside an IAM user identity.",
        attack_vector="Attacker calls iam:PutUserPolicy on their own user with Action: * and Resource: *, granting direct account administrator access.",
        required_actions=["iam:PutUserPolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Prevent users from modifying inline policies. Deny iam:PutUserPolicy and transition to managed policies.",
        alt_id="RULE_CRIT_003",
        mitre_attack_id="T1098"
    ),

    # 10. Method 10 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_010",
        name="IAM PutGroupPolicy Inline Policy Injection",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to inject an inline policy granting wildcard permissions into an IAM group.",
        attack_vector="Attacker calls iam:PutGroupPolicy with an administrative document on a group they are a member of.",
        required_actions=["iam:PutGroupPolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Deny iam:PutGroupPolicy for all non-governance identities and enforce centralized policy pipelines.",
        alt_id="RULE_CRIT_004",
        mitre_attack_id="T1098"
    ),

    # 11. Method 11 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_011",
        name="IAM PutRolePolicy Inline Policy Injection",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to embed an inline policy granting full administrative access into an IAM role.",
        attack_vector="Attacker embeds a wildcard policy into an assumeable or passable role, then accesses that role.",
        required_actions=["iam:PutRolePolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Restrict iam:PutRolePolicy to IAM administrators and require Service Control Policies preventing inline role policies.",
        alt_id="RULE_CRIT_005",
        mitre_attack_id="T1098"
    ),

    # 12. Method 12 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_012",
        name="IAM AddUserToGroup Privileged Group Membership Escalation",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to add an IAM user to any IAM group, inheriting all policies attached to that group.",
        attack_vector="Attacker adds their own user account to an existing administrator or operations group.",
        required_actions=["iam:AddUserToGroup"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Deny iam:AddUserToGroup on sensitive administrative groups using explicit Deny statements or SCPs.",
        alt_id="RULE_CRIT_009",
        mitre_attack_id="T1098"
    ),

    # 13. Method 13 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_013",
        name="IAM UpdateAssumeRolePolicy Trust Document Manipulation",
        severity=RuleSeverity.CRITICAL,
        cvss_score=9.8,
        description="Allows caller to modify the trust policy (AssumeRolePolicyDocument) of an IAM role.",
        attack_vector="Attacker updates the trust policy of an existing administrative role to trust their own identity, then calls sts:AssumeRole.",
        required_actions=["iam:UpdateAssumeRolePolicy"],
        required_resources=["*"],
        compute_service="IAM",
        remediation_guidance="Restrict iam:UpdateAssumeRolePolicy strictly to IAM security governance automation and monitor via CloudTrail.",
        alt_id="RULE_CRIT_010",
        mitre_attack_id="T1098"
    ),

    # 14. Method 14 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_014",
        name="EC2 RunInstances PassRole Instance Metadata Extraction",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to launch an EC2 instance with an attached privileged instance profile and extract temporary credentials via IMDS.",
        attack_vector="Attacker launches an EC2 instance specifying a high-privilege instance profile, with user data script exfiltrating credentials from IMDS.",
        required_actions=["iam:PassRole", "ec2:RunInstances"],
        required_resources=["*"],
        compute_service="EC2",
        remediation_guidance="Add the condition iam:PassedToService: ec2.amazonaws.com on iam:PassRole, scope resource to specific role ARNs, and enforce IMDSv2.",
        alt_id="RULE_HIGH_005",
        mitre_attack_id="T1078.004"
    ),

    # 15. Method 15 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_015",
        name="Lambda CreateFunction PassRole & Invoke",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create a Lambda function with a privileged execution role and invoke it directly to execute arbitrary code.",
        attack_vector="Attacker creates a Lambda function passing an administrative execution role and invokes it to perform unauthorized operations.",
        required_actions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        required_resources=["*"],
        compute_service="Lambda",
        remediation_guidance="Scope iam:PassRole to specific Lambda role ARNs and restrict lambda:CreateFunction / lambda:InvokeFunction permissions.",
        alt_id="RULE_HIGH_006",
        mitre_attack_id="T1078.004"
    ),

    # 16. Method 16 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_016",
        name="Lambda EventSourceMapping PassRole Trigger",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create a Lambda function with an elevated role and trigger execution via an event source mapping without invoke rights.",
        attack_vector="Attacker creates a Lambda function with a privileged role, creates an event source mapping, and publishes an event to trigger execution.",
        required_actions=["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
        required_resources=["*"],
        compute_service="Lambda",
        remediation_guidance="Restrict lambda:CreateEventSourceMapping and enforce strict resource ARN limits on iam:PassRole.",
        alt_id="RULE_HIGH_007",
        mitre_attack_id="T1078.004"
    ),

    # 17. Method 17 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_017",
        name="Lambda UpdateFunctionCode Tampering",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to overwrite the executable code of an existing Lambda function running under a high-privilege IAM execution role.",
        attack_vector="Attacker modifies the deployment package of an existing administrative Lambda function to include backdoor execution logic.",
        required_actions=["lambda:UpdateFunctionCode"],
        required_resources=["*"],
        compute_service="Lambda",
        remediation_guidance="Restrict lambda:UpdateFunctionCode to CI/CD deployment roles only and enforce code signing for AWS Lambda.",
        alt_id="RULE_HIGH_008",
        mitre_attack_id="T1078.004"
    ),

    # 18. Method 18 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_018",
        name="Glue DevEndpoint PassRole SSH Escalation",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create or update an AWS Glue development endpoint with an administrative role and attacker-controlled SSH public key.",
        attack_vector="Attacker launches a Glue development endpoint passing an administrative role and SSH key, connects via SSH, and extracts credentials.",
        required_actions=["iam:PassRole", "glue:CreateDevEndpoint"],
        required_resources=["*"],
        compute_service="Glue",
        remediation_guidance="Disallow glue:CreateDevEndpoint and glue:UpdateDevEndpoint for standard users and constrain iam:PassRole to glue.amazonaws.com.",
        alt_id="RULE_HIGH_009",
        mitre_attack_id="T1078.004",
        action_groups=[["iam:passrole"], ["glue:createdevendpoint", "glue:updatedevendpoint"]]
    ),

    # 19. Method 19 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_019",
        name="CloudFormation Stack PassRole Escalation",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to deploy a CloudFormation template passing a privileged service role, provisioning new administrative resources.",
        attack_vector="Attacker creates or updates a CloudFormation stack with a template that creates an admin user, passing a privileged role.",
        required_actions=["iam:PassRole", "cloudformation:CreateStack"],
        required_resources=["*"],
        compute_service="CloudFormation",
        remediation_guidance="Restrict cloudformation:CreateStack / UpdateStack and ensure CloudFormation service roles do not possess full IAM administration capabilities.",
        alt_id="RULE_HIGH_010",
        mitre_attack_id="T1078.004",
        action_groups=[["iam:passrole"], ["cloudformation:createstack", "cloudformation:updatestack"]]
    ),

    # 20. Method 20 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_020",
        name="DataPipeline PassRole Command Execution",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create, configure, and activate an AWS DataPipeline with a privileged role executing arbitrary shell commands.",
        attack_vector="Attacker creates a DataPipeline with ShellCommandActivity passing an elevated role, then activates it to run shell commands.",
        required_actions=["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"],
        required_resources=["*"],
        compute_service="DataPipeline",
        remediation_guidance="Restrict datapipeline lifecycle actions and restrict iam:PassRole to verified DataPipeline role ARNs.",
        alt_id="RULE_HIGH_011",
        mitre_attack_id="T1078.004"
    ),

    # 21. Method 21 (Rhino)
    EscalationRule(
        rule_id="PRIV_ESC_021",
        name="CodeBuild Project PassRole Build Execution",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to create a CodeBuild project with a privileged service role, configure a buildspec executing privilege escalation commands, and trigger the build.",
        attack_vector="Attacker creates a CodeBuild project passing an administrative service role with a buildspec that creates an admin user, then starts the build.",
        required_actions=["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        required_resources=["*"],
        compute_service="CodeBuild",
        remediation_guidance="Restrict codebuild:CreateProject and codebuild:StartBuild, and scope iam:PassRole to dedicated non-administrative build roles.",
        alt_id="RULE_HIGH_012",
        mitre_attack_id="T1078.004"
    ),

    # 22. Modern Extension 1
    EscalationRule(
        rule_id="PRIV_ESC_022",
        name="ECS Task Execution PassRole Container Run",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to register an ECS task definition with a high-privilege task execution role and run a container executing arbitrary commands.",
        attack_vector="Attacker registers an ECS task definition with an administrative task execution role, then executes ecs:RunTask to run their container.",
        required_actions=["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
        required_resources=["*"],
        compute_service="ECS",
        remediation_guidance="Constrain iam:PassRole for ECS task definitions to specific task role ARNs and restrict ecs:RegisterTaskDefinition / ecs:RunTask.",
        alt_id="RULE_HIGH_013",
        mitre_attack_id="T1078.004",
        action_groups=[["iam:passrole"], ["ecs:registertaskdefinition"], ["ecs:runtask", "ecs:starttask"]]
    ),

    # 23. Modern Extension 2
    EscalationRule(
        rule_id="PRIV_ESC_023",
        name="SageMaker Notebook PassRole Terminal Access",
        severity=RuleSeverity.HIGH,
        cvss_score=8.8,
        description="Allows caller to launch a SageMaker notebook instance attached to a privileged IAM role and access its Jupyter terminal via a presigned URL.",
        attack_vector="Attacker creates a SageMaker notebook instance with a privileged role, generates a presigned URL, and extracts credentials from terminal IMDS.",
        required_actions=["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"],
        required_resources=["*"],
        compute_service="SageMaker",
        remediation_guidance="Scope iam:PassRole to specific SageMaker roles with minimal permissions and restrict presigned URL creation.",
        alt_id="RULE_HIGH_014",
        mitre_attack_id="T1078.004"
    ),

    # 24. Modern Extension 3
    EscalationRule(
        rule_id="PRIV_ESC_024",
        name="STS AssumeRole Transitive Chaining Hop",
        severity=RuleSeverity.MEDIUM,
        cvss_score=6.5,
        description="Allows caller to assume an IAM role via STS, enabling lateral movement and transitive privilege escalation chains.",
        attack_vector="Attacker assumes an IAM role via STS that in turn possesses higher permissions or additional escalation paths.",
        required_actions=["sts:AssumeRole"],
        required_resources=["*"],
        compute_service="STS",
        remediation_guidance="Require ExternalId or MFA conditions on role trust policies and specify explicit role ARNs rather than wildcards.",
        alt_id="RULE_MED_001",
        mitre_attack_id="T1548"
    ),

    # 25. Modern Extension 4
    EscalationRule(
        rule_id="PRIV_ESC_025",
        name="Full Administrator Wildcard Access",
        severity=RuleSeverity.CRITICAL,
        cvss_score=10.0,
        description="Policy grants unrestricted administrative power across all AWS services, APIs, and resources without boundary checks.",
        attack_vector="Caller possesses unconditional administrative control over the entire AWS account. Can create users, delete backups, and alter all resources.",
        required_actions=["*"],
        required_resources=["*"],
        compute_service="ALL",
        remediation_guidance="Remove the wildcard statement immediately. Adopt AWS Least Privilege best practices by specifying exact services, actions, and resource ARNs.",
        alt_id="RULE_CRIT_001",
        mitre_attack_id="T1078"
    ),
]

# High-performance lookup mapping supporting both primary ID and alt ID
RULES_BY_ID: Dict[str, EscalationRule] = {}
for rule in RULES_CATALOG:
    RULES_BY_ID[rule.rule_id.upper()] = rule
    if rule.alt_id:
        RULES_BY_ID[rule.alt_id.upper()] = rule


def get_rule_by_id(rule_id: str) -> Optional[EscalationRule]:
    """Retrieve a single rule by its unique rule_id or alternative ID."""
    return RULES_BY_ID.get(rule_id.upper())


def get_all_rules() -> List[EscalationRule]:
    """Retrieve all 25 registered escalation rules."""
    return list(RULES_CATALOG)


def get_rules_by_severity(severity: RuleSeverity) -> List[EscalationRule]:
    """Filter rules by severity level."""
    return [r for r in RULES_CATALOG if r.severity == severity]


def get_rules_by_service(service: str) -> List[EscalationRule]:
    """Filter rules by compute/target service."""
    return [r for r in RULES_CATALOG if r.compute_service.upper() == service.upper()]


def evaluate_actions_against_rules(allowed_actions: Set[str]) -> List[EscalationRule]:
    """
    Checks an active allowed action set against all 25 rules and returns all triggered rules.
    """
    triggered = []
    for rule in RULES_CATALOG:
        if rule.is_action_satisfied(allowed_actions):
            triggered.append(rule)
    return triggered
