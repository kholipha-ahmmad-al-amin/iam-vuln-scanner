# IAM Vulnerability Scanner

## The Problem

AWS IAM misconfiguration is the leading cause of cloud breaches. Security teams lack automated tooling to detect privilege escalation paths buried inside complex IAM policy documents. Manual review of hundreds of policies is error-prone and operationally unsustainable. This engine automates full-depth static analysis of IAM JSON policies, maps all privilege escalation vectors across 25 known attack patterns, and constructs a navigable attack graph of role relationships.

## The Architecture

The system is a Python-first backend built on FastAPI with async PostgreSQL persistence via SQLAlchemy. At its core is a deterministic rule evaluation engine that parses IAM policy JSON into an AST (Abstract Syntax Tree), evaluates each statement against a 25-rule escalation catalog, and feeds results into a graph builder that models role chaining and trust relationship paths. The REST API exposes policy ingestion, scan execution, and results retrieval.

```mermaid
graph TD
    Client((Client)) --> |POST /api/v1/policies| API[FastAPI Ingestion Layer]
    API --> |Persist Policy| DB[(PostgreSQL)]
    API --> |Dispatch Scan| Evaluator[IAM Rule Evaluator]
    Evaluator --> |AST Parse| Parser[IAM AST Parser]
    Parser --> |Policy Nodes| RuleCatalog[25-Rule Escalation Catalog]
    RuleCatalog --> |Findings| GraphBuilder[Attack Graph Builder]
    GraphBuilder --> |Persist Graph| DB
    GraphBuilder --> |Attack Paths| API
    API --> |Scan Results + Graph| Client
```

## Entity Relationship Diagram

```mermaid
erDiagram
    SCAN {
        uuid id PK
        string status
        timestamp created_at
        timestamp completed_at
    }
    POLICY {
        uuid id PK
        uuid scan_id FK
        string name
        json raw_document
        timestamp created_at
    }
    VULNERABILITY {
        uuid id PK
        uuid policy_id FK
        string rule_id
        string severity
        string description
        json affected_actions
        timestamp detected_at
    }
    ATTACK_GRAPH {
        uuid id PK
        uuid scan_id FK
        json nodes
        json edges
        timestamp created_at
    }
    SCAN ||--o{ POLICY : contains
    POLICY ||--o{ VULNERABILITY : generates
    SCAN ||--o{ ATTACK_GRAPH : produces
```

## Data Flow Diagram (Level 0)

```mermaid
graph TD
    Analyst((Security Analyst)) --> |IAM Policy JSON| System[IAM Vulnerability Scanner]
    System --> |Vulnerability Report + Attack Graph| Analyst
    System --> |Persist Findings| DB[(PostgreSQL)]
```

## Data Flow Diagram (Level 1)

```mermaid
graph TD
    Client((Client)) --> |Raw Policy JSON| Ingest(Policy Ingestion API)
    Ingest --> |Stored Policy| DB[(PostgreSQL)]
    Ingest --> |Policy Document| ASTParser(IAM AST Parser)
    ASTParser --> |Policy AST| RuleEngine(Rule Evaluation Engine)
    RuleEngine --> |Matched Rules| FindingsCollector(Findings Collector)
    FindingsCollector --> |Vulnerability Records| DB
    FindingsCollector --> |Findings| GraphBuilder(Attack Graph Builder)
    GraphBuilder --> |Graph Edges and Nodes| DB
    GraphBuilder --> |Attack Path JSON| Client
```

## Use Case Diagram

```mermaid
flowchart LR
    Analyst((Security Analyst)) --> UploadPolicy(Upload IAM Policy)
    Analyst --> TriggerScan(Trigger Scan)
    Analyst --> ViewFindings(View Vulnerability Findings)
    Analyst --> ExploreGraph(Explore Attack Graph)
    System((System)) --> EvaluateRules(Evaluate 25 Escalation Rules)
    EvaluateRules -.-> |include| ParseAST(Parse Policy AST)
    EvaluateRules -.-> |include| BuildGraph(Build Attack Graph)
```

## Sequence Diagram

```mermaid
sequenceDiagram
    participant C as Client
    participant A as FastAPI
    participant E as Rule Evaluator
    participant G as Graph Builder
    participant D as PostgreSQL

    C->>A: POST /api/v1/policies (policy JSON)
    A->>D: INSERT policy record
    A-->>C: 201 Created (policy_id)

    C->>A: POST /api/v1/scans (policy_id)
    A->>E: evaluate_policy(policy_ast)
    E->>E: Match against 25-rule catalog
    E-->>A: findings[]
    A->>G: build_attack_graph(findings)
    G-->>A: attack_graph (nodes, edges)
    A->>D: INSERT vulnerabilities + attack_graph
    A-->>C: 200 OK (scan_id, severity_summary)

    C->>A: GET /api/v1/scans/{scan_id}
    A->>D: SELECT scan + vulnerabilities + graph
    A-->>C: Full scan report
```

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| API Framework | FastAPI |
| ORM | SQLAlchemy (async) |
| Database | PostgreSQL |
| Validation | Pydantic v2 |
| Testing | pytest (167 tests, 0 failures) |
| IAM Rules | 25-rule privilege escalation catalog |
| Containerization | Docker (planned) |

## Privilege Escalation Rules Covered

**Critical Severity (10 rules)**
- Admin wildcard (`*:*`)
- CreatePolicyVersion
- PutUserPolicy / PutGroupPolicy / PutRolePolicy
- AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy
- AddUserToGroup
- UpdateAssumeRolePolicy

**High Severity (14 rules)**
- PassRole via EC2, Lambda, Glue, CloudFormation, CodeBuild, ECS, SageMaker, DataPipeline
- CreateAccessKey, CreateLoginProfile, UpdateLoginProfile
- SetDefaultPolicyVersion, LambdaUpdateFunctionCode, LambdaAddEventSource

**Medium Severity (1 rule)**
- STS AssumeRole chaining

## Local Setup

```bash
git clone https://github.com/kholipha-ahmmad-al-amin/iam-vuln-scanner.git
cd iam-vuln-scanner/backend

python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/Mac

pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start API server (requires DATABASE_URL env var for persistence)
uvicorn app.main:app --reload --port 8000
```

To scan a sample policy:
```bash
curl -X POST http://localhost:8000/api/v1/policies \
  -H "Content-Type: application/json" \
  -d @backend/samples/vulnerable_passrole_ec2.json
```

---

Developed by Kholipha Ahmmad Al-Amin
Founder and CEO, EquiSaaS BD | Principal Consultant, AR IT Consultancy
Expertise: Full Stack Enterprise Architecture & AI Engineering
GitHub: https://github.com/kholipha-ahmmad-al-amin
LinkedIn: https://www.linkedin.com/in/kholipha-ahmmad-al-amin
Portfolio: https://kholipha-ahmmad-al-amin.equisaas-bd.com
Email: kholifaahmadalamin@gmail.com
