"""
backend/tests/test_api.py

Comprehensive test suite verifying all REST API endpoints:
- Health check (/api/health and /health)
- Rules catalog (/api/rules and /api/rules/{rule_id})
- Stateless policy analysis (/api/policies/analyze)
- Persistent scans (/api/scans, /api/scans/{id}, /api/scans/{id}/graph, DELETE /api/scans/{id})
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
class TestHealthEndpoints:
    """Verifies service liveness and database connectivity checks."""

    async def test_health_api_prefix(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["database"] == "connected"
            assert "version" in data
            assert "timestamp" in data

    async def test_health_root_path(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["database"] == "connected"


@pytest.mark.asyncio
class TestRulesEndpoints:
    """Verifies detection rules catalog discovery and filtering endpoints."""

    async def test_get_all_rules_returns_catalog(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/rules")
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data, list)
            assert len(data) >= 21  # 25 authoritative detection rules

            # Verify schema of catalog items
            first_rule = data[0]
            assert "id" in first_rule
            assert "name" in first_rule
            assert "severity" in first_rule
            assert "category" in first_rule
            assert "description" in first_rule
            assert "mitigation" in first_rule
            assert "required_actions" in first_rule

    async def test_filter_rules_by_severity(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/rules?severity=CRITICAL")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) > 0
            for item in data:
                assert item["severity"] == "CRITICAL"

    async def test_filter_rules_by_service(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/rules?service=EC2")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) > 0
            for item in data:
                assert item["compute_service"].upper() == "EC2"

    async def test_get_rule_by_id_success(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Query by canonical ID
            resp = await client.get("/api/rules/IAM-ESC-001")
            assert resp.status_code == 200
            data = resp.json()
            assert data["rule_id"] in ("PRIV_ESC_001", "IAM-ESC-001", "RULE_CRIT_002")

    async def test_get_rule_by_id_not_found(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/rules/NONEXISTENT_RULE_999")
            assert resp.status_code == 404
            data = resp.json()
            assert "not found" in data["detail"].lower()


@pytest.mark.asyncio
class TestStatelessPolicyAnalysis:
    """Verifies stateless ad-hoc policy evaluation endpoint."""

    async def test_analyze_vulnerable_passrole_policy(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "policy_name": "PassRoleEC2Test",
                "policy_json": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "ec2:RunInstances"],
                            "Resource": "*",
                        }
                    ],
                },
            }
            resp = await client.post("/api/policies/analyze", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_valid"] is True
            assert data["is_vulnerable"] is True
            assert data["risk_score"] > 0
            assert len(data["vulnerabilities"]) >= 1

            finding = data["vulnerabilities"][0]
            assert "rule_id" in finding
            assert "severity" in finding
            assert "remediation" in finding
            assert "remediations" in finding
            assert len(finding["remediations"]) > 0

            # Verify attack graph output
            assert "graph" in data
            assert "nodes" in data["graph"]
            assert "edges" in data["graph"]

    async def test_analyze_benign_readonly_policy(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "policy_name": "ReadOnlyS3",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::my-secure-bucket/*",
                        }
                    ],
                },
            }
            resp = await client.post("/api/policies/analyze", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_valid"] is True
            assert data["is_vulnerable"] is False
            assert data["risk_score"] == 0
            assert len(data["vulnerabilities"]) == 0

    async def test_analyze_missing_payload(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/policies/analyze", json={})
            assert resp.status_code == 422

    async def test_analyze_invalid_policy_structure(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "policy_json": {
                    "Version": "2012-10-17",
                    "Statement": "ThisIsNotAValidStatementStructure",
                }
            }
            resp = await client.post("/api/policies/analyze", json=payload)
            assert resp.status_code == 422


@pytest.mark.asyncio
class TestScansLifecycleEndpoints:
    """Verifies persistent scan lifecycle: create, list, details, graph, delete."""

    async def test_create_and_retrieve_scan_with_policy_json(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            create_payload = {
                "title": "API Automation Test Scan",
                "description": "Integration test validating scan persistence",
                "policy_json": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:CreatePolicyVersion",
                            "Resource": "*",
                        }
                    ],
                },
            }
            create_resp = await client.post("/api/scans", json=create_payload)
            assert create_resp.status_code == 201
            scan_data = create_resp.json()
            scan_id = scan_data["id"]

            assert scan_data["title"] == "API Automation Test Scan"
            assert scan_data["status"] == "COMPLETED"
            assert scan_data["total_policies"] == 1
            assert scan_data["total_vulnerabilities"] >= 1
            assert scan_data["risk_score"] > 0
            assert "policies" in scan_data
            assert "vulnerabilities" in scan_data
            assert "findings" in scan_data
            assert "graph" in scan_data

            # Retrieve scan details
            get_resp = await client.get(f"/api/scans/{scan_id}")
            assert get_resp.status_code == 200
            detail_data = get_resp.json()
            assert detail_data["id"] == scan_id
            assert detail_data["title"] == "API Automation Test Scan"
            assert len(detail_data["policies"]) == 1
            assert len(detail_data["vulnerabilities"]) >= 1

    async def test_create_scan_with_batch_policies(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "name": "Batch Policies Test",
                "policies": [
                    {
                        "policy_name": "DevPolicy",
                        "policy_type": "MANAGED",
                        "attached_entity_type": "Role",
                        "attached_entity_name": "DeveloperRole",
                        "policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["iam:PassRole", "lambda:CreateFunction"],
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                    {
                        "policy_name": "AuditorPolicy",
                        "policy_type": "MANAGED",
                        "attached_entity_type": "User",
                        "attached_entity_name": "SecurityAuditor",
                        "policy_document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:Get*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                ],
            }
            create_resp = await client.post("/api/scans", json=payload)
            assert create_resp.status_code == 201
            scan_data = create_resp.json()
            assert scan_data["total_policies"] == 2
            assert len(scan_data["policies"]) == 2

    async def test_list_scans_with_pagination(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            list_resp = await client.get("/api/scans?page=1&page_size=5")
            assert list_resp.status_code == 200
            data = list_resp.json()
            assert "items" in data
            assert "total" in data
            assert "page" in data
            assert "page_size" in data
            assert "total_pages" in data
            assert data["page"] == 1
            assert data["page_size"] == 5
            assert isinstance(data["items"], list)

    async def test_get_scan_not_found(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/scans/00000000-0000-0000-0000-000000000000")
            assert resp.status_code == 404
            assert "not found" in resp.json()["detail"].lower()

    async def test_get_scan_graph_structure(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create a scan first
            create_payload = {
                "title": "Graph Verification Scan",
                "policy_json": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "ec2:RunInstances"],
                            "Resource": "*",
                        }
                    ],
                },
            }
            create_resp = await client.post("/api/scans", json=create_payload)
            assert create_resp.status_code == 201
            scan_id = create_resp.json()["id"]

            # Query graph endpoint
            graph_resp = await client.get(f"/api/scans/{scan_id}/graph")
            assert graph_resp.status_code == 200
            graph_data = graph_resp.json()

            assert graph_data["scan_id"] == scan_id
            assert "nodes" in graph_data
            assert "edges" in graph_data
            assert "summary" in graph_data
            assert "cytoscape" in graph_data
            assert isinstance(graph_data["nodes"], list)
            assert isinstance(graph_data["edges"], list)
            assert len(graph_data["nodes"]) > 0
            assert len(graph_data["edges"]) > 0

            # Verify React Flow node fields
            first_node = graph_data["nodes"][0]
            assert "id" in first_node
            assert "data" in first_node
            assert "position" in first_node

    async def test_get_scan_graph_not_found(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/scans/00000000-0000-0000-0000-000000000000/graph")
            assert resp.status_code == 404

    async def test_delete_scan_lifecycle(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Create a scan to delete
            create_payload = {
                "title": "Temporary Scan for Deletion",
                "policy_json": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:ListBucket",
                            "Resource": "*",
                        }
                    ],
                },
            }
            create_resp = await client.post("/api/scans", json=create_payload)
            assert create_resp.status_code == 201
            scan_id = create_resp.json()["id"]

            # Delete the scan
            del_resp = await client.delete(f"/api/scans/{scan_id}")
            assert del_resp.status_code == 204

            # Verify it is no longer found
            get_resp = await client.get(f"/api/scans/{scan_id}")
            assert get_resp.status_code == 404

            # Second delete returns 404
            del_again_resp = await client.delete(f"/api/scans/{scan_id}")
            assert del_again_resp.status_code == 404
