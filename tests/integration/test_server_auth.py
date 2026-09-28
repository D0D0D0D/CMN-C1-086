# Integration — entry-adapter auth core (CMN-C1-086)
# Verifies the standalone HTTP entry point rejects unauthenticated callers
# (fail-closed) and accepts INVOKE_AUTH_TOKEN Bearer authentication. The old
# fallback that defaulted callers to ANONYMOUS was fail-open (S-1 bypass) and
# has been removed.

import json

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
TestClient = fastapi_testclient.TestClient


SAMPLE = json.dumps(
    {
        "period": "2026-06",
        "logs": [
            {"entry_id": "E1", "agent_type": "rag", "action": "query", "outcome": "success"},
        ],
    }
)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("INVOKE_AUTH_TOKEN", "mock-invoke-token-for-testing")
    from src.api.server import app

    return TestClient(app)


def test_unauthenticated_invoke_rejected(client):
    # No verified middleware trust and no Bearer token → 401 (fail-closed).
    resp = client.post("/invoke", json={"input": SAMPLE, "session_id": "s1"})
    assert resp.status_code == 401


def test_invalid_token_rejected(client):
    resp = client.post(
        "/invoke",
        json={"input": SAMPLE, "session_id": "s1"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401


def test_valid_token_accepted(client):
    resp = client.post(
        "/invoke",
        json={"input": SAMPLE, "session_id": "s1"},
        headers={"Authorization": "Bearer mock-invoke-token-for-testing"},
    )
    # Token promotes ANONYMOUS → VERIFIED_EXTERNAL; invoke proceeds (not 401/403).
    assert resp.status_code == 200


def test_health_no_auth_required(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
