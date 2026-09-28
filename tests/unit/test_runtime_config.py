"""Runtime configuration must drive the production HTTP agent."""

from __future__ import annotations

import json

import pytest

from framework.errors import SecurityViolationError
from src.nodes.pre_process_node import MAX_LOG_BYTES


def _write_config(path, *, max_log_bytes: int = 1024) -> None:
    path.write_text(
        "\n".join(
            (
                "max_retry: 3",
                f"max_log_bytes: {max_log_bytes}",
                "memory_enabled: false",
                "hitl:",
                "  enabled: false",
            )
        )
    )


def test_production_http_agent_consumes_runtime_config() -> None:
    from src.api import server

    assert server.agent.config["max_log_bytes"] == MAX_LOG_BYTES
    assert server.agent.config["max_retry"] == 3
    assert server.agent.config["memory_enabled"] is False
    assert server.agent.config["hitl"] == {"enabled": False}


def test_entrypoint_configures_preprocess_size_cap(monkeypatch, tmp_path) -> None:
    from src.api import server

    config_path = tmp_path / "config.yaml"
    _write_config(config_path, max_log_bytes=1024)
    graph = server._build_agent(config_path)
    node = graph._nodes["pre_process"]
    payload = json.dumps({"logs": [{"action": "x" * 2048}]})

    with pytest.raises(SecurityViolationError):
        node._extra_security_gate_input({"user_input": payload})

    testclient = pytest.importorskip("fastapi.testclient")
    monkeypatch.setenv("INVOKE_AUTH_TOKEN", "mock-invoke-token-for-testing")
    monkeypatch.setattr(server, "agent", graph)
    response = testclient.TestClient(server.app).post(
        "/invoke",
        json={"input": payload, "session_id": "runtime-config-test"},
        headers={"Authorization": "Bearer mock-invoke-token-for-testing"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "error"


def test_missing_config_keeps_documented_default_cap(tmp_path) -> None:
    from src.api import server

    graph = server._build_agent(tmp_path / "missing.yaml")
    node = graph._nodes["pre_process"]
    assert graph.config["max_log_bytes"] == MAX_LOG_BYTES
    assert node.max_log_bytes == MAX_LOG_BYTES


def test_unknown_runtime_key_is_rejected(tmp_path) -> None:
    from src.runtime_config import load_runtime_config

    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    config_path.write_text(config_path.read_text() + "\ndecorative_only: true\n")

    with pytest.raises(ValueError, match="unknown runtime configuration"):
        load_runtime_config(config_path)


def test_invalid_runtime_value_types_are_rejected(tmp_path) -> None:
    from src.runtime_config import load_runtime_config

    invalid_documents = (
        "- not-a-mapping\n",
        "max_retry: true\nmax_log_bytes: 1024\nmemory_enabled: false\nhitl: {enabled: false}\n",
        "max_retry: 3\nmax_log_bytes: 0\nmemory_enabled: false\nhitl: {enabled: false}\n",
        "max_retry: 3\nmax_log_bytes: 1024\nmemory_enabled: disabled\nhitl: {enabled: false}\n",
        "max_retry: 3\nmax_log_bytes: 1024\nmemory_enabled: false\nhitl: true\n",
        "max_retry: 3\nmax_log_bytes: 1024\nmemory_enabled: false\nhitl: {enabled: enabled}\n",
        "max_retry: 3\nmax_log_bytes: 1024\nmemory_enabled: false\nhitl: {enabled: true}\n",
    )
    config_path = tmp_path / "config.yaml"
    for document in invalid_documents:
        config_path.write_text(document)
        with pytest.raises(ValueError):
            load_runtime_config(config_path)
