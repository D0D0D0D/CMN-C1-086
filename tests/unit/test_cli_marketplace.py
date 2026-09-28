"""AGENTIC STAR Marketplace adapter tests for CMN-C1-086."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

import cli
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.base import SecretProvider
from framework.secrets.context import bound_secrets
from shared.services.llm.base_llm import BaseLLM
from src.graph.graph import AgentAuditReportAgent

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VALID_AZURE_ENV = {
    "AZURE_OPENAI_API_KEY": "test-key",
    "AZURE_OPENAI_ENDPOINT": "http://127.0.0.1:1",
    "AZURE_OPENAI_DEPLOYMENT": "test-deployment",
}
_SAMPLE = json.dumps(
    {
        "period": "2026-06",
        "logs": [
            {
                "entry_id": "E1",
                "agent_type": "rag",
                "action": "query",
                "outcome": "success",
            },
            {
                "entry_id": "E2",
                "agent_type": "react",
                "action": "exfiltrate",
                "outcome": "blocked",
                "is_security_exception": True,
            },
        ],
    }
)


class _UnusedProvider(SecretProvider):
    def get(self, key: str, default: str | None = None) -> str | None:
        del key
        return default


class _CountingLLM(BaseLLM):
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[Any]) -> dict[str, Any]:
        self.calls += 1
        return {
            "content": "監査ログを確認し、重大イベントを一件検出しました。",
            "tool_calls": [],
            "model": "counting-fake",
            "usage": {},
        }

    def stream(self, messages: list[Any]):
        yield self.complete(messages)["content"]

    def bind_tools(self, tools: list[Any]) -> BaseLLM:
        del tools
        return self


class _InspectableMarketplaceGraph(cli.MarketplaceGraph):
    def _enrich_output(self, output: dict[str, Any], result: dict[str, Any]) -> None:
        super()._enrich_output(output, result)
        output["_test_state"] = result


def _ctx() -> InvocationContext:
    return InvocationContext(
        caller_id="marketplace-test",
        caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
    )


def _set_valid_azure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in _VALID_AZURE_ENV.items():
        monkeypatch.setenv(key, value)


def _runtime_config() -> dict[str, Any]:
    return cli.load_agent_config(_REPO_ROOT)


def test_environment_provider_exposes_only_allowlisted_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INVOKE_AUTH_TOKEN", "must-not-be-readable")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "allowed-api-key")
    provider = cli._AllowlistedEnvironmentProvider()

    assert provider.get("INVOKE_AUTH_TOKEN", "sentinel") == "sentinel"
    assert provider.get("AZURE_OPENAI_API_KEY", "sentinel") == "allowed-api-key"


def test_invoke_rebuilds_input_context(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_invoke(self, user_input, session_id="", ctx=None, input_context=None):
        del self
        captured.update(
            user_input=user_input,
            session_id=session_id,
            ctx=ctx,
            input_context=input_context,
        )
        return {"status": "success", "output": "ok"}

    monkeypatch.setattr(AgentAuditReportAgent, "invoke", fake_invoke)
    agent = cli.MarketplaceGraph(config={})
    result = agent.invoke(
        _SAMPLE,
        ctx=_ctx(),
        input_context={"conversation_history": [{"role": "user", "content": "CANARY"}]},
    )

    assert result["status"] == "success"
    assert captured["user_input"] == _SAMPLE
    assert captured["input_context"] == {}
    assert "conversation_history" not in captured["input_context"]


@pytest.mark.parametrize("key", cli._AZURE_OPENAI_SECRET_KEYS)
@pytest.mark.parametrize("bad_value", [None, "", " leading", "trailing ", "embedded value"])
def test_provision_secrets_rejects_missing_or_dirty_azure_values(
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    bad_value: str | None,
) -> None:
    _set_valid_azure_environment(monkeypatch)
    if bad_value is None:
        monkeypatch.delenv(key)
    else:
        monkeypatch.setenv(key, bad_value)

    with pytest.raises(ValueError):
        cli.MarketplaceGraph(config={}).provision_secrets(_UnusedProvider())


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://example.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview",
        "https://example.services.ai.azure.example/openai",
        "https://example.services.ai.azure.example/v1",
        "https://example.services.ai.azure.example?api-version=2024-10-21",
        "example.services.ai.azure.example",
    ],
    ids=["api-path", "openai-path", "base-path", "query-only", "missing-scheme"],
)
def test_unusable_azure_endpoint_shape_fails_during_startup(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    """AzureOpenAIClient appends its own path, so anything but a bare endpoint breaks.

    The resulting error surfaces inside complete(); a node that swallows it
    degrades silently while the invocation still reports status: success, so the
    adapter has to reject the shape at startup instead.
    """

    _set_valid_azure_environment(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", endpoint)

    with pytest.raises(ValueError, match="bare"):
        cli.MarketplaceGraph(config={}).provision_secrets(_UnusedProvider())


def test_default_azure_llm_is_wired_before_compile_and_invoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_azure_environment(monkeypatch)
    agent = _InspectableMarketplaceGraph(config=_runtime_config())
    assert vars(agent.config["llm"]) == {}
    agent.compile()
    wired = agent._nodes["main"]._config["llm"]
    assert wired is not None
    assert isinstance(wired, BaseLLM)

    agent.provision_secrets(_UnusedProvider())
    with bound_secrets(agent._secrets_provider):
        result = agent.invoke(_SAMPLE, ctx=_ctx())

    reason = result["_test_state"]["narrative_degradation_reason"]
    assert result["status"] == "success"
    assert reason != "llm_not_injected"
    assert reason.startswith("llm_failed:")


def test_explicit_null_llm_is_replaced_before_compile() -> None:
    config = _runtime_config()
    config["llm"] = None
    agent = cli.MarketplaceGraph(config=config)
    agent.compile()

    wired = agent._nodes["main"]._config["llm"]
    assert wired is not None
    assert isinstance(wired, BaseLLM)


def test_default_azure_llm_reaches_connection_without_bound_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_azure_environment(monkeypatch)
    agent = _InspectableMarketplaceGraph(config=_runtime_config())
    agent.compile()
    agent.provision_secrets(_UnusedProvider())

    result = agent.invoke(_SAMPLE, ctx=_ctx())

    reason = result["_test_state"]["narrative_degradation_reason"]
    assert result["status"] == "success"
    assert reason.startswith("llm_failed:")
    assert reason != "llm_failed:MissingSecret"


def test_caller_supplied_llm_is_preserved_and_used() -> None:
    counting_fake = _CountingLLM()
    agent = _InspectableMarketplaceGraph(config={"llm": counting_fake})
    agent.compile()

    assert agent._nodes["main"]._config["llm"] is counting_fake
    result = agent.invoke(_SAMPLE, ctx=_ctx())

    assert counting_fake.calls >= 1
    assert result["_test_state"]["narrative_source"] == "llm"


def test_runner_order_succeeds_without_conversation_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_azure_environment(monkeypatch)
    counting_fake = _CountingLLM()
    config = _runtime_config()
    config["llm"] = counting_fake
    agent = _InspectableMarketplaceGraph(config=config)
    agent.compile()
    agent.provision_secrets(_UnusedProvider())

    result = agent.invoke(
        _SAMPLE,
        ctx=_ctx(),
        input_context={"conversation_history": [{"role": "user", "content": "CANARY"}]},
    )

    assert result["status"] == "success"
    assert result["output"]
    assert "CANARY" not in json.dumps(result, ensure_ascii=False)
    assert counting_fake.calls == 1
    assert result["_test_state"]["narrative_source"] == "llm"
    assert result["_test_state"]["narrative_degradation_reason"] == ""


def test_invoke_disables_hitl(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_invoke(self, user_input, session_id="", ctx=None, input_context=None):
        del self, user_input, session_id, input_context
        captured["ctx"] = ctx
        return {"status": "success", "output": "ok"}

    monkeypatch.setattr(AgentAuditReportAgent, "invoke", fake_invoke)
    agent = cli.MarketplaceGraph(config={})
    original = _ctx()
    agent.invoke(_SAMPLE, ctx=original)

    assert original.hitl_allowed is True
    assert captured["ctx"].hitl_allowed is False


def test_cli_module_importable_by_path() -> None:
    spec = importlib.util.spec_from_file_location("cli_import_test", _REPO_ROOT / "cli.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)

    assert module.MarketplaceGraph.__name__ == "MarketplaceGraph"
