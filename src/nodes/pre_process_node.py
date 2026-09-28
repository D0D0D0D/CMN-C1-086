"""AgentCore Platform v1.0 — PreProcessNode (LogIngest + S-2) — CMN-C1-086."""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - S-2 domain checks go in _extra_security_gate_input (NEVER override
#    _security_gate_input — @final, TypeError at class definition)

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.errors import SecurityViolationError
from shared.utils.audit_logger import emit_trace_event

from src.services import audit_aggregator
from src.services.report_format import format_error_report

# 1MB hard input cap (decoupled from any LLM context window). Mirrors
# config/config.yaml max_log_bytes (moved there by the AgentRegistry manifest
# migration because the manifest is static-only).
MAX_LOG_BYTES = 1024 * 1024

_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "disregard previous",
    "you are now",
    "system prompt",
)

# Whitespace is collapsed before matching so newline/tab/multi-space evasions
# (legal inside JSON strings) cannot bypass the marker scan.
_WS = re.compile(r"\s+")


def _normalize(text: str) -> str:
    # .lower() is intentional: it defends against case-mixing evasions
    # ("IGNORE Previous Instructions") in addition to the whitespace collapse,
    # so the marker list can stay lowercase.
    return _WS.sub(" ", text.lower())


class PreProcessNode(FunctionNode):
    """LogIngest: parse + validate the activity-log payload, derive the period."""

    # S-1: enterprise audit logs require an authenticated caller.
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, *, config: Mapping[str, Any] | None = None) -> None:
        super().__init__()
        values = config or {}
        self._max_log_bytes = int(values.get("max_log_bytes", MAX_LOG_BYTES))

    @property
    def max_log_bytes(self) -> int:
        """Configured input cap, exposed for operational verification."""

        return self._max_log_bytes

    @staticmethod
    def _error(errors: list) -> dict:
        # post_process is skipped on the error route (route() -> finalize), so we
        # surface the disclaimer-prefixed error here via formatted_output.
        return {
            "status": AgentStatus.ERROR.value,
            "error_log": errors,
            "formatted_output": format_error_report(errors),
        }

    def execute(self, state: dict) -> dict:
        user_input = state.get("user_input", "") or ""
        if not user_input.strip():
            return self._error(["PreProcessNode: activity log payload (user_input) is empty"])

        try:
            parsed_logs, period = audit_aggregator.parse_logs(user_input)
        except ValueError as e:
            return self._error([f"PreProcessNode: {e}"])

        input_context = state.get("input_context", {}) or {}
        period = str(input_context.get("report_period", "") or "") or period

        emit_trace_event(
            "activity_logs_ingested",
            {"entry_count": len(parsed_logs), "report_period": period,
             "size_bytes": len(user_input.encode("utf-8"))},
            state,
        )
        return {
            "validated_input": user_input.strip(),
            "parsed_logs": parsed_logs,
            "report_period": period,
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_input(self, state: AgentState) -> AgentState:
        """S-2: input size cap + prompt-injection screening on the payload."""
        text = state.get("user_input", "") or ""
        size = len(text.encode("utf-8"))
        if size > self._max_log_bytes:
            raise SecurityViolationError(
                "PreProcessNode",
                required=f"<= {self._max_log_bytes} bytes",
                actual=f"{size} bytes",
            )
        normalized = _normalize(text)  # collapse whitespace to defeat newline/tab evasions
        for marker in _INJECTION_MARKERS:
            if marker in normalized:
                raise SecurityViolationError(
                    "PreProcessNode", required="no prompt-injection markers", actual=marker
                )
        return state
