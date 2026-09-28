"""AgentCore Platform v1.0 — PostProcessNode (ReportAssemble + S-3 + S-5) — CMN-C1-086."""

from __future__ import annotations

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.errors import SecurityViolationError
from shared.utils.audit_logger import emit_trace_event

from src.services.report_format import S5_DISCLAIMER, assemble_report, format_error_report


class PostProcessNode(FunctionNode):
    """ReportAssemble: build the Markdown report (S-5) and shape the caller result."""

    # S-1: enterprise audit logs require an authenticated caller.
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict) -> dict:
        # Defensive: on the framework error route this node is skipped (route()
        # sends error -> finalize), so the error is surfaced by pre_process. This
        # branch only fires if an error reaches post_process directly.
        if state.get("status") == AgentStatus.ERROR.value:
            errors = state.get("error_log", []) or []
            return {
                "formatted_output": format_error_report(errors),
                "result": {"ok": False, "error_log": errors, "disclaimer": S5_DISCLAIMER},
                "status": AgentStatus.ERROR.value,
            }

        metrics = state.get("audit_metrics", {}) or {}
        security_events = state.get("security_events", []) or []
        narrative = state.get("narrative_summary", "") or ""
        period = state.get("report_period", "") or ""
        # ナラティブの出所（main が決める）。監査レポートはそれ自体が証跡なので、
        # LLM 起草部分と決定論的集計部分をレポート本文と result の両方で区別する。
        narrative_source = state.get("narrative_source", "") or "deterministic"
        narrative_reason = state.get("narrative_degradation_reason", "") or ""
        narrative_pii_masked = bool(state.get("narrative_pii_masked", False))

        body = assemble_report(
            period, metrics, security_events, narrative,
            narrative_source=narrative_source,
            narrative_degradation_reason=narrative_reason,
            narrative_pii_masked=narrative_pii_masked,
        )
        report = f"{S5_DISCLAIMER}\n\n{body}"

        emit_trace_event(
            "audit_report_finalized",
            {"compliance_status": metrics.get("compliance_status"),
             "security_event_count": len(security_events),
             "narrative_source": narrative_source,
             "degradation_reason": narrative_reason,
             "narrative_pii_masked": narrative_pii_masked},
            state,
        )
        return {
            "report_markdown": report,
            "formatted_output": report,
            "result": {
                "ok": True,
                "report_markdown": report,
                "report_period": period,
                "audit_metrics": metrics,
                "security_events": security_events,
                "narrative_source": narrative_source,
                "narrative_degradation_reason": narrative_reason,
                "narrative_pii_masked": narrative_pii_masked,
            },
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_output(self, result: dict) -> dict:
        """S-3 preservation variant — NON-SUPPRESSIBLE security-event guarantee.

        Every security event present in the source MUST appear in the rendered
        report **as its own structured table row**. A bare substring check is
        insufficient: an attacker could strip the row yet leave the entry_id
        elsewhere (narrative, disclaimer) and pass. We therefore require the
        exact row prefix ``| {entry_id} | {kind} |`` that ``_assemble_report``
        emits for the security-event table — ``kind`` only appears in that
        table, so a sprinkled id alone cannot satisfy it. Fail closed on any
        missing row rather than emit a sanitized audit.
        """
        inner = result.get("result")
        if not isinstance(inner, dict):
            return result
        report = inner.get("report_markdown", "") or ""
        for ev in inner.get("security_events", []) or []:
            eid = ev.get("entry_id", "")
            kind = ev.get("kind", "")
            if eid and f"| {eid} | {kind} |" not in report:
                raise SecurityViolationError(
                    "PostProcessNode",
                    required=f"security event row '| {eid} | {kind} |' present in report (non-suppressible)",
                    actual="missing or tampered",
                )
        return result
