"""AgentCore Platform v1.0 — CMN-C1-086 State."""

# ADR-005: State must be a flat TypedDict — never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption. Extend AgentState with agent-specific fields only.
# Do NOT add credentials, secrets, or Pydantic models.

from __future__ import annotations

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Agent Activity Audit & Compliance Report Generator state.

    Shared fields (user_input, status, session_id, node_history, error_log,
    correlation_id, trace_id, hitl_*, etc.) are inherited from AgentState.
    """

    # ── pre_process (LogIngest) ──────────────────────────────────────────────
    validated_input: str        # sanitized activity-log payload (JSON text)
    report_period: str          # reporting window, e.g. "2026-06"
    parsed_logs: list           # [{timestamp, agent_id, agent_type, action, outcome,
                                #   trust_level, data_access, is_security_exception,
                                #   is_unauthorized, is_human_override}]

    # ── main (AuditAggregate + Narrative) ────────────────────────────────────
    audit_metrics: dict         # {action_counts_by_type, exception_summary,
                                #  override_events, data_access_log, compliance_status}
    security_events: list       # NON-SUPPRESSIBLE: security exceptions + unauthorized access
    narrative_summary: str      # narrative prose (optional; metrics are deterministic)
    narrative_source: str       # "llm" | "deterministic" — provenance of narrative_summary
    narrative_degradation_reason: str   # "" when the LLM narrative was adopted
    narrative_pii_masked: bool  # True when the S-3 hook masked PII in the narrative

    # ── post_process (ReportAssemble) ────────────────────────────────────────
    report_markdown: str        # assembled audit report
    result: dict                # final output returned to caller
