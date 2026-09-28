"""Audit log aggregation service (CMN-C1-086).

Pure, deterministic domain logic — no business routing, no credentials, no
framework imports. Nodes call this; it never calls back into nodes. This is the
core capability of the Cat 1 template: turn raw agent activity logs into
standardized audit metrics + the NON-SUPPRESSIBLE security-event list.
"""

from __future__ import annotations

import json
from typing import Any

# Canonical field names accepted on each activity-log entry. Unknown fields are
# ignored; missing fields default to safe values.
_TRUTHY = (True, "true", "True", 1, "1", "yes")


def _as_bool(v: Any) -> bool:
    return v in _TRUTHY


def parse_logs(raw: str) -> tuple[list[dict], str]:
    """Parse the raw activity-log payload into (entries, report_period).

    Accepts either a JSON array of entries, or an envelope object
    ``{"period": "2026-06", "logs": [...]}``. Raises ValueError on malformed
    input or when no log entries are present.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as e:
        raise ValueError(f"activity log payload is not valid JSON: {e}") from e

    period = ""
    if isinstance(data, dict):
        period = str(data.get("period", "") or "")
        entries = data.get("logs", data.get("entries", []))
    elif isinstance(data, list):
        entries = data
    else:
        raise ValueError("activity log payload must be a JSON array or {period, logs} object")

    if not isinstance(entries, list) or not entries:
        raise ValueError("activity log payload contains no log entries")

    normalized: list[dict] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise ValueError(f"log entry #{i} is not an object")
        normalized.append(
            {
                "entry_id": str(e.get("entry_id", e.get("id", f"E{i:04d}"))),
                "timestamp": str(e.get("timestamp", "")),
                "agent_id": str(e.get("agent_id", "unknown")),
                "agent_type": str(e.get("agent_type", "unknown")),
                "action": str(e.get("action", "unknown")),
                "outcome": str(e.get("outcome", "unknown")),
                "trust_level": str(e.get("trust_level", "unknown")),
                "data_access": str(e.get("data_access", "")),
                "is_security_exception": _as_bool(e.get("is_security_exception", False)),
                "is_unauthorized": _as_bool(e.get("is_unauthorized", False)),
                "is_human_override": _as_bool(e.get("is_human_override", False)),
            }
        )

    if not period and normalized:
        # derive period from the first parseable timestamp (YYYY-MM)
        ts = normalized[0]["timestamp"]
        period = ts[:7] if len(ts) >= 7 else "unspecified"

    return normalized, period


def extract_security_events(parsed_logs: list[dict]) -> list[dict]:
    """NON-SUPPRESSIBLE: every security exception OR unauthorized-access entry.

    These entries MUST always appear in the final report; the post_process S-3
    preservation gate verifies their presence (defense in depth).
    """
    events = []
    for e in parsed_logs:
        if e["is_security_exception"] or e["is_unauthorized"]:
            kind = "security_exception" if e["is_security_exception"] else "unauthorized_access"
            events.append(
                {
                    "entry_id": e["entry_id"],
                    "kind": kind,
                    "timestamp": e["timestamp"],
                    "agent_id": e["agent_id"],
                    "agent_type": e["agent_type"],
                    "action": e["action"],
                    "outcome": e["outcome"],
                }
            )
    return events


def aggregate(parsed_logs: list[dict]) -> dict:
    """Aggregate audit metrics from normalized log entries (deterministic)."""
    action_counts: dict[str, int] = {}
    exception_summary: dict[str, int] = {}
    override_events: list[dict] = []
    data_access_log: list[dict] = []

    for e in parsed_logs:
        action_counts[e["agent_type"]] = action_counts.get(e["agent_type"], 0) + 1
        outcome = e["outcome"].lower()
        if outcome in ("error", "exception", "failure", "denied"):
            exception_summary[e["outcome"]] = exception_summary.get(e["outcome"], 0) + 1
        if e["is_human_override"]:
            override_events.append(
                {"entry_id": e["entry_id"], "agent_id": e["agent_id"],
                 "action": e["action"], "timestamp": e["timestamp"]}
            )
        if e["data_access"]:
            data_access_log.append(
                {"entry_id": e["entry_id"], "agent_id": e["agent_id"],
                 "resource": e["data_access"], "timestamp": e["timestamp"]}
            )

    security_count = sum(
        1 for e in parsed_logs if e["is_security_exception"] or e["is_unauthorized"]
    )
    # Compliance status: any security event => "attention_required"; else any
    # exception => "review"; else "compliant".
    if security_count > 0:
        compliance_status = "attention_required"
    elif exception_summary:
        compliance_status = "review"
    else:
        compliance_status = "compliant"

    return {
        "total_entries": len(parsed_logs),
        "action_counts_by_type": action_counts,
        "exception_summary": exception_summary,
        "override_events": override_events,
        "data_access_log": data_access_log,
        "security_event_count": security_count,
        "compliance_status": compliance_status,
    }
