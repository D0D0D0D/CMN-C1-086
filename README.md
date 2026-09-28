# CMN-C1-086 — Agent Activity Audit & Compliance Report Generator

> **Category**: Cat 1 (single technical capability)
> **Industry**: CMN

## Overview

Agent Activity Audit & Compliance Report Generator turns a structured JSON activity log — the
record of what a group of AI agents did over a period — into a standardized Markdown audit
report, ready for review or downstream PDF rendering. It counts actions by agent type, summarises
exceptions and errors, lists human overrides and data-access events, and derives an overall
compliance status.

It suits work where the log already exists and now has to be made reviewable: an operator
assembling a monthly governance report, a compliance reviewer checking whether any security
exception or unauthorized-access attempt occurred in a window, or a team that wants human
overrides and data access laid out per period rather than grepped out of raw logs.

The division of labour between the language model and the deterministic layer is the point of the
design. Every audit *fact* — the counts, the event list, the compliance status — is computed from
the log without the model. The model writes one thing only: the prose of the summary section.

- **Security events are non-suppressible.** Entries flagged `is_security_exception` or
  `is_unauthorized` are extracted deterministically and must appear in the rendered report as
  their own table rows. The output gate re-checks the rendered Markdown for each row and raises
  rather than emit a report from which an inconvenient event has gone missing. A bare
  substring check would not do — an id sprinkled into the narrative would satisfy it — so the
  exact row prefix is what is verified.
- **The narrative is optional and never load-bearing.** With no language model injected, or when
  the call fails, returns nothing, or returns something unsafe, the agent falls back to a
  deterministic summary and still succeeds. The report says which of the two it used, and why, so
  a degraded run is visible rather than silent.
- **The report states where its numbers come from.** The summary heading distinguishes
  *AI-drafted* from *deterministically generated*, and the body records that the aggregate tables
  — not the prose — are the authoritative figures.

The agent supports audit preparation. It does not perform the audit: it does not replace human
review, does not give legal advice, and does not determine regulatory compliance.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Integration

Provide:

- an AgentCore runtime;
- caller authentication in front of the entry adapter — every node requires verified-external
  trust, and the standalone server rejects an unauthenticated caller outright;
- optionally, a `BaseLLM` implementation injected through `config["llm"]`. No provider client is
  bundled and no model is named in the agent itself. Without one, the summary section is generated
  deterministically and the run still returns `status=success`; the aggregate tables and the
  security-event table do not depend on a model at all.

Runtime parameters read from `config/config.yaml` (defaults in parentheses). Unknown keys are
rejected at start-up rather than ignored:

| Key | Meaning |
|---|---|
| `max_retry` (`3`) | Framework retry budget for the pipeline |
| `max_log_bytes` (`1048576`) | Hard cap on the activity-log payload, enforced by the input gate before parsing |
| `memory_enabled` (`false`) | Whether a checkpointer is attached. Left false, no state is persisted between invocations |
| `hitl.enabled` (`false`) | Human-in-the-loop. Not used by this template; `hitl.enabled: true` additionally requires `memory_enabled: true` |

The template does not collect logs, connect to a logging backend, watch a live stream, compare
periods, or render PDF. Input is one JSON payload per invocation.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent is built for the platform and connects to it at start-up. Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Supplied by the platform's own package registry at build time. It is not published on public PyPI, so `pip install -e .` alone does not fetch it. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The agent does not fall back to a degraded mode when the framework is missing: `src/api/server.py`
imports `framework.*` and `shared.*` at module scope and builds the graph at import time, so
without the AgentCore package the process fails to start. With the framework installed but no
platform around it, the standalone server does start and answers `/health` — but it injects no
language model, so a successful invocation returns the deterministic summary rather than an
AI-drafted one, and it configures no caller authentication, so `/invoke` answers **401** until
`INVOKE_AUTH_TOKEN` is set or verifying middleware is placed in front. The test suite runs
without a platform connection.

## Input

`POST /invoke` takes a JSON body with `input` and an optional `session_id`. The activity log goes
in `input` **as a JSON string** — either a JSON array of entries, or an object
`{"period": "...", "logs": [...]}`.

Callers must be authenticated. The entry adapter reads a trust level stamped by upstream
middleware if one is present; otherwise, when `INVOKE_AUTH_TOKEN` is set on the server
environment, a matching `Authorization: Bearer` header promotes the caller to `VERIFIED_EXTERNAL`
(a mismatched token is **401**). A caller that is neither middleware-verified nor
token-authenticated is rejected with **401** — there is no anonymous path into the graph, and
every node requires `VERIFIED_EXTERNAL` regardless.

```bash
curl -X POST http://127.0.0.1:8000/invoke \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${INVOKE_AUTH_TOKEN}" \
  --data @- <<'JSON'
{
  "input": "{\"period\":\"2026-06\",\"logs\":[{\"entry_id\":\"E1\",\"agent_type\":\"rag\",\"action\":\"query\",\"outcome\":\"success\"},{\"entry_id\":\"E2\",\"agent_type\":\"react\",\"action\":\"exfiltrate\",\"outcome\":\"blocked\",\"is_security_exception\":true},{\"entry_id\":\"E3\",\"agent_type\":\"react\",\"action\":\"tool_call\",\"outcome\":\"denied\",\"is_unauthorized\":true}]}",
  "session_id": "audit-demo-001"
}
JSON
```

Each entry is normalised, and a missing field takes a documented default rather than failing the
whole payload: `entry_id` (falls back to `id`, then a positional `E0000` form), `timestamp`,
`agent_id` / `agent_type` / `action` / `outcome` / `trust_level` (default `"unknown"`),
`data_access`, and the three booleans `is_security_exception`, `is_unauthorized`,
`is_human_override`.

The reporting period is taken from the payload's `period`; failing that, from the first entry's
timestamp truncated to `YYYY-MM`; failing that, `"unspecified"`. A caller invoking the graph
directly may override it with `input_context.report_period` — the HTTP body has no field for it.

Input fails closed. An empty payload, malformed JSON, a payload that is neither an array nor a
`{period, logs}` object, or one with no entries, ends as `status=error` with the reason in the
returned report. A payload over `max_log_bytes`, or one containing a known prompt-injection
marker, is rejected by the input gate before parsing — the marker scan lowercases and collapses
whitespace first, so case-mixing and newline padding do not evade it.

## Output

The standard AgentCore envelope is returned: `status`, `output`, `node_history`, `trace_id` and
`correlation_id`. `output` is the finished Markdown report — the S-5 disclaimer, then the header
block (period, total entries, compliance status, security-event count), the summary section, the
per-agent-type action table, the exception summary, human-override events, the data-access log,
and last the security-event table.

The structured view of the same run — the metrics dict, the extracted security events, the
narrative provenance and the masking flag — is assembled into `result` in state alongside the
Markdown. Note that the standard envelope projects the report string, so a caller that needs the
structured form reads it from state rather than from the HTTP response.

`compliance_status` takes one of three values, in this precedence: `attention_required` (at least
one security exception or unauthorized-access entry), `review` (no security event but at least
one error/exception/failure/denied outcome), `compliant` (neither).

```markdown
> 📌 **ディスクレーマー**: ...

# AI エージェント活動監査レポート — 2026-06

- 総活動件数: **2**
- コンプライアンスステータス: **attention_required**
- セキュリティイベント件数: **1**

## サマリ（決定論生成）
> ℹ️ 本節は集計値から機械的に生成しています（LLM 未使用）。
...

## ⚠️ セキュリティイベント（必須記載・抑制不可）
| entry_id | kind | agent_id | action | outcome | timestamp |
|---|---|---|---|---|---|
| E2 | security_exception | unknown | exfiltrate | blocked |  |
```

The report is written in Japanese. Values above are illustrative; real output depends on the log
supplied.

## Security and Limitations

Every node requires verified-external trust, so an anonymous caller is stopped before any node
body runs. On the way in, the payload is size-capped and screened for prompt-injection markers.
On the way out, two independent gates apply: the security-event preservation check described
above, and a PII mask over the model-written prose. The framework's own input scan covers the
standard input fields, and its output scan looks for credentials, not personal information — so
the model-authored narrative is masked by the agent itself, and the fact that a mask was applied
is recorded in the report rather than hidden.

Before any prompt is sent, the payload built for the model is scanned for credential patterns; if
one is found the request is not sent at all and the run degrades to the deterministic summary.
This is the only place egress can be stopped, because the framework's output gate runs after the
provider call, not before it.

Degradation reasons are recorded, and they name a category, never provider text: `llm_not_injected`,
`llm_unsupported:<type>`, `llm_failed:<exception type>`, `input_unsafe_content:<kind>`,
`llm_empty`, `llm_unsafe_content:<kind>`. Provider exception messages are never written to state
or to the report — a rejection message can echo the request back.

Known limits, recorded rather than open:

- **A credential inside the log values stops the whole run.** Activity-log values are rendered
  into the report tables, so a credential pattern in them trips the framework's output scan and
  the invocation ends as `status=error` with no report. That is deliberate: publishing a key
  inside an audit report is worse than refusing to produce one.
- **Personal-name masking is partial for Japanese prose.** The framework detector matches a name
  that follows an explicit label (氏名 / 名前 / 担当者) plus a separator; a bare name in running
  text is not detected. The agent reuses the framework detector rather than adding a second,
  divergent one, so this gap is inherited and documented rather than papered over.
- **Compliance status is a mechanical rule over flags in the log, not a judgement.** It is only as
  good as the flags the log carries; the agent does not infer that an action was a security event
  from its description.
- **Timestamps are used as strings.** The period is derived by truncating the first entry's
  timestamp, so a log whose first entry is out of order, or whose timestamps are in mixed formats,
  can produce a period the operator must set explicitly.

Output is machine-generated and assistive. It does not substitute for a formal audit, and any
decision that matters should be made against the primary records by a person.

## Release

- Version: 1.0.0
- Category: single technical capability (Cat 1), document-generation pattern
- Generation mode: `llm` — the narrative section only; every audit figure is deterministic
- HITL: not enabled
- Persistence: none — no checkpointer is configured
- Secrets: none required by the agent; the entry adapter reads `INVOKE_AUTH_TOKEN` from the
  environment when caller-token authentication is in use
- External API clients: deployment-injected; none bundled in the agent

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection and without a language model, using fakes. Running the
agent itself does not: a bare `uvicorn src.api.server:app` starts, but answers `/invoke` with 401
until caller authentication is configured, and injects no model — so a successful run there
returns the deterministic summary by design.

## Documentation

`docs/02_design.md` carries the node flow, the state schema, the security-layer mapping and the
design decision record. `docs/03_test_spec.md` records the test specification and results.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and test specifications
```

See `docs/02_design.md` for the design and `docs/03_test_spec.md` for the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
