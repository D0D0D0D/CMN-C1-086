"""実 LLM 1 回転検証のための共有 fixture。

CMN-C1-086 の LLM シームは**`config["llm"]`（`BaseLLM`）**。
`Graph.register_nodes()` が `config` を `MainNode` に渡し、`src/services/llm_client.py`
の `synthesize_narrative()` が `BaseLLM.complete()` を叩く。アダプタは `src/` 側に
あるので、ここに `live_llm_injector` は要らない（ハーネスが `config["llm"]` を
埋めるだけで実 LLM に到達する）。

`case_payload` は **この AG の本来の入力**（実運用に近い活動ログ）を置く。
汎用ペイロードでは出ない欠陥（サマリが集計表と食い違う・非抑制イベントが埋もれる等）を
実 LLM 1 回転で出すのが目的なので、override / data_access / 複数種の例外 /
セキュリティイベント混在の多件数ログにしてある。
"""

from __future__ import annotations

import pytest


@pytest.fixture
def agent_config() -> dict:
    # ハーネスは config/config.yaml を基底にし、この値を上に重ね、
    # さらに config["llm"] を埋める。追加の構築依存は無い。
    return {}


def _live_activity_log() -> dict:
    """実運用に近い 1 か月分の活動ログ（32 件）。

    - agent_type 4 種・outcome 4 種
    - human override 3 件 / data_access 12 件
    - セキュリティイベント 4 件（security_exception 2 / unauthorized 2）
      → compliance_status は attention_required になる
    """
    logs: list[dict] = []

    def add(**kw):
        logs.append(kw)

    # 通常の RAG 問い合わせ（data_access あり）
    for i in range(1, 11):
        add(entry_id=f"E{i:03d}", timestamp=f"2026-06-{i:02d}T09:15:00+09:00",
            agent_id=f"rag-agent-{(i % 3) + 1}", agent_type="rag",
            action="knowledge_query", outcome="success",
            trust_level="VERIFIED_EXTERNAL",
            data_access=f"kb/finance/quarterly_report_{i:02d}")
    # 文書生成（一部失敗）
    for i in range(11, 19):
        add(entry_id=f"E{i:03d}", timestamp=f"2026-06-{i:02d}T13:40:00+09:00",
            agent_id="docgen-agent-1", agent_type="docgen",
            action="generate_document",
            outcome="success" if i % 4 else "error",
            trust_level="VERIFIED_EXTERNAL",
            data_access="kb/templates/audit_form" if i % 2 else "")
    # ツール実行（denied / exception 混在）
    add(entry_id="E019", timestamp="2026-06-19T02:05:00+09:00", agent_id="react-agent-2",
        agent_type="react", action="external_api_call", outcome="exception",
        trust_level="VERIFIED_EXTERNAL")
    add(entry_id="E020", timestamp="2026-06-20T02:07:00+09:00", agent_id="react-agent-2",
        agent_type="react", action="external_api_call", outcome="failure",
        trust_level="VERIFIED_EXTERNAL")
    # human override（人による差し戻し）
    for n, day in enumerate(("21", "22", "23"), start=21):
        add(entry_id=f"E{n:03d}", timestamp=f"2026-06-{day}T10:00:00+09:00",
            agent_id="rag-agent-1", agent_type="rag", action="human_override_apply",
            outcome="success", trust_level="INTERNAL", is_human_override=True,
            data_access="kb/finance/override_ledger")
    # 監査対象外の軽量アクション
    for i in range(24, 29):
        add(entry_id=f"E{i:03d}", timestamp=f"2026-06-{i:02d}T18:30:00+09:00",
            agent_id="chat-agent-1", agent_type="chat", action="chat_turn",
            outcome="success", trust_level="VERIFIED_EXTERNAL")
    # ── セキュリティイベント（非抑制・必ずレポートに全件出る） ──────────────
    add(entry_id="E029", timestamp="2026-06-27T03:12:00+09:00", agent_id="react-agent-9",
        agent_type="react", action="bulk_export_customer_table", outcome="blocked",
        trust_level="ANONYMOUS", is_security_exception=True,
        data_access="db/customers")
    add(entry_id="E030", timestamp="2026-06-27T03:14:00+09:00", agent_id="react-agent-9",
        agent_type="react", action="credential_store_read", outcome="denied",
        trust_level="ANONYMOUS", is_unauthorized=True, data_access="vault/secrets")
    add(entry_id="E031", timestamp="2026-06-28T23:58:00+09:00", agent_id="docgen-agent-7",
        agent_type="docgen", action="write_outside_workspace", outcome="blocked",
        trust_level="VERIFIED_EXTERNAL", is_security_exception=True)
    add(entry_id="E032", timestamp="2026-06-29T04:01:00+09:00", agent_id="unknown-agent",
        agent_type="react", action="admin_endpoint_probe", outcome="denied",
        trust_level="ANONYMOUS", is_unauthorized=True)
    return {"period": "2026-06", "logs": logs}


@pytest.fixture
def case_payload() -> dict:
    return _live_activity_log()


@pytest.fixture
def live_input_context() -> dict:
    # happy path は input_context 無しで invoke する。
    return {}
