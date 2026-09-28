# Integration — full invoke chain (CMN-C1-086)
# Verifies the fixed 5-node backbone executes end-to-end against the framework
# and that the non-suppressible security events survive into the final report.

import json

import pytest

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.services.llm.base_llm import BaseLLM
from src.graph.graph import AgentAuditReportAgent


SAMPLE = json.dumps(
    {
        "period": "2026-06",
        "logs": [
            {"entry_id": "E1", "agent_type": "rag", "action": "query", "outcome": "success"},
            {"entry_id": "E2", "agent_type": "react", "action": "exfiltrate",
             "outcome": "blocked", "is_security_exception": True},
            {"entry_id": "E3", "agent_type": "react", "action": "tool_call",
             "outcome": "denied", "is_unauthorized": True},
        ],
    }
)


@pytest.fixture
def agent():
    a = AgentAuditReportAgent()
    a.compile()
    return a


def _ctx():
    return InvocationContext(
        session_id="test-invoke-1",
        caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
        caller_id="tester",
    )


def test_full_invoke_success(agent):
    out = agent.invoke(SAMPLE, ctx=_ctx())
    assert out.get("status") == "success"
    # node_history is a list of node-name strings. The strict equality is
    # intentional: it pins the fixed 5-node backbone order so an unintended
    # graph change (added/removed/reordered node) fails loudly. If the framework
    # legitimately changes the backbone, update this expectation deliberately.
    nodes = [n if isinstance(n, str) else n.get("node") for n in out.get("node_history", [])]
    assert nodes == ["InitializeNode", "PreProcessNode", "MainNode",
                     "PostProcessNode", "FinalizeNode"]


def test_non_suppressible_events_in_report(agent):
    out = agent.invoke(SAMPLE, ctx=_ctx())
    # get_output() projects formatted_output (the report markdown string)
    output = out.get("output")
    report = output if isinstance(output, str) else output.get("report_markdown", "")
    # both the security exception (E2) and unauthorized access (E3) must appear
    assert "E2" in report
    assert "E3" in report
    assert "セキュリティイベント" in report


def test_empty_input_graceful_error(agent):
    out = agent.invoke("", ctx=_ctx())
    # pre_process errors; chain still finalizes with an error result (no crash)
    assert out.get("status") == "error"
    # the root cause must be surfaced via the projected output, not swallowed
    output = out.get("output") or ""
    assert "エラー" in output
    assert "empty" in output  # pre_process error_log mentions the empty payload


# ── config["llm"] 注入シームが本番構築経路で main まで届くこと ────────────────
# 本番の構築は `AgentBaseGraph.__init__(self, config=None)` のみ（独自コンストラクタ
# 引数は持たない）。ここが切れていると `generation_mode: "llm"` を宣言していても
# 実 LLM に一度も到達しない — この統合テストがその配線そのものを見る。
class _RecordingBaseLLM(BaseLLM):
    def __init__(self, content: str = "監査所見: 権限昇格の試行に注意が必要である。") -> None:
        self.content = content
        self.calls: list = []

    def complete(self, messages: list) -> dict:
        self.calls.append(messages)
        return {"content": self.content, "model": "fake-model-1", "tool_calls": []}

    def stream(self, messages: list):
        yield self.content

    def bind_tools(self, tools: list) -> "_RecordingBaseLLM":
        return self


def _report_of(out) -> str:
    output = out.get("output")
    return output if isinstance(output, str) else (output or {}).get("report_markdown", "")


def test_config_llm_reaches_main_node_through_the_production_constructor():
    llm = _RecordingBaseLLM()
    a = AgentAuditReportAgent(config={"llm": llm})
    a.compile()
    out = a.invoke(SAMPLE, ctx=_ctx())

    assert out.get("status") == "success"
    assert llm.calls, "config['llm'] が main まで届いていない（シームが切れている）"
    report = _report_of(out)
    assert "監査所見: 権限昇格の試行に注意が必要である。" in report
    # 監査レポートは証跡なので、LLM 起草部分が読み手に分かること。
    assert "## サマリ（AI 起草）" in report
    assert "件数・対象・時刻などの数値は以下の集計表が正本" in report
    # 決定論の集計表は LLM の有無に関わらず同じ内容で出る。
    assert "| E2 | security_exception |" in report
    assert "| E3 | unauthorized_access |" in report


def test_without_llm_the_report_marks_the_summary_as_deterministic(agent):
    out = agent.invoke(SAMPLE, ctx=_ctx())
    report = _report_of(out)
    assert "## サマリ（決定論生成）" in report
    assert "本節は集計値から機械的に生成しています（LLM 未使用）" in report
    assert "本期間のエージェント活動は合計 3 件記録された。" in report


def test_llm_failure_degrades_to_deterministic_and_says_so_in_the_report():
    class _Boom(_RecordingBaseLLM):
        def complete(self, messages: list) -> dict:
            raise TimeoutError("upstream gateway timeout for tenant acme")

    a = AgentAuditReportAgent(config={"llm": _Boom()})
    a.compile()
    out = a.invoke(SAMPLE, ctx=_ctx())

    # 集計だけでレポートは成立するので、縮退しても success を維持する。
    assert out.get("status") == "success"
    report = _report_of(out)
    assert "## サマリ（決定論生成 — LLM 応答を採用せず: llm_failed:TimeoutError）" in report
    # 例外の型名のみ。プロバイダのメッセージは出さない。
    assert "acme" not in report
    assert "gateway timeout" not in report
    assert "| E2 | security_exception |" in report


# ── LLM 未注入時の出力を丸ごと固定する（既存挙動の非改変ガード） ─────────────────
# この期待値は **develop（78b16f7）の実出力**に、今回意図した差分だけを当てて作った
# （サマリ見出しの 1 行変更＋注記 1 行＋空行 1 行）。したがって「意図しない出力変化」は
# 部分文字列テストをすり抜けてもここで落ちる。
GOLDEN_INPUT = json.dumps({
    "period": "2026-06",
    "logs": [
        {"entry_id": "E1", "agent_type": "rag", "action": "query", "outcome": "success",
         "timestamp": "2026-06-01T10:00:00Z", "agent_id": "a1", "data_access": "kb/x"},
        {"entry_id": "E2", "agent_type": "react", "action": "exfiltrate", "outcome": "blocked",
         "is_security_exception": True, "timestamp": "2026-06-02T10:00:00Z", "agent_id": "a2"},
        {"entry_id": "E3", "agent_type": "react", "action": "tool_call", "outcome": "denied",
         "is_unauthorized": True, "timestamp": "2026-06-03T10:00:00Z", "agent_id": "a3"},
        {"entry_id": "E4", "agent_type": "rag", "action": "override", "outcome": "error",
         "is_human_override": True, "timestamp": "2026-06-04T10:00:00Z", "agent_id": "a1"},
    ],
}, ensure_ascii=False)

GOLDEN_REPORT = '> 📌 **ディスクレーマー**: 本レポートは AI による監査支援であり、人による正式な監査レビューや法的助言を代替するものではありません。最終的な判断は人が行ってください。\n\n# AI エージェント活動監査レポート — 2026-06\n\n- 総活動件数: **4**\n- コンプライアンスステータス: **attention_required**\n- セキュリティイベント件数: **2**\n\n## サマリ（決定論生成）\n> ℹ️ 本節は集計値から機械的に生成しています（LLM 未使用）。\n\n本期間のエージェント活動は合計 4 件記録された。例外・エラーは 2 件、human override は 1 件であった。セキュリティ例外・不正アクセス試行が 2 件検出されており、本レポート末尾に必須項目として全件記載している（抑制不可）。総合コンプライアンスステータス: attention_required。\n\n## agent type 別アクション数\n| agent_type | count |\n|---|---|\n| rag | 2 |\n| react | 2 |\n\n## 例外・エラーサマリ\n| outcome | count |\n|---|---|\n| denied | 1 |\n| error | 1 |\n\n## human override イベント\n| entry_id | agent_id | action | timestamp |\n|---|---|---|---|\n| E4 | a1 | override | 2026-06-04T10:00:00Z |\n\n## データアクセスログ\n| entry_id | agent_id | resource | timestamp |\n|---|---|---|---|\n| E1 | a1 | kb/x | 2026-06-01T10:00:00Z |\n\n## ⚠️ セキュリティイベント（必須記載・抑制不可）\n| entry_id | kind | agent_id | action | outcome | timestamp |\n|---|---|---|---|---|---|\n| E2 | security_exception | a2 | exfiltrate | blocked | 2026-06-02T10:00:00Z |\n| E3 | unauthorized_access | a3 | tool_call | denied | 2026-06-03T10:00:00Z |'


def test_report_without_llm_is_byte_identical_to_the_declared_baseline(agent):
    out = agent.invoke(GOLDEN_INPUT, ctx=_ctx())
    assert out.get("status") == "success"
    assert _report_of(out) == GOLDEN_REPORT


# ── LLM が生成した PII は呼び出し元に届かない（end-to-end） ────────────────────
def test_llm_generated_pii_does_not_reach_the_caller():
    llm = _RecordingBaseLLM("担当者 Taro Yamada（user@example.com）が対応した。")
    a = AgentAuditReportAgent(config={"llm": llm})
    a.compile()
    out = a.invoke(SAMPLE, ctx=_ctx())

    assert out.get("status") == "success"
    report = _report_of(out)
    assert "user@example.com" not in report
    assert "Taro Yamada" not in report
    assert "[MASKED]" in report
    assert "## サマリ（AI 起草）" in report


def test_pii_masking_is_visible_in_the_report_not_only_in_result():
    """`get_output()` は `formatted_output`（文字列）を返すので `result` のフラグは
    呼び出し元に届かない。AI 出力を書き換えた事実はレポート本文に出す。"""
    llm = _RecordingBaseLLM("担当者 Taro Yamada が対応した。")
    a = AgentAuditReportAgent(config={"llm": llm})
    a.compile()
    report = _report_of(a.invoke(SAMPLE, ctx=_ctx()))
    assert "個人情報を自動マスクしました" in report
    # 原文はどこにも保持していない。復元可能性を示唆する案内を出さない。
    assert "マスク前の原文は保持していません" in report
    assert "監査ログを参照" not in report


def test_clean_llm_narrative_carries_no_masking_notice():
    llm = _RecordingBaseLLM("権限昇格の試行に注意が必要である。")
    a = AgentAuditReportAgent(config={"llm": llm})
    a.compile()
    report = _report_of(a.invoke(SAMPLE, ctx=_ctx()))
    assert "個人情報を自動マスクしました" not in report
    assert "## サマリ（AI 起草）" in report
