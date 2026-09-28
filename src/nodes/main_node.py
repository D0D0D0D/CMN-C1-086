"""AgentCore Platform v1.0 — MainNode (AuditAggregate + Narrative) — CMN-C1-086."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from framework.nodes.function_node import FunctionNode
from framework.security import detect_pii
from framework.security.pii_masking import mask_pii
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.services import audit_aggregator
from src.services.llm_client import synthesize_narrative


class MainNode(FunctionNode):
    """AuditAggregate: deterministic metrics + non-suppressible security events + LLM narrative.

    LLM は `config["llm"]` シームからのみ受け取る（`Graph.register_nodes()` が
    `config=self.config` で渡す）。未注入・失敗・空応答では決定論ナラティブへ縮退し
    `status=success` を維持する — **監査メトリクスと非抑制セキュリティイベントは
    `audit_aggregator` が決定論的に作り、LLM には一切依存しない**ため、縮退しても
    監査レポートは成立する。
    """

    # S-1: enterprise audit logs require an authenticated caller.
    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, *, config: Mapping[str, Any] | None = None) -> None:
        super().__init__()
        # 構築時に決まる静的 config のみ。実行ごとに変わる値は State で運ぶ（§9）。
        self._config: dict[str, Any] = dict(config or {})

    def execute(self, state: dict) -> dict:
        # pre→main is an unconditional edge; honor an upstream error (graceful pass-through).
        if state.get("status") == AgentStatus.ERROR.value:
            return {"status": AgentStatus.ERROR.value}

        parsed_logs = state.get("parsed_logs", []) or []

        metrics = audit_aggregator.aggregate(parsed_logs)
        security_events = audit_aggregator.extract_security_events(parsed_logs)

        emit_trace_event(
            "audit_metrics_aggregated",
            {"total_entries": metrics["total_entries"],
             "security_event_count": metrics["security_event_count"],
             "compliance_status": metrics["compliance_status"]},
            state,
        )

        # LLM 注入シーム: config["llm"]。クライアントは呼び出しごとに
        # このスコープで消費するだけで self にキャッシュしない（ノードインスタンスは
        # 全 invocation で共有されるので、self に載せると別の呼び出しへ漏れる）。
        narrative, source, reason, model = synthesize_narrative(
            metrics, llm=self._config.get("llm")
        )
        emit_trace_event(
            "narrative_synthesized",
            # model は canonical response の値。config の文字列は注入クライアントの
            # 選択を決めないので、それを載せると監査ログが実際と食い違う。
            {"chars": len(narrative), "narrative_source": source,
             "degradation_reason": reason, "model": model},
            state,
        )

        return {
            "audit_metrics": metrics,
            "security_events": security_events,
            "narrative_summary": narrative,
            "narrative_source": source,
            "narrative_degradation_reason": reason,
            "narrative_pii_masked": False,   # S-3 フックが確定させる（下記）
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_output(self, result: dict) -> dict:
        """S-3 拡張: **LLM が書いた散文**の PII をマスクする。

        framework 既定の S-2 が走査するのは `user_input` / `validated_input` /
        `llm_response` の 3 フィールドだけで、本テンプレートが LLM 本文を置く
        `narrative_summary` は対象外。S-3 既定は credential しか見ず PII を見ない。
        したがってモデルが生成・反射した個人情報は、ここでマスクしない限り
        State → レポート → 呼び出し元へそのまま出る。

        入力側は既に守られている: `user_input` は S-2 が `execute()` の前にマスク
        するので、`parsed_logs` 由来の集計値・レポート表はマスク済みの値から作られる。
        塞ぐ必要があるのは **LLM 由来の本文だけ**。

        値を書き換えるのはこのフックだけで、レンダリング（post_process）は後段なので
        「ゲートで変換した値」と「出力された本文」が乖離することはない。

        ⚠️ **残存ギャップ（Rule 6.4）**: `detect_pii` の `name_jp` が拾うのは
        氏名／名前／担当者ラベル＋区切りに続く漢字・カタカナ氏名まで（1.0.1 で実測）。
        **ラベルの無い裸の日本語氏名**（「担当の山田太郎が…」）は検出できない。
        本ノードが返すのは LLM が書いた日本語の散文なので、このギャップは実在する。
        ここでは substrate（`detect_pii`）を再利用するに留め、残存ギャップ向けの
        独自検出器は入れていない（既知の残件）。ラベル付きのケースは substrate が
        既に持っているので、自前実装すると検出ロジックが二重になる。
        """
        narrative = result.get("narrative_summary")
        if not isinstance(narrative, str) or not narrative:
            return result
        findings = detect_pii(narrative)
        if not findings:
            return result
        result["narrative_summary"] = mask_pii(narrative, findings)
        # マスクした事実を監査可能にする（AI の出力を書き換えたことを黙って隠さない）。
        result["narrative_pii_masked"] = True
        return result
