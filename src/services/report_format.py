"""Audit report formatting (CMN-C1-086).

Pure rendering helpers shared by the nodes. Kept separate from the nodes so the
S-5 disclaimer and the report layout have a single source of truth, and so the
error path (detected in pre_process, which runs before post_process and skips it
on the framework error route) can surface a disclaimer-prefixed error report too.
"""

from __future__ import annotations

# S-5 disclaimer — prepended to every report (success and error). Technical
# self-check aid; does NOT replace formal human review or constitute legal advice.
S5_DISCLAIMER = (
    "> 📌 **ディスクレーマー**: 本レポートは AI による監査支援であり、人による正式な"
    "監査レビューや法的助言を代替するものではありません。最終的な判断は人が行ってください。"
)


def format_error_report(errors: list) -> str:
    """Disclaimer-prefixed error report surfaced when ingestion/validation fails."""
    body = "\n".join(f"- {e}" for e in (errors or [])) or "- 不明なエラー"
    return f"{S5_DISCLAIMER}\n\n# 監査レポート生成エラー\n\nレポートを生成できませんでした。原因:\n{body}"


# ナラティブ節の出所ラベル。監査レポートはそれ自体が証跡になるため、**LLM が起草した
# 散文と決定論的に集計した数値を読み手が区別できる**ようにする。数値の正本は常に
# 集計表であり、その旨も本文に書く（LLM に件数を数え直させない設計の明示）。
_NARRATIVE_NOTE_LLM = (
    "> ℹ️ 本節は AI が起草した所見です。**件数・対象・時刻などの数値は以下の集計表が正本**であり、"
    "本節の記述と食い違う場合は集計表を採用してください。"
)
_NARRATIVE_NOTE_DETERMINISTIC = (
    "> ℹ️ 本節は集計値から機械的に生成しています（LLM 未使用）。"
)
# AI の出力を書き換えた事実は読み手に見える形で残す。`result` に載せるだけでは
# `get_output()` が `formatted_output`（文字列）を優先するため呼び出し元に届かない。
# 原文は**どこにも保持していない**（保持したらマスクの意味が無い）。監査ログにも残らないので、
# 「監査ログを参照」のような復元可能性を示唆する案内を書かない — 監査担当者が存在しない
# 証跡を探すことになる。
_NARRATIVE_NOTE_PII_MASKED = (
    "> ⚠️ 本節に含まれていた個人情報を自動マスクしました（`[MASKED]`）。"
    "マスク前の原文は保持していません。"
)


def narrative_heading(source: str, degradation_reason: str = "") -> str:
    """サマリ節の見出し（出所を明示する）。

    - `llm`           -> 「サマリ（AI 起草）」
    - `deterministic` -> 「サマリ（決定論生成）」。LLM を試みて採用しなかった場合は
      その理由コードも添える（未注入の既定運用と、実行時に失敗した状態を区別する）。
    """
    if source == "llm":
        return "## サマリ（AI 起草）"
    reason = (degradation_reason or "").strip()
    if reason and reason != "llm_not_injected":
        return f"## サマリ（決定論生成 — LLM 応答を採用せず: {reason}）"
    return "## サマリ（決定論生成）"


def assemble_report(
    period: str,
    metrics: dict,
    security_events: list,
    narrative: str,
    narrative_source: str = "deterministic",
    narrative_degradation_reason: str = "",
    narrative_pii_masked: bool = False,
) -> str:
    """Assemble the full Markdown audit report. Security events are ALWAYS rendered."""
    lines: list[str] = []
    lines.append(f"# AI エージェント活動監査レポート — {period or '期間未指定'}")
    lines.append("")
    lines.append(f"- 総活動件数: **{metrics.get('total_entries', 0)}**")
    lines.append(f"- コンプライアンスステータス: **{metrics.get('compliance_status', 'unknown')}**")
    lines.append(f"- セキュリティイベント件数: **{metrics.get('security_event_count', 0)}**")
    lines.append("")
    if narrative:
        lines.append(narrative_heading(narrative_source, narrative_degradation_reason))
        lines.append(
            _NARRATIVE_NOTE_LLM if narrative_source == "llm" else _NARRATIVE_NOTE_DETERMINISTIC
        )
        if narrative_pii_masked:
            lines.append(_NARRATIVE_NOTE_PII_MASKED)
        lines.append("")
        lines.append(narrative)
        lines.append("")

    lines.append("## agent type 別アクション数")
    lines.append("| agent_type | count |")
    lines.append("|---|---|")
    for atype, cnt in sorted((metrics.get("action_counts_by_type") or {}).items()):
        lines.append(f"| {atype} | {cnt} |")
    lines.append("")

    lines.append("## 例外・エラーサマリ")
    exc = metrics.get("exception_summary") or {}
    if exc:
        lines.append("| outcome | count |")
        lines.append("|---|---|")
        for k, v in sorted(exc.items()):
            lines.append(f"| {k} | {v} |")
    else:
        lines.append("例外・エラーは記録されていません。")
    lines.append("")

    lines.append("## human override イベント")
    overrides = metrics.get("override_events") or []
    if overrides:
        lines.append("| entry_id | agent_id | action | timestamp |")
        lines.append("|---|---|---|---|")
        for o in overrides:
            lines.append(f"| {o['entry_id']} | {o['agent_id']} | {o['action']} | {o['timestamp']} |")
    else:
        lines.append("human override イベントはありません。")
    lines.append("")

    lines.append("## データアクセスログ")
    dal = metrics.get("data_access_log") or []
    if dal:
        lines.append("| entry_id | agent_id | resource | timestamp |")
        lines.append("|---|---|---|---|")
        for d in dal:
            lines.append(f"| {d['entry_id']} | {d['agent_id']} | {d['resource']} | {d['timestamp']} |")
    else:
        lines.append("データアクセスイベントはありません。")
    lines.append("")

    # NON-SUPPRESSIBLE section — security exceptions + unauthorized access.
    # Always rendered; the post_process S-3 preservation gate verifies every
    # event row '| {entry_id} | {kind} |' is present.
    lines.append("## ⚠️ セキュリティイベント（必須記載・抑制不可）")
    if security_events:
        lines.append("| entry_id | kind | agent_id | action | outcome | timestamp |")
        lines.append("|---|---|---|---|---|---|")
        for s in security_events:
            lines.append(
                f"| {s['entry_id']} | {s['kind']} | {s['agent_id']} | "
                f"{s['action']} | {s['outcome']} | {s['timestamp']} |"
            )
    else:
        lines.append("対象期間にセキュリティ例外・不正アクセス試行は検出されませんでした。")
    return "\n".join(lines)
