"""Narrative-synthesis LLM seam (CMN-C1-086).

**注入シームは `config["llm"]` 一本**（`BaseLLM` — `complete(messages) -> dict`）。
`Graph.register_nodes()` が `self.config` を `MainNode` へ渡し、`MainNode.execute()` が
`self._config.get("llm")` をこのモジュールへ委ねる。テンプレは**モデル ID も具体
クライアントも持たない**（モデル選択はデプロイ側の判断）。

CMN-C1-086 のドメインプロトコル（`summarize(system, metrics) -> str`）と `BaseLLM` の
差は、このモジュール内の**アダプタ（`_complete_narrative`）が吸収する**。アダプタを
テスト側にだけ置くと本番にアダプタが無い状態になるため、必ず `src/` に置く。

## 監査 AG としての設計上の線引き

- **監査事実（件数・対象エージェント・イベント一覧・コンプライアンス判定）は
  `audit_aggregator` が決定論的に算出する。LLM には一切依存しない。**
- LLM が書くのは「サマリ」節の**所見の散文のみ**。数値の正本はレポート本文の集計表であり、
  その旨をレポートに明記する（`report_format.assemble_report`）。
- LLM 未注入 / 失敗 / 空応答 / credential 混入では**決定論ナラティブへ縮退**し、
  `status=success` を維持する。集計表と非抑制セキュリティイベント表だけで監査レポートは
  成立するため、縮退はレポートの価値を損なわない（縮退した事実はレポートに明示する）。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from framework.security import detect_credentials, detect_pii
from framework.security.pii_masking import mask_pii

try:  # 型の存在は wheel 変種に依存しうるので import 失敗を許容する（duck 判定へ落ちる）
    from shared.services.llm.base_llm import BaseLLM
except ImportError:  # pragma: no cover — registry wheel には存在する
    BaseLLM = None

# ナラティブの出所（レポート・監査イベント・result に載る）
SOURCE_LLM = "llm"
SOURCE_DETERMINISTIC = "deterministic"

# 縮退理由（例外の型名以外のプロバイダ由来文字列は載せない）
REASON_NOT_INJECTED = "llm_not_injected"
REASON_UNSUPPORTED = "llm_unsupported"
REASON_FAILED = "llm_failed"
REASON_EMPTY = "llm_empty"
REASON_UNSAFE = "llm_unsafe_content"
REASON_INPUT_UNSAFE = "input_unsafe_content"

# LLM へ渡すプロンプト view の上限。入力ログは最大 1MB（config.yaml max_log_bytes）
# 取りうるので、metrics をそのまま渡すとプロンプト長が入力サイズに比例して膨らむ。
PROMPT_SAMPLE_LIMIT = 20
PROMPT_MAX_CHARS = 8000
# 集計キー（agent_type / outcome）は活動ログ由来で長さ無制限。
PROMPT_KEY_MAX_CHARS = 64
# 監査イベントに載せるモデル名の上限（壊れたクライアントの巨大文字列を監査基盤へ流さない）。
MODEL_NAME_MAX_CHARS = 120

NARRATIVE_SYSTEM_PROMPT = (
    "You are an AI governance auditor. Write a concise, factual Japanese summary "
    "of the supplied audit metrics. Do not omit security events. "
    "件数は `..._count` フィールドの値をそのまま使ってください。`..._sample` は先頭数件の"
    "抜粋であり全件ではないので、そこから件数を数えないでください。"
    "数値の正本はレポート本文の集計表です。件数を数え直したり、与えられていない"
    "事実を補ったりしないでください。出力は本文のみ（見出し・前置き・後書きなし）、"
    "200〜400 字程度にまとめてください。"
)


def deterministic_narrative(metrics: dict) -> str:
    """集計値だけから機械的に組み立てるナラティブ（LLM 非依存・縮退時の本文）。

    数値は `metrics` からそのまま引く。文字列の生成に LLM を使わないので、
    レポート本文の集計表と必ず一致する。
    """
    total = sum((metrics.get("action_counts_by_type") or {}).values())
    exc = metrics.get("exception_summary") or {}
    exc_total = sum(exc.values()) if isinstance(exc, dict) else 0
    overrides = len(metrics.get("override_events") or [])
    sec = metrics.get("security_event_count", 0)
    status = metrics.get("compliance_status", "unknown")
    parts = [
        f"本期間のエージェント活動は合計 {total} 件記録された。",
        f"例外・エラーは {exc_total} 件、human override は {overrides} 件であった。",
    ]
    if sec > 0:
        parts.append(
            f"セキュリティ例外・不正アクセス試行が {sec} 件検出されており、"
            "本レポート末尾に必須項目として全件記載している（抑制不可）。"
        )
    else:
        parts.append("対象期間にセキュリティ例外・不正アクセス試行は検出されなかった。")
    parts.append(f"総合コンプライアンスステータス: {status}。")
    return "".join(parts)


def _top_n(counts: dict, limit: int) -> dict:
    """件数辞書を上位 `limit` 件に畳む（agent_type / outcome はユーザー入力由来で無制限）。"""
    if not isinstance(counts, dict):
        return {}
    ordered = sorted(counts.items(), key=lambda kv: (-int(kv[1] or 0), str(kv[0])))
    # キーは活動ログ由来（`agent_type` / `outcome`）で長さに上限が無い。件数だけ畳んでも
    # 1 キー 20,000 字ならプロンプトは膨らむので、キー長も切り詰める。
    # 🔴 単純な前方一致の切り詰めは **別区分を同じキーへ潰す**（後勝ちで件数が消え、
    # LLM に渡す内訳が合計と矛盾する）。切り詰めたキーには元キーのダイジェストを付けて
    # 区別を保つ。
    return {_shorten_key(str(k)): v for k, v in ordered[:limit]}


# 切り詰めたキーの目印。**入力キーがこの文字を含む場合も切り詰め対象**にする —
# `_shorten_key(K)` をそのまま別のキーとして投入されると、素の実装では
# `f(K) == f(f(K))` の確定的な衝突が作れてしまう（短いので再加工されないため）。
_SHORTENED_MARK = "…"
_KEY_DIGEST_CHARS = 16


def _shorten_key(key: str) -> str:
    if len(key) <= PROMPT_KEY_MAX_CHARS and _SHORTENED_MARK not in key:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:_KEY_DIGEST_CHARS]
    head = PROMPT_KEY_MAX_CHARS - _KEY_DIGEST_CHARS - len(_SHORTENED_MARK)
    return f"{key[:head]}{_SHORTENED_MARK}{digest}"


def build_narrative_payload(metrics: dict) -> dict:
    """LLM へ渡す view を組む。

    2 つの目的がある（どちらも実 LLM 1 回転の実測で必要と判明した）:

    1. **件数はこちら側で数えて渡す。** `override_events` を生リストのまま渡すと
       モデルは件数を自分で数えて散文に書く（実測: 「3 件記録され」）。監査の件数は
       ログから決定論的に出すべき値なので、`*_count` として与え、モデルには
       数えさせない。抜粋であることも明示する（黙って切ると抜粋から件数を数える）。
    2. **プロンプト長を入力サイズから切り離す。** `data_access_log` は 1 エントリ 1 行
       増えるので、1MB の活動ログでは metrics をそのまま渡すと巨大な prompt になる。
    """
    exc = metrics.get("exception_summary") or {}
    overrides = list(metrics.get("override_events") or [])
    access = list(metrics.get("data_access_log") or [])
    action_counts = metrics.get("action_counts_by_type") or {}

    payload: dict[str, Any] = {
        "total_entries": metrics.get("total_entries", 0),
        "compliance_status": metrics.get("compliance_status", "unknown"),
        "security_event_count": metrics.get("security_event_count", 0),
        "action_type_count": len(action_counts) if isinstance(action_counts, dict) else 0,
        "action_counts_by_type": _top_n(action_counts, PROMPT_SAMPLE_LIMIT),
        "exception_total": sum(exc.values()) if isinstance(exc, dict) else 0,
        "exception_summary": _top_n(exc, PROMPT_SAMPLE_LIMIT),
        "override_event_count": len(overrides),
        "override_event_sample": overrides[:PROMPT_SAMPLE_LIMIT],
        "data_access_count": len(access),
        "data_access_sample": access[:PROMPT_SAMPLE_LIMIT],
        "samples_are_excerpts": True,
    }
    if len(json.dumps(payload, ensure_ascii=False)) > PROMPT_MAX_CHARS:
        # 1 エントリが極端に長い場合は件数だけを残す（縮退ではなく prompt の切り詰め）。
        payload["override_event_sample"] = []
        payload["data_access_sample"] = []
        payload["samples_omitted"] = True
    if len(json.dumps(payload, ensure_ascii=False)) > PROMPT_MAX_CHARS:
        # それでも超えるのは集計キー自体が巨大なとき。内訳を落として件数だけ残す。
        payload["action_counts_by_type"] = {}
        payload["exception_summary"] = {}
        payload["breakdowns_omitted"] = True
    return payload


def _messages_from_payload(payload: dict) -> list[dict]:
    return [
        {"role": "system", "content": NARRATIVE_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, sort_keys=True)},
    ]


def build_narrative_messages(metrics: dict) -> list[dict]:
    """ナラティブ生成プロンプトを組む（`src/` に置く — テスト側に置かない）。"""
    return _messages_from_payload(build_narrative_payload(metrics))


def extract_content(response: Any) -> str:
    """`BaseLLM.complete()` の canonical response から assistant テキストを取り出す。

    `{"content": None}` を `str()` にかけると文字列 `"None"` が本文として利用者に
    返るので、None は空文字へ正規化する（空応答は success にしない — 呼び出し側で
    縮退させる）。
    """
    if isinstance(response, dict):
        return str(response.get("content") or "").strip()
    return str(response or "").strip()


def extract_model(response: Any) -> str:
    """canonical response の `model` を返す。

    監査イベントに載せるモデル名は**注入されたクライアントが実際に使ったモデル**で
    なければならない。config の文字列は注入クライアントの選択を決めないので、
    それを報告すると監査ログが実際と食い違う。
    """
    if isinstance(response, dict):
        return str(response.get("model") or "")
    return ""


def sanitize_model_name(model: str) -> str:
    """監査イベントに載せる前にモデル名を健全化する。

    モデル名は注入クライアント（テンプレート外のコード）が返す値であり、
    `MainNode` の返り値には含めない＝S-3 の credential スキャンを通らないまま
    監査基盤へ出る。壊れた / 悪意あるクライアントの応答メタデータから資格情報が
    監査ログへ流れないよう、ここで検査・切り詰めする。
    """
    if not model:
        return ""
    if detect_credentials(model):
        return "[REDACTED]"
    # credential と同じ理由で PII も落とす（監査基盤へ出る値であり S-3 を通らない）。
    findings = detect_pii(model)
    if findings:
        model = mask_pii(model, findings)
    return model[:MODEL_NAME_MAX_CHARS]


def _is_usable_client(llm: Any) -> bool:
    """注入されたオブジェクトを LLM クライアントとして使ってよいか。

    🔴 **型が取れるなら isinstance が唯一の判定**。duck typing を先に（あるいは
    並列に）置いてはいけない — SDK 実クライアント（`AnthropicClient` 等）は
    `__getattr__` で内部 LangChain クライアントへ委譲するので、属性の有無を見る
    判定は「持っていないメソッド」まで真になり、バッチ用の別シグネチャを掴む。

    duck 判定は **`BaseLLM` 型を import できない wheel 変種でだけ**使うフォール
    バックであり、そのときも `type(llm)` を見る（インスタンス側 `getattr` は
    上記の委譲に釣られる）。

    `BaseLLM` は ABC で `complete` が abstractmethod なので、
    `isinstance(x, BaseLLM)` が真なら `type(x)` は必ず `complete` を持つ
    （実測: 未実装のサブクラスは `TypeError` で構築できない）。
    """
    if BaseLLM is not None:
        return isinstance(llm, BaseLLM)
    return callable(getattr(type(llm), "complete", None))


def synthesize_narrative(
    metrics: dict, llm: Any | None = None
) -> tuple[str, str, str, str]:
    """ナラティブを合成する。戻り値は `(text, source, reason, model)`。

    **ノードのインスタンスに状態を持たせない**ため、出所・縮退理由・モデル名はすべて
    戻り値で運ぶ（ノードは全 invocation で共有されるので、self に載せると漏れる）。

    - `llm is None`            -> 決定論（CI / 未プロビジョニング）reason=`llm_not_injected`
    - `BaseLLM` でない（型が無い wheel では `complete` を持たない）
      -> 決定論 reason=`llm_unsupported:<型名>`
    - `complete()` が送出       -> 決定論 reason=`llm_failed:<例外型名>`
      （`str(exc)` は依頼文の反射や資格情報を含みうるので State に入れない）
    - プロンプトに credential  -> **送信せず**決定論 reason=`input_unsafe_content:<種別>`
      （S-3 は `complete()` の後にしか効かないので、プロバイダへの egress を
      止められるのは送信前のここだけ）
    - 応答が空                  -> 決定論 reason=`llm_empty`
    - 応答に credential パターン -> 決定論 reason=`llm_unsafe_content:<種別>`
      framework の S-3 は credential を検出すると `RuntimeError` を送出し、
      **その execute() の返り値ごと捨てられて監査レポート全体が失われる**。
      生成元ノードの `execute()` 内で落とすのが正しい（S-3 に届く前に処理する）。
    """
    if llm is None:
        return deterministic_narrative(metrics), SOURCE_DETERMINISTIC, REASON_NOT_INJECTED, ""

    if not _is_usable_client(llm):
        return (
            deterministic_narrative(metrics),
            SOURCE_DETERMINISTIC,
            f"{REASON_UNSUPPORTED}:{type(llm).__name__}",
            "",
        )

    # 🔴 送信前の egress ゲート。プロンプトには活動ログ由来の文字列
    # （agent_id / resource / timestamp）が載る。S-2 は PII しかマスクせず
    # credential を見ない。S-3 は `complete()` の**後**なので、監査対象ログに
    # 混入した鍵がプロバイダへ出るのを止められるのはここだけ。
    messages = build_narrative_messages(metrics)
    # 🔴 検査対象は **実際にプロバイダへ出る文字列そのもの**。`detect_credentials_in_value()`
    # は dict の「値」しか走査しないため、`agent_type` / `outcome` のように入力由来の値が
    # **キー**になる payload では素通りする。直列化後の本文を見れば経路に依らず捕まる。
    input_findings = detect_credentials("\n".join(str(m.get("content", "")) for m in messages))
    if input_findings:
        return (
            deterministic_narrative(metrics),
            SOURCE_DETERMINISTIC,
            f"{REASON_INPUT_UNSAFE}:{input_findings[0]['type']}",
            "",
        )

    try:
        response = llm.complete(messages)
        # 応答の取り出しも try の内側に置く。契約違反クライアントの `__str__` が
        # 送出したとき、外側だと framework が `str(exc)` と traceback を State と
        # 監査イベントへ入れてしまう（縮退の保証が崩れる）。
        content = extract_content(response)
        model = sanitize_model_name(extract_model(response))
    except Exception as exc:  # noqa: BLE001 — ナラティブ失敗で監査レポートを止めない
        return (
            deterministic_narrative(metrics),
            SOURCE_DETERMINISTIC,
            f"{REASON_FAILED}:{type(exc).__name__}",
            "",
        )

    if not content:
        return deterministic_narrative(metrics), SOURCE_DETERMINISTIC, REASON_EMPTY, model

    findings = detect_credentials(content)
    if findings:
        return (
            deterministic_narrative(metrics),
            SOURCE_DETERMINISTIC,
            f"{REASON_UNSAFE}:{findings[0]['type']}",
            model,
        )

    return content, SOURCE_LLM, "", model
