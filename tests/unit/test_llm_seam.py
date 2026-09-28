"""CMN-C1-086 — LLM 注入シーム（config["llm"]）と縮退の契約。

期待値はすべてリテラルで書く（production の定数・関数から計算しない — 自己参照 oracle
だと実装を壊しても一緒に動いてテストが赤くならない）。
"""

from __future__ import annotations


import pytest
from shared.services.llm.base_llm import BaseLLM

from src.services.llm_client import (
    build_narrative_messages,
    build_narrative_payload,
    extract_content,
    extract_model,
    synthesize_narrative,
)

# 決定論ナラティブの期待本文（リテラル固定 — production の関数から計算しない）。
DETERMINISTIC_TEXT = (
    "本期間のエージェント活動は合計 5 件記録された。"
    "例外・エラーは 2 件、human override は 1 件であった。"
    "セキュリティ例外・不正アクセス試行が 2 件検出されており、"
    "本レポート末尾に必須項目として全件記載している（抑制不可）。"
    "総合コンプライアンスステータス: attention_required。"
)

METRICS = {
    "total_entries": 5,
    "action_counts_by_type": {"rag": 2, "react": 2, "docgen": 1},
    "exception_summary": {"error": 1, "denied": 1},
    "override_events": [{"entry_id": "E4", "agent_id": "a1", "action": "override",
                         "timestamp": "2026-06-02T12:00:00Z"}],
    "data_access_log": [],
    "security_event_count": 2,
    "compliance_status": "attention_required",
}


class _FakeBaseLLM(BaseLLM):
    """BaseLLM を実際に継承した double（本番クライアントと同じ判定経路を通る）。"""

    def __init__(self, response) -> None:
        self.response = response
        self.calls: list = []

    def complete(self, messages: list) -> dict:
        self.calls.append(messages)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def stream(self, messages: list):
        yield ""

    def bind_tools(self, tools: list) -> "_FakeBaseLLM":
        return self


class _DuckClient:
    """BaseLLM を継承しないが `complete()` をクラスに持つ double。"""

    def __init__(self, response) -> None:
        self.response = response

    def complete(self, messages):
        return self.response


class _DelegatingProxy:
    """`__getattr__` で何でも返すオブジェクト（SDK 実クライアントの委譲と同型）。

    クラスに `complete` を持たないので、シームは「使えないクライアント」として
    **縮退**しなければならない（getattr ベースの duck 判定だと真になってしまう）。
    """

    def __getattr__(self, name):  # pragma: no cover - 呼ばれたら設計違反
        return lambda *a, **k: {"content": "delegated", "model": "proxy"}


# ── 注入されていない（CI / 未プロビジョニング） ─────────────────────────────
def test_no_llm_falls_back_to_deterministic():
    text, source, reason, model = synthesize_narrative(METRICS, llm=None)
    assert source == "deterministic"
    assert reason == "llm_not_injected"
    assert model == ""
    assert text == DETERMINISTIC_TEXT


# ── 正常系 ────────────────────────────────────────────────────────────────
def test_base_llm_narrative_is_adopted_with_canonical_model():
    llm = _FakeBaseLLM({"content": "  監査所見の本文  ", "model": "gpt-test-1"})
    text, source, reason, model = synthesize_narrative(METRICS, llm=llm)
    assert text == "監査所見の本文"
    assert source == "llm"
    assert reason == ""
    # モデル名は canonical response から。config の文字列ではない。
    assert model == "gpt-test-1"
    assert len(llm.calls) == 1


# ── 型が取れるなら isinstance が唯一の判定 ────────────────────────────────
def test_non_base_llm_object_is_rejected_even_though_it_has_complete():
    """duck typing は BaseLLM 型が使える限り**採用しない**（fail-visible に縮退）。"""
    text, source, reason, _ = synthesize_narrative(
        METRICS, llm=_DuckClient({"content": "duck 経路の所見", "model": "m"})
    )
    assert source == "deterministic"
    assert reason == "llm_unsupported:_DuckClient"
    assert "duck 経路の所見" not in text
    assert text == DETERMINISTIC_TEXT


def test_duck_fallback_is_used_only_when_the_base_llm_type_is_unavailable(monkeypatch):
    """`BaseLLM` を import できない wheel 変種でだけ duck 判定に落ちる。"""
    import src.services.llm_client as seam

    monkeypatch.setattr(seam, "BaseLLM", None)
    text, source, _, _ = synthesize_narrative(
        METRICS, llm=_DuckClient({"content": "duck 経路の所見", "model": "m"})
    )
    assert text == "duck 経路の所見"
    assert source == "llm"

    # フォールバックでもインスタンス側 getattr には釣られない。
    _, source2, reason2, _ = synthesize_narrative(METRICS, llm=_DelegatingProxy())
    assert source2 == "deterministic"
    assert reason2 == "llm_unsupported:_DelegatingProxy"


# ── __getattr__ 委譲に釣られない ──────────────────────────────────────────
def test_getattr_delegating_object_degrades_instead_of_being_treated_as_llm():
    text, source, reason, _ = synthesize_narrative(METRICS, llm=_DelegatingProxy())
    assert source == "deterministic"
    assert reason == "llm_unsupported:_DelegatingProxy"
    assert text == DETERMINISTIC_TEXT
    assert "delegated" not in text


def test_plain_object_without_complete_degrades():
    _, source, reason, _ = synthesize_narrative(METRICS, llm=object())
    assert source == "deterministic"
    assert reason == "llm_unsupported:object"


# ── 縮退 ──────────────────────────────────────────────────────────────────
def test_provider_exception_degrades_with_type_name_only():
    secret = "api key sk-liveAAAAAAAAAAAAAAAAAAAAAAAA rejected for tenant acme"
    llm = _FakeBaseLLM(TimeoutError(secret))
    text, source, reason, _ = synthesize_narrative(METRICS, llm=llm)
    assert source == "deterministic"
    assert reason == "llm_failed:TimeoutError"
    # プロバイダのメッセージ（依頼文の反射・資格情報を含みうる）は State に載せない。
    assert secret not in reason
    assert "acme" not in reason
    assert text == DETERMINISTIC_TEXT


@pytest.mark.parametrize("response", [
    {"content": None, "model": "m"},
    {"content": "", "model": "m"},
    {"content": "   \n ", "model": "m"},
])
def test_empty_response_degrades_and_never_yields_the_string_none(response):
    text, source, reason, model = synthesize_narrative(METRICS, llm=_FakeBaseLLM(response))
    assert source == "deterministic"
    assert reason == "llm_empty"
    assert model == "m"
    assert text == DETERMINISTIC_TEXT
    assert text != "None"
    assert "None" not in text


def test_credential_shaped_narrative_degrades_before_the_s3_gate_sees_it():
    # AKIA + 16 大文字英数 = framework の credential detector が拾う形。
    # ここで落とさないと S-3 が RuntimeError を投げ、監査レポートごと失われる。
    poisoned = "調査中に AKIAIOSFODNN7EXAMPLE を検出した。"
    text, source, reason, _ = synthesize_narrative(METRICS, llm=_FakeBaseLLM(
        {"content": poisoned, "model": "m"}))
    assert source == "deterministic"
    assert reason == "llm_unsafe_content:aws_key"
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert text == DETERMINISTIC_TEXT


# ── プロンプト契約 ────────────────────────────────────────────────────────
def test_prompt_tells_the_model_not_to_recount_the_numbers():
    messages = build_narrative_messages(METRICS)
    assert [m["role"] for m in messages] == ["system", "user"]
    system = messages[0]["content"]
    assert "数値の正本はレポート本文の集計表です" in system
    assert "件数を数え直したり" in system
    # 抜粋から件数を数えさせない指示（黙って切ると抜粋の長さを件数として書く）。
    assert "`..._count` フィールドの値をそのまま使ってください" in system
    assert "抜粋であり全件ではないので、そこから件数を数えないでください" in system


def test_payload_supplies_every_count_so_the_model_never_counts():
    """実 LLM は生リストを渡すと件数を自分で数えて散文に書く（実測）。

    監査の件数は決定論的に出すべき値なので、payload 側で数えて渡す。
    """
    payload = build_narrative_payload(METRICS)
    assert payload["total_entries"] == 5
    assert payload["security_event_count"] == 2
    assert payload["override_event_count"] == 1     # override_events は 1 件
    assert payload["exception_total"] == 2          # error 1 + denied 1
    assert payload["data_access_count"] == 0
    assert payload["action_type_count"] == 3
    assert payload["samples_are_excerpts"] is True
    # 生リストをそのまま入れない（件数フィールドと対で抜粋を渡す）。
    assert "override_events" not in payload
    assert "data_access_log" not in payload


def test_payload_is_bounded_regardless_of_input_size():
    """入力ログは最大 1MB。metrics を素通しするとプロンプトが入力サイズに比例する。"""
    big = {
        "total_entries": 5000,
        "action_counts_by_type": {f"type-{i}": 5000 - i for i in range(300)},
        "exception_summary": {f"outcome-{i}": i for i in range(300)},
        "override_events": [{"entry_id": f"O{i}", "agent_id": "a", "action": "x",
                             "timestamp": "2026-06-01T00:00:00Z"} for i in range(2000)],
        "data_access_log": [{"entry_id": f"D{i}", "agent_id": "a", "resource": "r" * 40,
                             "timestamp": "2026-06-01T00:00:00Z"} for i in range(2000)],
        "security_event_count": 7,
        "compliance_status": "attention_required",
    }
    payload = build_narrative_payload(big)
    # 件数は正確に、サンプルは 20 件まで。
    assert payload["override_event_count"] == 2000
    assert payload["data_access_count"] == 2000
    assert payload["action_type_count"] == 300
    assert len(payload["override_event_sample"]) <= 20
    assert len(payload["data_access_sample"]) <= 20
    assert len(payload["action_counts_by_type"]) == 20
    assert len(payload["exception_summary"]) == 20
    user_message = build_narrative_messages(big)[1]["content"]
    assert len(user_message) <= 8000, f"prompt が上限を超えた: {len(user_message)} 字"


def test_oversized_single_entries_drop_the_samples_but_keep_the_counts():
    huge = {
        "total_entries": 3,
        "action_counts_by_type": {"rag": 3},
        "exception_summary": {},
        "override_events": [],
        "data_access_log": [{"entry_id": "D1", "agent_id": "a",
                             "resource": "x" * 9000, "timestamp": "t"}],
        "security_event_count": 0,
        "compliance_status": "compliant",
    }
    payload = build_narrative_payload(huge)
    assert payload["data_access_count"] == 1
    assert payload["data_access_sample"] == []
    assert payload["samples_omitted"] is True
    assert len(build_narrative_messages(huge)[1]["content"]) <= 8000


# ── canonical response の取り出し ─────────────────────────────────────────
def test_extract_content_normalises_none_to_empty_string():
    assert extract_content({"content": None}) == ""
    assert extract_content({"content": " a "}) == "a"
    assert extract_content(None) == ""


def test_extract_model_returns_empty_when_absent():
    assert extract_model({"content": "x"}) == ""
    assert extract_model({"content": "x", "model": "m-1"}) == "m-1"
    assert extract_model("not a dict") == ""


# ── MainNode の S-4 ドメインイベント（TC-05 / PB-1） ──────────────────────────
def _audit_events(monkeypatch, llm):
    """MainNode.execute() が出すドメインイベントを捕まえる。

    `main_node` は `from shared.utils.audit_logger import emit_trace_event` で
    **自前の binding** を持つので、定義元モジュールではなくノードモジュール側を差し替える。
    """
    import src.nodes.main_node as main_node_module
    from src.nodes.main_node import MainNode

    captured: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        main_node_module, "emit_trace_event",
        lambda event_type, payload, _state, _c=captured: _c.append((event_type, payload)),
    )
    node = MainNode(config={"llm": llm} if llm is not None else {})
    result = node.execute({
        "status": "success",
        "parsed_logs": [
            {"entry_id": "E1", "timestamp": "2026-06-01T00:00:00Z", "agent_id": "a1",
             "agent_type": "rag", "action": "query", "outcome": "success",
             "trust_level": "VERIFIED_EXTERNAL", "data_access": "",
             "is_security_exception": False, "is_unauthorized": False,
             "is_human_override": False},
        ],
    })
    return captured, result


def test_main_node_emits_narrative_provenance_in_the_audit_trail(monkeypatch):
    llm = _FakeBaseLLM({"content": "所見", "model": "audited-model-9"})
    events, result = _audit_events(monkeypatch, llm)

    names = [e for e, _ in events]
    assert names == ["audit_metrics_aggregated", "narrative_synthesized"]
    payload = dict(events[1][1])
    assert payload["narrative_source"] == "llm"
    assert payload["degradation_reason"] == ""
    # モデル名は canonical response の値（config の文字列ではない）。
    assert payload["model"] == "audited-model-9"
    assert result["narrative_source"] == "llm"
    assert result["narrative_degradation_reason"] == ""


def test_main_node_audit_trail_records_the_degradation_reason(monkeypatch):
    events, result = _audit_events(monkeypatch, None)
    payload = dict(events[1][1])
    assert payload["narrative_source"] == "deterministic"
    assert payload["degradation_reason"] == "llm_not_injected"
    assert result["narrative_source"] == "deterministic"
    assert result["narrative_degradation_reason"] == "llm_not_injected"


def test_sample_slice_bounds_the_payload_even_when_the_char_cap_does_not():
    """抜粋の件数上限は「サイズ上限に達しない中規模入力」でだけ効く独立の防御。

    全件を積んでも 8,000 字に収まる大きさ（= サイズ上限のフォールバックが発火しない）で
    確かめないと、上限を外しても「フォールバックが空にするので通る」ことになる。
    """
    mid = {
        "total_entries": 50,
        "action_counts_by_type": {"rag": 50},
        "exception_summary": {},
        "override_events": [{"entry_id": f"O{i}", "agent_id": "a",
                             "action": "o", "timestamp": "t"} for i in range(50)],
        "data_access_log": [],
        "security_event_count": 0,
        "compliance_status": "compliant",
    }
    payload = build_narrative_payload(mid)
    assert "samples_omitted" not in payload, "この入力ではサイズ上限は発火しないはず"
    assert payload["override_event_count"] == 50
    assert len(payload["override_event_sample"]) == 20


# ── 送信前の egress ゲート（S-3 は complete() の後にしか効かない） ─────────────
def test_credential_in_the_activity_log_is_never_sent_to_the_provider():
    """監査対象ログに混入した鍵をプロバイダへ出さない。

    S-2 は PII しかマスクせず credential を見ない。S-3 は `complete()` の後なので
    egress を止められない。止められるのは送信前のこの検査だけ。
    """
    poisoned_metrics = dict(METRICS)
    poisoned_metrics["data_access_log"] = [
        {"entry_id": "D1", "agent_id": "a1", "timestamp": "t",
         "resource": "s3://bucket?token=AKIAIOSFODNN7EXAMPLE"},
    ]
    llm = _FakeBaseLLM({"content": "所見", "model": "m"})
    text, source, reason, _ = synthesize_narrative(poisoned_metrics, llm=llm)

    assert llm.calls == [], "credential を含むプロンプトをプロバイダへ送ってしまっている"
    assert source == "deterministic"
    assert reason == "input_unsafe_content:aws_key"
    assert text == DETERMINISTIC_TEXT


# ── モデル名の健全化（S-3 を通らない経路） ────────────────────────────────────
def test_model_name_from_a_broken_client_is_sanitised_before_the_audit_log():
    """`model` は MainNode の返り値に入らない＝S-3 の credential スキャンを通らない。"""
    llm = _FakeBaseLLM({"content": "所見", "model": "AKIAIOSFODNN7EXAMPLE"})
    _, source, _, model = synthesize_narrative(METRICS, llm=llm)
    assert source == "llm"
    assert model == "[REDACTED]"


def test_absurdly_long_model_name_is_truncated():
    llm = _FakeBaseLLM({"content": "所見", "model": "m" * 5000})
    _, _, _, model = synthesize_narrative(METRICS, llm=llm)
    assert len(model) == 120


# ── 応答処理の例外も縮退させる（try の内側） ──────────────────────────────────
def test_exception_while_reading_the_response_also_degrades():
    """契約違反クライアントの `__str__` が送出しても success を保つ。

    ここを try の外に出すと framework が `str(exc)` と traceback を State と
    監査イベントへ入れてしまう。
    """
    class _ExplodingContent:
        def __str__(self):
            raise ValueError("secret in the message: tenant acme")

    llm = _FakeBaseLLM({"content": _ExplodingContent(), "model": "m"})
    text, source, reason, model = synthesize_narrative(METRICS, llm=llm)
    assert source == "deterministic"
    assert reason == "llm_failed:ValueError"
    assert "acme" not in reason
    assert model == ""
    assert text == DETERMINISTIC_TEXT


# ── 集計キーが巨大でもプロンプトは頭打ち ──────────────────────────────────────
def test_enormous_breakdown_keys_cannot_blow_up_the_prompt():
    """`agent_type` / `outcome` は活動ログ由来で長さ無制限。"""
    metrics = {
        "total_entries": 3,
        "action_counts_by_type": {"x" * 20000: 3},
        "exception_summary": {"y" * 20000: 1},
        "override_events": [],
        "data_access_log": [],
        "security_event_count": 0,
        "compliance_status": "compliant",
    }
    payload = build_narrative_payload(metrics)
    assert payload["total_entries"] == 3
    assert payload["action_type_count"] == 1
    assert len(build_narrative_messages(metrics)[1]["content"]) <= 8000
    # キーを切り詰めることで**内訳を落とさずに**収める。内訳ごと捨てる 2 段目の
    # フォールバック（`breakdowns_omitted`）はここでは発火してはいけない。
    assert "breakdowns_omitted" not in payload
    for key in list(payload["action_counts_by_type"]) + list(payload["exception_summary"]):
        assert len(key) == 64


def test_keys_sharing_a_long_prefix_do_not_collapse_into_one_bucket():
    """前方一致で切り詰めると別区分が同じキーへ潰れ、内訳が合計と矛盾する。

    LLM に渡す決定論的集計が自己矛盾すると、誤った監査所見の材料になる。
    """
    prefix = "agent-" + "z" * 80
    metrics = {
        "total_entries": 9,
        "action_counts_by_type": {f"{prefix}-alpha": 4, f"{prefix}-beta": 5},
        "exception_summary": {},
        "override_events": [],
        "data_access_log": [],
        "security_event_count": 0,
        "compliance_status": "compliant",
    }
    payload = build_narrative_payload(metrics)
    breakdown = payload["action_counts_by_type"]
    assert payload["action_type_count"] == 2
    assert len(breakdown) == 2, f"別区分が 1 つに潰れた: {breakdown}"
    assert sum(breakdown.values()) == 9
    for key in breakdown:
        assert len(key) <= 64


# ── LLM が生成した PII は S-3 フックでマスクする ──────────────────────────────
def test_llm_generated_pii_is_masked_by_the_node_s3_hook():
    """S-2 は `narrative_summary` を走査せず、S-3 既定は PII を見ない。

    したがってモデルが書いた個人情報は、ノードのフックでマスクしない限り
    State → レポート → 呼び出し元へそのまま出る。
    """
    from src.nodes.main_node import MainNode

    node = MainNode()
    masked = node._extra_security_gate_output({
        "narrative_summary": "担当は Taro Yamada（user@example.com）である。",
        "narrative_pii_masked": False,
    })
    assert "user@example.com" not in masked["narrative_summary"]
    assert "Taro Yamada" not in masked["narrative_summary"]
    assert "[MASKED]" in masked["narrative_summary"]
    assert masked["narrative_pii_masked"] is True


def test_clean_narrative_is_left_untouched_and_not_flagged():
    from src.nodes.main_node import MainNode

    clean = "本期間の活動は合計 5 件で、コンプライアンスステータスは attention_required。"
    out = MainNode()._extra_security_gate_output({
        "narrative_summary": clean, "narrative_pii_masked": False,
    })
    assert out["narrative_summary"] == clean
    assert out["narrative_pii_masked"] is False


def test_credential_in_a_breakdown_key_is_also_blocked_before_egress():
    """`agent_type` / `outcome` は入力由来の値が **辞書キー**になる経路。

    framework の `detect_credentials_in_value()` は dict の値しか走査しないため、
    payload を構造として検査すると素通りする。実際に送る文字列を検査すること。
    """
    metrics = dict(METRICS)
    metrics["action_counts_by_type"] = {"AKIAIOSFODNN7EXAMPLE": 3}
    llm = _FakeBaseLLM({"content": "所見", "model": "m"})
    text, source, reason, _ = synthesize_narrative(metrics, llm=llm)

    assert llm.calls == [], "credential をキーに持つプロンプトを送ってしまっている"
    assert source == "deterministic"
    assert reason == "input_unsafe_content:aws_key"
    # 決定論本文は集計値から組むだけなので credential を含まない。
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "本期間のエージェント活動は合計 3 件記録された。" in text


def test_pii_in_a_broken_clients_model_name_is_masked_before_the_audit_log():
    llm = _FakeBaseLLM({"content": "所見", "model": "Taro Yamada user@example.com"})
    _, source, _, model = synthesize_narrative(METRICS, llm=llm)
    assert source == "llm"
    assert "user@example.com" not in model
    assert "Taro Yamada" not in model
    assert "[MASKED]" in model


def test_masking_over_triggers_on_title_case_english_and_that_is_accepted():
    """既知のトレードオフ（意図的にこの挙動を選んでいる）。

    framework の氏名検出は Latin script の Title Case 2 語を人名扱いするので、
    AI が「Human Override」のような技術用語を英語 Title Case で書くとマスクされる。
    誤マスクは可読性を落とすが、**未マスクの個人情報が監査レポートに残るより安全**で、
    数値・対象・時刻の正本は決定論的な集計表側にあるので監査の情報量は失われない。
    語句の allowlist を持つと検出器との追いかけっこになるため採らない。
    """
    from src.nodes.main_node import MainNode

    out = MainNode()._extra_security_gate_output({
        "narrative_summary": "Human Override が 3 件記録された。",
        "narrative_pii_masked": False,
    })
    assert out["narrative_summary"] == "[MASKED] が 3 件記録された。"
    assert out["narrative_pii_masked"] is True


def test_a_key_that_already_looks_shortened_cannot_collide_with_its_source():
    """`_shorten_key(K)` をそのまま別キーとして投入する確定的衝突を塞ぐ。

    目印を含むキーは短くても再加工するので `f(K) != f(f(K))` になる。
    """
    from src.services.llm_client import _shorten_key

    long_key = "agent-" + "z" * 200
    once = _shorten_key(long_key)
    twice = _shorten_key(once)
    assert len(once) <= 64 and len(twice) <= 64
    assert once != twice, "f(K) == f(f(K)) の衝突が残っている"

    metrics = {
        "total_entries": 9, "action_counts_by_type": {long_key: 4, once: 5},
        "exception_summary": {}, "override_events": [], "data_access_log": [],
        "security_event_count": 0, "compliance_status": "compliant",
    }
    breakdown = build_narrative_payload(metrics)["action_counts_by_type"]
    assert len(breakdown) == 2, f"別区分が 1 つに潰れた: {breakdown}"
    assert sum(breakdown.values()) == 9


def test_shortened_key_carries_a_wide_enough_digest():
    """ダイジェスト幅は衝突耐性そのもの。短くすると衝突を作れるので構造で固定する。

    （区別できるキーを 2 本使うテストでは、1 桁でも偶然通ってしまい検知できない。）
    """
    from src.services.llm_client import _shorten_key

    shortened = _shorten_key("agent-" + "z" * 300)
    assert len(shortened) == 64
    head, _, digest = shortened.rpartition("…")
    assert head, "元キーの手掛かり（先頭）が残っていない"
    assert len(digest) == 16
    assert all(c in "0123456789abcdef" for c in digest)
