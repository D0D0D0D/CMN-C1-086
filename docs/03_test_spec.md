# Test Specification — CMN-C1-086

## Test Strategy
- カバレッジ目標: 主要ノード・サービス・セキュリティゲートを全パス網羅（unit + PB + integration）
- テスト種別: Unit（ノード単体）/ Proof-of-Boundary（セキュリティゲート境界）/ Integration（invoke チェーン全体）
- 実行: `python -m pytest tests/ -v`、`python -m pytest tests/proof_of_boundary/ -v`
- フレームワーク: `agenticstar-agentcore==1.0.0`（CI は registry から install）

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State contract: flat TypedDict（Pydantic/dataclass 不使用） | `test_state_file_safety`（PB）pass | PASS |
| TC-02 | SecurityViolationError fires on invalid input | `TestS2InputGate` で oversized/injection が raise | PASS |
| TC-03 | No JWT/Credential in State / src | CI `gate-credential-scan`: 0 violations | PASS |
| TC-04 | InvocationContext via configurable only | invoke は ctx 経由（integration） | PASS |
| TC-05 | S-4: no duplicate lifecycle events in `execute()` | `node_start/complete/error` を `execute()` で発行しない | PASS |
| TC-06 | S-2: `_security_gate_input()` 非 override（FunctionNode） | `_extra_security_gate_input` のみ実装 | PASS |
| TC-07 | S-3: `_security_gate_output()` 非 override（FunctionNode） | `_extra_security_gate_output` のみ実装 | PASS |
| TC-08 | `required_trust_level` enforced | manifest `VERIFIED_EXTERNAL`（integration は VERIFIED_EXTERNAL で実行） | PASS |
| TC-11 | S-4: 各 `execute()` に ≥1 ドメイン `emit_trace_event()` | pre/main/post 各ノードで emit | PASS |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result | Result |
|-------|----------|------|----------------|--------|
| PB-1 | BaseNode → AuditLogger | `emit_trace_event()` が各 execute で発火 | No silent failures | PASS |
| PB-2 | State serialization | post-invoke State は primitives のみ | `test_state_file_safety` | PASS |
| PB-4 | Import isolation | Level 0 import なし | `test_import_isolation` AST: 0 | PASS |
| PB-6 | Invoke execution order | S-1 → S-4 start → S-2 → execute → S-3 → S-4 complete | integration で 5 ノード順序検証 | PASS |
| **PB-S2** | S-2 入力ゲート | サイズ上限超過・injection マーカーで `SecurityViolationError` | `TestS2InputGate` | PASS |
| **PB-S3** | S-3 非サプレッシブル preservation | レポートからセキュリティイベントが欠落したら fail-closed | `TestS3PreservationGate` | PASS |

## Business Logic Tests

| TC-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | ログ集計（agent type 別アクション数） | 5 件サンプルログ | `action_counts_by_type` 正確、`total_entries==5` | PASS |
| BL-02 | 非サプレッシブルなセキュリティイベント抽出 | security_exception + unauthorized を含むログ | E3/E5 が `security_events` に必ず含まれる | PASS |
| BL-03 | コンプライアンスステータス判定 | セキュリティイベント有 | `attention_required` | PASS |
| BL-04 | 不正 JSON / 空入力 | `"{not json"` / `""` / `"[]"` | `status="error"`（graceful） | PASS |
| BL-05 | レポートに全セキュリティイベント記載＋S-5 disclaimer | サンプルログ | report に E3/E5 と「ディスクレーマー」 | PASS |
| BL-06 | invoke 全チェーン | サンプルログ | `status="success"`、5 ノード実行、report にセキュリティイベント | PASS |

## Test Execution Summary
- 実行日: 2026-08-28（ローカル `agenticstar-agentcore==1.0.1`）
- 合計テスト: 78
- Pass: 76 / Fail: 0 / Skip: 2（PB-7 = 非 HITL のため auto-waived）
- 備考: unit（nodes / runtime_config / TC-06・07 / LLM シーム）+ PB（import_isolation / state_safety /
  security_gates / invoke_order / pb7）+ integration（invoke chain / server auth）

## 実 LLM 1 回転検証

モックだけで固めた実装は実 LLM を繋いだ瞬間に動かないことがあるため、注入シームへ実 LLM クライアントを刺して 1 回 invoke し、**中身のある出力が出ること**を確認している（`gitproject-dev-flow.md` §14-1-bis）。

| 項目 | 内容 |
|---|---|
| 実施日 | 2026-08-28 |
| 使用 LLM | ローカル CLI（Azure OpenAI）を `BaseLLM` 実装として注入 |
| 注入シーム | `config[llm]` |
| 実 LLM 呼び出し | 1 回 |
| 出力 | ['<text output: 3232字>'] が非空。縮退理由なし |

本番の LLM は `AnthropicClient` 等で、これは検証用シーム。テンプレの `src/` は変更していない（一時テストを生成→実行→削除する方式）。CI には入れていない（ローカル CLI と鍵が要るため）。

## 実 LLM 検証で確認したこと / 見つけて直した欠陥

上の節はハーネスが自動で書き換えるため、内容の分析はここに残す。

**確認できたこと（4 回転すべて）**

- `config["llm"]` に刺した `BaseLLM` が **本番の構築経路（`Graph(config=...)` → `register_nodes()`
  → `MainNode`）を通って実際に呼ばれた**。修正前はテスト側の monkeypatch でしか LLM に届かず、
  本番経路は一度も通っていなかった。
- 叙述サマリが実 LLM 由来の文面になり、見出しが `## サマリ（AI 起草）` になる。
- **抑制不可のセキュリティイベント 4 件（E029 / E030 / E031 / E032）が表に全件残る。**
  この部分は `audit_aggregator` の決定論処理で、LLM の出来に依存しない（`docs/02_design.md`）。
- 散文中の数値が集計表と一致する（総 32 / データアクセス 19 / override 3 / セキュリティ 4 / 例外計 6）。

入力は `tests/conftest.py` の `case_payload`（活動ログ **32 件** — agent_type 4 種 / 例外 4 種 /
human override 3 件 / data_access 19 件 / セキュリティイベント 4 件）。汎用ダミーではなく、
この AG の本来の入力で回している。

**この検証で見つけて直した欠陥（2 件）**

1. **モデルが件数を自分で数えていた。** `override_events` を生リストのまま渡していたため、
   1 回目の実行で「3 件記録され」という **モデルが数えた件数**が散文に入った。監査の件数は
   ログから決定論的に出すべき値なので、プロンプト payload 側で `*_count` として数えて渡し、
   「`_sample` は抜粋なので数えるな」と明示する形に変更した（`build_narrative_payload()`）。
   2 回目以降は散文中の数値がすべて供給値の転記になった。
2. **プロンプト長が入力サイズに比例していた。** `metrics` をそのまま渡していたため、
   活動ログ 32 件で 3.4KB。入力上限は 1MB（`config/config.yaml: max_log_bytes`）なので、
   実運用サイズではプロンプトが破綻する。payload を件数＋先頭 20 件の抜粋に畳み、
   直列化長 8,000 字を超えたら抜粋を、なお超えたら内訳を落とす形に変更した（件数は常に保つ）。

**残存リスク（機械保証していないこと）**: AI 起草の散文と集計表の一致は機械検査していない。
件数をモデルに数えさせない構成にしたうえで、レポート側で出所（AI 起草 / 決定論生成）と
「数値の正本は集計表」を明示し、最終担保は人のレビューに置く（S-5 ディスクレーマー）。

## LLM 注入シームのユニット/統合テスト（`tests/unit/test_llm_seam.py`）

| ケース | 期待 |
|---|---|
| `config["llm"]` 未注入 | 決定論ナラティブ・`llm_not_injected`・`status=success` |
| `BaseLLM` を注入 | 実 LLM 由来の本文・出所 `llm`・モデル名は応答の `model` |
| `BaseLLM` でないオブジェクト（`complete` を持っていても） | 縮退 `llm_unsupported:<型名>` |
| `__getattr__` で何でも返すオブジェクト | 縮退（委譲に釣られない） |
| `BaseLLM` 型が import できない wheel 変種 | クラス側 `complete` の duck 判定にフォールバック |
| 活動ログ（値・集計キーの双方）に credential | **送信せず**縮退 `input_unsafe_content:<種別>` |
| `complete()` が送出 / 応答の取り出しで送出 | 縮退 `llm_failed:<例外型名>`。プロバイダのメッセージは載らない |
| 応答が `None` / 空 / 空白 | 縮退 `llm_empty`。文字列 `"None"` を本文にしない |
| 応答に credential パターン | 縮退 `llm_unsafe_content:<種別>`（S-3 が run 全体を落とす前に止める） |
| 応答に PII | `MainNode` の S-3 フックでマスク・レポートに注記・`narrative_pii_masked` |
| 応答の `model` に credential / PII / 巨大文字列 | `[REDACTED]` / マスク / 120 字で切り詰め |
| プロンプト payload | 件数は全て供給・抜粋 20 件・キー 64 字（衝突しない切り詰め）・直列化長 8,000 字以内 |
| S-4 監査イベント | `narrative_synthesized` に出所 / 縮退理由 / モデル名が載る |
| LLM 未注入時のレポート | develop 実出力＋宣言済み差分と byte 一致（golden） |
