# Template Design Specification — CMN-C1-086

Agent Activity Audit & Compliance Report Generator（Cat 1 / DocGeneration パターン）

## Position in AgentCore Architecture

- **Agent Class**: `AgentAuditReportAgent`
- **L1 Base**: **AgentBaseGraph**（L1 直接継承。Cat 1 のため inner graph なし）
  - base_type メタデータは `DocGenerationAgent`（Level 2 の概念パターン参照）だが、
    実装はあくまで L1 の `AgentBaseGraph` を直接継承する。
- **Three-Layer Separation**:
  - State: flat TypedDict 合成（Pydantic 不可 — msgpack 非互換）
  - Node: L1 継承（Template Method: `execute(self, state) -> dict` のみ override）
  - Graph: 合成（`register_nodes()` で 3 スロットにドメインノードを割り当て。`add_edges()` /
    `route()` は override しない）

## Architecture Overview

固定 5 ノード backbone（Cat 1）に、本テンプレートのドメイン処理を 3 スロットへ 1:1 で
マッピングする。

### Node Configuration

| Node | 責務 | Input State（読み取り） | Output State（変更キーのみ返す） | Inherits/Overrides |
|------|------|------|------|------|
| initialize | schema_version / session_id / caller_trust_level 設定 | — | （framework 既定） | InitializeNode (default) |
| pre_process | **LogIngest + S-2**: 活動ログ JSON のパース・スキーマ検証・正規化。サイズ上限＋prompt-injection スクリーニング | `user_input`（活動ログ JSON 文字列）, `input_context` | `validated_input`, `parsed_logs`, `report_period`, `status` | `PreProcessNode(FunctionNode)` + `_extra_security_gate_input` |
| main | **AuditAggregate + Narrative**: agent type 別アクション数・例外/エラー・human override・データアクセスを集計。**非サプレッシブルなセキュリティイベント抽出**。LLM ナラティブ合成 | `parsed_logs`, `report_period` | `audit_metrics`, `security_events`, `narrative_summary`, `status` | `MainNode(FunctionNode)` |
| post_process | **ReportAssemble + S-3 + S-5**: Markdown 監査レポート組立。**非サプレッシブル preservation 検証**（全セキュリティイベントがレポートに含まれることを保証）。S-5 disclaimer 付与 | `audit_metrics`, `security_events`, `narrative_summary` | `report_markdown`, `formatted_output`, `result`, `status` | `PostProcessNode(FunctionNode)` + `_extra_security_gate_output` |
| finalize | response_metadata / total_time_ms 構築 | — | （framework 既定） | FinalizeNode (default) |

### Data Flow

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
                                            ↓ (retry, max 3)
                                          pre_process
```

- `pre→main` は無条件辺。`route()` は main の後に `state["status"]` を読む
  （`success`→post_process / `retry`→pre_process / 他→finalize）。framework 所有のため override しない。
- pre_process が `status="error"`（空入力・不正 JSON）を返した場合、main は無条件に実行されるため
  上流エラーをパススルーし、post_process でエラー result を組み立てる（graceful degradation）。

### State Definition

`src/schemas/state.py` の `State(AgentState)`。共有フィールド（`user_input`, `status`,
`session_id`, `node_history`, `error_log`, `correlation_id`, `trace_id`, `hitl_*` 等）は
`AgentState` から継承。

| Field | Type | Purpose | Required |
|-------|------|---------|----------|
| `validated_input` | `str` | サニタイズ済み活動ログ payload | Yes |
| `report_period` | `str` | レポート対象期間（例 `2026-06`。ログから推定 or input_context 指定） | Yes |
| `parsed_logs` | `list` | パース済みログエントリ `[{timestamp, agent_id, agent_type, action, outcome, trust_level, data_access, is_security_exception, is_unauthorized, is_human_override}]` | Yes |
| `audit_metrics` | `dict` | 集計結果（action_counts_by_type / exception_summary / override_events / data_access_log / compliance_status） | Yes |
| `security_events` | `list` | **非サプレッシブル**: セキュリティ例外＋不正アクセス試行の一覧（id 付き） | Yes |
| `narrative_summary` | `str` | ナラティブ要約（LLM 起草 or 決定論生成・メトリクスは常に決定的） | No |
| `narrative_source` | `str` | `llm` / `deterministic` — `narrative_summary` の出所。レポート見出しと `result` に出す | Yes |
| `narrative_degradation_reason` | `str` | LLM を採用しなかった理由コード（`llm_not_injected` / `llm_unsupported:<型名>` / `input_unsafe_content:<種別>` / `llm_failed:<例外型名>` / `llm_empty` / `llm_unsafe_content:<種別>`）。採用時は空文字 | Yes |
| `narrative_pii_masked` | `bool` | AI 起草本文の個人情報を S-3 フックでマスクしたか | Yes |
| `report_markdown` | `str` | 組立済み監査レポート | Yes |
| `result` | `dict` | 呼び出し元へ返す最終出力（`ok` / `report_markdown` / `report_period` / `audit_metrics` / `security_events` / `narrative_source` / `narrative_degradation_reason` / `narrative_pii_masked`。エラー時は `ok: False` / `error_log` / `disclaimer`）。なお `get_output()` は `formatted_output`（レポート文字列）を優先するため、**この dict は標準経路では呼び出し元に届かない** — 読み手に必要な情報はレポート本文にも出す | Yes |

**State Constraints (mandatory):**
- Flat TypedDict のみ（primitives + JSON-serializable）。Pydantic / dataclass / 任意オブジェクト不可
- JWT / API キー / credential を State に置かない（checkpoint DB 漏洩防止）
- InvocationContext は `config["configurable"]` 経由のみ（State に置かない）

## Framework Utilization

### Shared Components Used
- [x] InvocationContext（correlation_id / session_id / caller_trust_level）
- [x] SecurityViolationError（S-2 違反時に raise）
- [x] **S-2**: `PreProcessNode._extra_security_gate_input()` — 入力サイズ上限（既定 1MB）＋
      prompt-injection マーカー検知。framework 既定の PII スキャンの後段に追加（`@final` の
      `_security_gate_input()` は override しない）
- [x] **S-3（main）**: `MainNode._extra_security_gate_output()` — **LLM が書いた散文の PII マスク**。
      framework の S-2 が走査するのは `user_input` / `validated_input` / `llm_response` の 3 つだけで、
      本テンプレートが LLM 本文を置く `narrative_summary` は対象外。S-3 既定は credential しか見ない。
      入力側は S-2 が `user_input` を `execute()` 前にマスクするので、`parsed_logs` 由来の集計値と
      レポート表はマスク済みの値から作られる。塞ぐ必要があるのは **LLM 由来の本文だけ**
      （framework は出力側の PII を見ないので、ここで塞ぐ）。マスクした事実は
      `narrative_pii_masked` に残す。
      ⚠️ **残存ギャップ（Rule 6.4・今サイクル WARN）**: `detect_pii` の `name_jp` は
      氏名／名前／担当者ラベル＋区切りに続く漢字・カタカナ氏名までで、**ラベルの無い
      裸の日本語氏名は検出できない**（1.0.1 で実測）。本 AG は LLM に日本語の散文を
      書かせるためこのギャップは実在する。substrate の再利用に留め、残存ギャップ向けの
      独自検出器は入れていない（ラベル付きのケースは substrate が既に持っているので、
      自前実装すると検出ロジックが二重になる）。
- [x] **S-3（post_process）**: `PostProcessNode._extra_security_gate_output()` — **preservation variant**:
      `security_events` の各 id が `report_markdown` に**構造化テーブル行 `| {entry_id} | {kind} |`
      として**含まれることを検証し、欠落していれば `SecurityViolationError`。framework 既定の
      credential スキャンの後段に追加（`@final` の `_security_gate_output()` は override しない）。
      このフックは**検証のみ**で値を書き換えない
- [x] **S-4**: `emit_trace_event()`（`shared.utils.audit_logger`）を各 `execute()` 内で呼ぶ
      （pre: `activity_logs_ingested` / main: `audit_metrics_aggregated`・`narrative_synthesized` /
      post: `audit_report_finalized`）。`node_start` / `node_complete` / `node_error` は
      `BaseNode.__call__()` が自動発行するため `execute()` 内で重複発行しない

> **S-2/S-3 gate behaviour by node type (ADR-017):**
> - 本テンプレートの 3 ノードは全て `FunctionNode` サブクラス → framework `@final` ゲートが自動実行され、
>   `_extra_security_gate_input()` / `_extra_security_gate_output()` で拡張する（直接 override は
>   クラス定義時 `TypeError`）。

### Composition Pattern

- **Pattern**: Standalone（Cat 1 — GraphNode / inner subgraph は使用しない）
- **Error propagation strategy**: pre_process のエラーは main がパススルーし、post_process が
  エラー result（`{ok: False, error_log, disclaimer}`）を組み立てる（handle）
- **Entry points**: `src/api/server.py`（HTTP `/invoke`）と `cli.py`（AGENTIC STAR Marketplace）の 2 本。
  どちらも adapter でありビジネスロジックを持たない。`cli.py` はグラフを継承した `MarketplaceGraph` で
  Marketplace 境界のみを固める（`config["llm"]` への遅延 Azure クライアント注入 / `input_context` の
  組み直し / `hitl_allowed=False` / 起動時の Azure 接続値 fail-closed）。詳細は `docs/07_operation_guide.md`。

## Import Isolation Confirmation
- [x] Level 0（agenticstar-platform SDK）を import しない
- [x] import 対象は `framework/` と `shared/` のみ（`agents/base/` 不要）

## Security Model（S-1〜S-5 マッピング）

| Layer | 本テンプレートでの実装 |
|---|---|
| S-1 Trust Gate | 各ノードに `required_trust_level`（最小 `VERIFIED_EXTERNAL` — 監査ログは認証済み呼び出しのみ）。`BaseNode.__call__()` が自動強制 |
| S-2 Input Gate | `PreProcessNode._extra_security_gate_input`: 入力サイズ上限＋injection 検知 |
| S-3 Output Gate | `MainNode._extra_security_gate_output`: LLM 由来本文の PII マスク／`PostProcessNode._extra_security_gate_output`: **非サプレッシブル preservation**（検証のみ）。credential は framework 既定スキャンが担当（下記 S-3 posture） |
| LLM egress | `synthesize_narrative()` は **送信前**にプロンプト payload を `detect_credentials_in_value()` で検査し、検出したら送信せず決定論へ縮退する。S-3 は `complete()` の後にしか効かないため、プロバイダへの流出を止められるのはここだけ |
| S-4 Audit Log | 各 `execute()` でドメインイベントを `emit_trace_event()` |
| S-5 Disclaimer | post_process で「本レポートは AI 監査支援であり正式な人手レビュー/法的助言を代替しない」を prepend |

### S-3 credential posture

本テンプレートは活動ログの値（`agent_id` / `action` / `data_access` など）をレポート表へ
そのまま描画する。ログに credential パターンが含まれていた場合、framework 既定の S-3 が
`RuntimeError` を送出し、**run 全体が `status=error` / `output` なし**になる（**BLOCK 姿勢**）。
監査レポートに鍵をそのまま載せるより、生成を止めて調査させる方が正しいと判断した。
`PostProcessNode` が `result` を書くノード自身なので、raise 時は `result` も書かれず、
`get_output()` の `formatted_output or result` フォールバックで未検査の本文が漏れることはない。

一方、**LLM へ送るプロンプト**は S-3 の前段（`complete()` の呼び出し前）にあるため、
`synthesize_narrative()` が送信前に自前で検査して egress を止める（上表 LLM egress）。

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | **AgentBaseGraph** | AutonomousBaseGraph | **AgentBaseGraph** | 固定パイプラインで十分。自律ループ不要（Cat 1） |
| Composition pattern | **Standalone（3 スロット直実装）** | GraphNode + inner graph | **Standalone** | Cat 1 単一能力。inner workflow は不要。集計は決定的処理 |
| 非サプレッシブル実装 | post_process 内の単純連結 | **S-3 preservation gate で強制検証** | **S-3 gate** | 「監査から不都合事象を削除できない」を framework ゲートで保証 = 規制適合の核心 |
| LLM 依存 | 必須（外部 API） | **`config["llm"]` 注入シーム＋決定論縮退** | **注入シーム** | メトリクス集計は LLM 不要で決定的。ナラティブのみ LLM。未注入・失敗時も監査レポートは成立 |
| LLM 注入経路 | Graph の独自コンストラクタ引数 | **`config["llm"]`** | **`config["llm"]`** | `BaseGraph.__init__(self, config=None)` が唯一の構築契約。独自引数は本番の呼び出し側が渡さないため恒久的に未配線になる |
| LLM 失敗時 | `status=error` | **決定論ナラティブへ縮退し `status=success`** | **縮退** | 集計表＋非抑制セキュリティイベント表だけで監査レポートは成立する。縮退の事実はレポート見出しと `result.narrative_degradation_reason` に明示するので、黙って劣化はしない |
| ナラティブの出所表示 | 表示しない | **レポート見出しで区別（AI 起草 / 決定論生成）** | **区別する** | 監査レポートはそれ自体が証跡。読み手が「LLM が書いた散文」と「決定論的に集計した数値」を取り違えないようにする。数値の正本は集計表であることも本文に明記 |
