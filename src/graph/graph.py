"""AgentCore Platform v1.0 — CMN-C1-086 graph (Cat 1).

Fixed 5-node backbone (AgentBaseGraph):
  START → initialize → pre_process → main → {route} → post_process → finalize → END
                                          ↓ (RETRY, max 3)
                                       pre_process

CMN-C1-086 is a Cat 1 DocGeneration-pattern capability: it ingests agent
activity logs, aggregates audit metrics, and assembles a standardized
compliance audit report. The three domain slots map 1:1 onto the backbone:

  pre_process  → LogIngestNode      (parse + validate activity logs, S-2)
  main         → AuditAggregateNode (metrics + non-suppressible security events + LLM narrative)
  post_process → ReportAssembleNode (Markdown report + non-suppressible preservation S-3 + S-5)

add_edges() / route() are framework concerns — NOT overridden.
"""

from __future__ import annotations

from framework.graph.agent_base_graph import AgentBaseGraph

from src.nodes.pre_process_node import PreProcessNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.schemas.state import State


class AgentAuditReportAgent(AgentBaseGraph):
    """CMN-C1-086 — Agent Activity Audit & Compliance Report Generator."""

    @property
    def name(self) -> str:
        return "cmn_c1_086"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode
        # Domain pipeline slots (required — fill all three).
        # config はここでノードへ渡す。LLM は config["llm"] シームで main に届く
        # （BaseGraph.__init__(config=None) が唯一の構築契約なので、独自コンストラクタ
        # 引数を足しても本番の呼び出し側が渡さず永久に未配線になる）。
        cfg = self.config or {}
        self._nodes["pre_process"] = PreProcessNode(config=cfg)
        self._nodes["main"] = MainNode(config=cfg)
        self._nodes["post_process"] = PostProcessNode()
