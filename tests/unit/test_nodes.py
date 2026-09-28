# CMN-C1-086 — Unit Tests: pre_process / main / post_process nodes

import inspect
import json


from framework.schemas.agent_status import AgentStatus
from src.nodes.pre_process_node import PreProcessNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode


SAMPLE_LOGS = json.dumps(
    {
        "period": "2026-06",
        "logs": [
            {"entry_id": "E1", "timestamp": "2026-06-01T10:00:00Z", "agent_id": "a1",
             "agent_type": "rag", "action": "query", "outcome": "success",
             "data_access": "kb/finance"},
            {"entry_id": "E2", "timestamp": "2026-06-01T11:00:00Z", "agent_id": "a2",
             "agent_type": "docgen", "action": "generate", "outcome": "error"},
            {"entry_id": "E3", "timestamp": "2026-06-02T09:00:00Z", "agent_id": "a3",
             "agent_type": "react", "action": "tool_call", "outcome": "denied",
             "is_unauthorized": True},
            {"entry_id": "E4", "timestamp": "2026-06-02T12:00:00Z", "agent_id": "a1",
             "agent_type": "rag", "action": "override", "outcome": "success",
             "is_human_override": True},
            {"entry_id": "E5", "timestamp": "2026-06-03T08:00:00Z", "agent_id": "a4",
             "agent_type": "react", "action": "exfiltrate", "outcome": "blocked",
             "is_security_exception": True},
        ],
    }
)


class TestPreProcessNode:
    def setup_method(self):
        self.node = PreProcessNode()

    def test_valid_logs_parsed(self):
        result = self.node.execute({"user_input": SAMPLE_LOGS})
        assert result["status"] == AgentStatus.SUCCESS.value
        assert len(result["parsed_logs"]) == 5
        assert result["report_period"] == "2026-06"

    def test_empty_input_errors(self):
        result = self.node.execute({"user_input": "   "})
        assert result["status"] == AgentStatus.ERROR.value
        assert result["error_log"]

    def test_invalid_json_errors(self):
        result = self.node.execute({"user_input": "{not valid json"})
        assert result["status"] == AgentStatus.ERROR.value

    def test_empty_log_array_errors(self):
        result = self.node.execute({"user_input": "[]"})
        assert result["status"] == AgentStatus.ERROR.value

    def test_execute_method_signature(self):
        """node contract: execute(self, state), no _invoke_impl."""
        sig = inspect.signature(PreProcessNode.execute)
        params = list(sig.parameters.keys())
        assert params[1] == "state"
        assert "_invoke_impl" not in PreProcessNode.__dict__


class TestMainNode:
    def setup_method(self):
        self.node = MainNode()
        parsed, _ = _parse(SAMPLE_LOGS)
        self.state = {"parsed_logs": parsed, "report_period": "2026-06",
                      "status": AgentStatus.SUCCESS.value}

    def test_aggregates_metrics(self):
        result = self.node.execute(self.state)
        assert result["status"] == AgentStatus.SUCCESS.value
        m = result["audit_metrics"]
        assert m["total_entries"] == 5
        assert m["action_counts_by_type"]["rag"] == 2
        assert m["compliance_status"] == "attention_required"  # has security events

    def test_extracts_non_suppressible_security_events(self):
        result = self.node.execute(self.state)
        ids = {e["entry_id"] for e in result["security_events"]}
        # E3 (unauthorized) + E5 (security exception) must both be present
        assert {"E3", "E5"} <= ids

    def test_upstream_error_passthrough(self):
        result = self.node.execute({"status": AgentStatus.ERROR.value})
        assert result["status"] == AgentStatus.ERROR.value
        assert "audit_metrics" not in result

    def test_narrative_present(self):
        result = self.node.execute(self.state)
        assert isinstance(result["narrative_summary"], str)
        assert result["narrative_summary"]


class TestPostProcessNode:
    def setup_method(self):
        self.node = PostProcessNode()

    def _full_state(self):
        from src.services import audit_aggregator
        parsed, period = _parse(SAMPLE_LOGS)
        return {
            "report_period": period,
            "audit_metrics": audit_aggregator.aggregate(parsed),
            "security_events": audit_aggregator.extract_security_events(parsed),
            "narrative_summary": "テスト用ナラティブ",
            "status": AgentStatus.SUCCESS.value,
        }

    def test_report_contains_security_events(self):
        result = self.node.execute(self._full_state())
        report = result["result"]["report_markdown"]
        assert "E3" in report and "E5" in report
        assert "ディスクレーマー" in report  # S-5

    def test_error_passthrough(self):
        result = self.node.execute({"status": AgentStatus.ERROR.value,
                                    "error_log": ["boom"]})
        assert result["status"] == AgentStatus.ERROR.value
        assert result["result"]["ok"] is False


def _parse(raw):
    from src.services import audit_aggregator
    return audit_aggregator.parse_logs(raw)
