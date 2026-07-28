"""
全链路审计日志模块
以JSON Lines格式记录系统全过程关键事件
"""
import json
import os
import uuid
from datetime import datetime
from typing import Any, Optional


class AuditLogger:
    """审计日志记录器，支持会话级和事件级记录"""

    def __init__(self, log_file: str = "audit_log.jsonl", enabled: bool = True):
        self.log_file = log_file
        self.enabled = enabled
        self.session_id = str(uuid.uuid4())[:8]
        self._event_count = 0

        # 确保日志目录存在
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    def log(
        self,
        event_type: str,
        payload: Any,
        module: str = "",
        decision: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        记录一条审计事件

        Args:
            event_type: 事件类型，如 user_input, tool_call_request, security_violation 等
            payload: 事件载荷（字符串或字典）
            module: 产生事件的模块名称
            decision: 安全决策结果（allow/deny/filter）
            metadata: 额外元数据
        """
        if not self.enabled:
            return

        self._event_count += 1
        entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "event_seq": self._event_count,
            "event_type": event_type,
            "module": module,
            "payload": payload if isinstance(payload, (dict, list)) else str(payload),
        }

        if decision is not None:
            entry["decision"] = decision

        if metadata:
            entry["metadata"] = metadata

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def log_user_input(self, user_input: str) -> None:
        """记录用户输入"""
        self.log("user_input", {"input": user_input}, module="agent")

    def log_agent_reasoning(self, reasoning: str) -> None:
        """记录Agent推理输出"""
        self.log("agent_reasoning", {"reasoning": reasoning}, module="agent")

    def log_tool_call_request(self, tool_name: str, arguments: dict) -> None:
        """记录工具调用请求"""
        self.log(
            "tool_call_request",
            {"tool": tool_name, "arguments": arguments},
            module="agent",
        )

    def log_whitelist_check(self, tool_name: str, passed: bool) -> None:
        """记录白名单校验结果"""
        self.log(
            "whitelist_check",
            {"tool": tool_name, "passed": passed},
            module="security.whitelist",
            decision="allow" if passed else "deny",
        )

    def log_permission_check(
        self, tool_name: str, required: str, granted: str, passed: bool
    ) -> None:
        """记录权限校验结果"""
        self.log(
            "permission_check",
            {
                "tool": tool_name,
                "required_level": required,
                "granted_level": granted,
                "passed": passed,
            },
            module="security.permission",
            decision="allow" if passed else "deny",
        )

    def log_human_confirm(self, tool_name: str, approved: bool, timed_out: bool = False) -> None:
        """记录高危操作人工确认结果"""
        self.log(
            "human_confirm",
            {"tool": tool_name, "approved": approved, "timed_out": timed_out},
            module="security.human_confirm",
            decision="allow" if approved else "deny",
        )

    def log_data_filter(
        self, tool_name: str, original_length: int, filtered: bool, patterns_hit: list
    ) -> None:
        """记录数据过滤结果"""
        self.log(
            "data_filter",
            {
                "tool": tool_name,
                "original_length": original_length,
                "filtered": filtered,
                "patterns_hit": patterns_hit,
            },
            module="security.data_filter",
            decision="filter" if filtered else "allow",
        )

    def log_tool_execution(self, tool_name: str, success: bool, result_summary: str) -> None:
        """记录工具执行结果"""
        self.log(
            "tool_execution",
            {"tool": tool_name, "success": success, "result_summary": result_summary[:200]},
            module="tools",
        )

    def log_security_violation(self, violation_type: str, detail: str) -> None:
        """记录安全违规事件"""
        self.log(
            "security_violation",
            {"type": violation_type, "detail": detail},
            module="security",
            decision="deny",
        )

    def get_stats(self) -> dict:
        """获取当前会话的统计摘要"""
        return {
            "session_id": self.session_id,
            "total_events": self._event_count,
            "log_file": self.log_file,
        }

    def reset_session(self) -> None:
        """重置会话（用于新评测用例）"""
        self.session_id = str(uuid.uuid4())[:8]
        self._event_count = 0


# 全局审计日志实例（延迟初始化）
_logger: Optional[AuditLogger] = None


def get_audit_logger(config: Optional[dict] = None) -> AuditLogger:
    """获取全局审计日志实例"""
    global _logger
    if _logger is None:
        if config:
            _logger = AuditLogger(
                log_file=config.get("log_file", "audit_log.jsonl"),
                enabled=config.get("enabled", True),
            )
        else:
            _logger = AuditLogger()
    return _logger
