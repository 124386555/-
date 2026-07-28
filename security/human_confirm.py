"""
高危操作人工确认模块
风险等级为high的工具调用时暂停执行，等待人工确认
支持自动评测模式（预设approve/deny规则）
"""
import threading
import queue
from typing import Optional
from .audit import AuditLogger


class HumanConfirm:
    """高危操作人工确认器"""

    def __init__(self, config: dict, audit: Optional[AuditLogger] = None):
        """
        Args:
            config: human_confirm配置段
            audit: 审计日志实例
        """
        self.audit = audit
        self.timeout_seconds = config.get("timeout_seconds", 60)
        self.auto_mode = config.get("auto_mode", False)
        self.auto_rules = config.get("auto_rules", {})

    def confirm(self, tool_name: str, arguments: dict, reason: str = "") -> bool:
        """
        请求人工确认高危操作

        Args:
            tool_name: 工具名称
            arguments: 工具调用参数
            reason: 调用原因说明

        Returns:
            True=已批准, False=已拒绝/超时
        """
        if self.auto_mode:
            return self._auto_confirm(tool_name)

        return self._interactive_confirm(tool_name, arguments, reason)

    def _auto_confirm(self, tool_name: str) -> bool:
        """自动模式：根据预设规则决策"""
        rule = self.auto_rules.get(tool_name, "deny")
        approved = rule == "approve"
        timed_out = False

        if self.audit:
            self.audit.log_human_confirm(tool_name, approved, timed_out)
            if not approved:
                self.audit.log_security_violation(
                    "human_confirm_deny",
                    f"高危工具 '{tool_name}' 在自动模式下被预设规则拒绝",
                )

        return approved

    def _interactive_confirm(self, tool_name: str, arguments: dict, reason: str) -> bool:
        """交互模式：终端等待用户输入"""
        print(f"\n{'='*60}")
        print(f"⚠  高危操作确认请求")
        print(f"{'='*60}")
        print(f"  工具: {tool_name}")
        print(f"  参数: {arguments}")
        if reason:
            print(f"  原因: {reason}")
        print(f"  超时: {self.timeout_seconds}秒后自动拒绝")
        print(f"{'='*60}")

        result_queue = queue.Queue()

        def _get_input():
            try:
                user_input = input("  是否批准？(y/n): ").strip().lower()
                result_queue.put(user_input)
            except EOFError:
                result_queue.put("n")

        thread = threading.Thread(target=_get_input, daemon=True)
        thread.start()

        try:
            user_input = result_queue.get(timeout=self.timeout_seconds)
            approved = user_input in ("y", "yes")
            timed_out = False
        except queue.Empty:
            approved = False
            timed_out = True
            print("  ⏰ 超时，自动拒绝")

        if self.audit:
            self.audit.log_human_confirm(tool_name, approved, timed_out)
            if not approved:
                violation_type = "human_confirm_timeout" if timed_out else "human_confirm_deny"
                self.audit.log_security_violation(
                    violation_type,
                    f"高危工具 '{tool_name}' 人工确认{'超时' if timed_out else '被拒绝'}",
                )

        return approved
