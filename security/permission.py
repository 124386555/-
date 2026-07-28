"""
最小权限分配模块
三级权限：read < write < admin
会话启动时按任务类型分配权限令牌，工具调用时比对权限
"""
from typing import Optional
from .audit import AuditLogger

# 权限等级定义（数字越大权限越高）
PERMISSION_LEVELS = {
    "read": 1,
    "write": 2,
    "admin": 3,
}


class PermissionManager:
    """最小权限管理器"""

    def __init__(self, config: dict, audit: Optional[AuditLogger] = None):
        """
        Args:
            config: 全局配置字典
            audit: 审计日志实例
        """
        self.audit = audit
        self.task_permissions = config.get("task_permissions", {})
        self._current_level: str = "read"  # 默认最低权限

    def set_session_permission(self, task_type: str) -> str:
        """
        根据任务类型设置会话权限

        Args:
            task_type: 任务类型标识（如 query_task, email_task）

        Returns:
            实际分配的权限等级
        """
        level = self.task_permissions.get(task_type, "read")
        if level not in PERMISSION_LEVELS:
            level = "read"
        self._current_level = level
        return level

    def set_permission_level(self, level: str) -> None:
        """直接设置权限等级（用于手动控制或测试）"""
        if level in PERMISSION_LEVELS:
            self._current_level = level

    def get_current_level(self) -> str:
        """获取当前会话的权限等级"""
        return self._current_level

    def check(self, tool_name: str, required_permission: str) -> bool:
        """
        校验当前权限是否满足工具要求

        Args:
            tool_name: 工具名称（仅用于审计日志）
            required_permission: 工具所需的权限等级

        Returns:
            True=权限足够, False=权限不足
        """
        required_rank = PERMISSION_LEVELS.get(required_permission, 1)
        current_rank = PERMISSION_LEVELS.get(self._current_level, 1)
        passed = current_rank >= required_rank

        if self.audit:
            self.audit.log_permission_check(
                tool_name,
                required=required_permission,
                granted=self._current_level,
                passed=passed,
            )
            if not passed:
                self.audit.log_security_violation(
                    "permission_denied",
                    f"工具 '{tool_name}' 需要 '{required_permission}' 权限，"
                    f"当前仅有 '{self._current_level}' 权限",
                )

        return passed
