"""
SecureToolWrapper - 安全中间件包装器
在每个工具的调用前后插入安全检查流程：
  tool_call生成 → ①白名单校验 → ②权限比对 → ③高危确认 → 执行工具 → ④返回结果过滤 → ⑤审计
"""
from typing import Optional, Any
from security.audit import AuditLogger
from security.whitelist import ToolWhitelist
from security.permission import PermissionManager
from security.human_confirm import HumanConfirm
from security.data_filter import DataFilter


class SecurityCheckResult:
    """安全检查结果"""

    def __init__(self, passed: bool, reason: str = "", stage: str = ""):
        self.passed = passed
        self.reason = reason
        self.stage = stage  # 在哪个阶段被拦截


class SecureToolWrapper:
    """
    安全工具包装器
    包装原始工具的invoke方法，在执行前依次进行安全校验
    """

    def __init__(
        self,
        whitelist: ToolWhitelist,
        permission: PermissionManager,
        human_confirm: HumanConfirm,
        data_filter: DataFilter,
        audit: AuditLogger,
        security_enabled: bool = True,
    ):
        self.whitelist = whitelist
        self.permission = permission
        self.human_confirm = human_confirm
        self.data_filter = data_filter
        self.audit = audit
        self.security_enabled = security_enabled

    def pre_check(self, tool_name: str, arguments: dict) -> SecurityCheckResult:
        """
        工具执行前的安全校验链

        依次执行：白名单 → 权限 → 高危确认
        任一环节失败则立即返回拒绝结果

        Args:
            tool_name: 工具名称
            arguments: 工具调用参数

        Returns:
            SecurityCheckResult
        """
        if not self.security_enabled:
            return SecurityCheckResult(True)

        # ① 白名单校验
        if not self.whitelist.check(tool_name):
            return SecurityCheckResult(
                False,
                reason=f"工具 '{tool_name}' 不在白名单中",
                stage="whitelist",
            )

        # ② 权限校验
        required_perm = self.whitelist.get_required_permission(tool_name)
        if not self.permission.check(tool_name, required_perm):
            return SecurityCheckResult(
                False,
                reason=f"权限不足：需要 '{required_perm}'，当前 '{self.permission.get_current_level()}'",
                stage="permission",
            )

        # ③ 高危操作确认
        risk_level = self.whitelist.get_risk_level(tool_name)
        if risk_level == "high":
            approved = self.human_confirm.confirm(tool_name, arguments)
            if not approved:
                return SecurityCheckResult(
                    False,
                    reason=f"高危工具 '{tool_name}' 未获人工批准",
                    stage="human_confirm",
                )

        return SecurityCheckResult(True)

    def post_filter(self, tool_name: str, result: str) -> str:
        """
        工具执行后的返回结果过滤

        Args:
            tool_name: 工具名称
            result: 工具原始返回内容

        Returns:
            过滤后的返回内容
        """
        if not self.security_enabled:
            return result

        filtered_result, was_filtered, patterns_hit = self.data_filter.filter_result(
            tool_name, result
        )

        return filtered_result

    def full_check_and_execute(
        self, tool_name: str, arguments: dict, execute_fn
    ) -> dict:
        """
        完整的安全检查+执行流程（供SecureTool的invoke调用）

        Args:
            tool_name: 工具名称
            arguments: 工具调用参数
            execute_fn: 实际的工具执行函数，签名 () -> dict

        Returns:
            标准化的返回格式 {"status": "ok/error", "data": ..., "security": {...}}
        """
        # 审计：记录工具调用请求
        self.audit.log_tool_call_request(tool_name, arguments)

        # 前置安全检查
        pre_result = self.pre_check(tool_name, arguments)
        if not pre_result.passed:
            return {
                "status": "error",
                "data": None,
                "security": {
                    "blocked": True,
                    "stage": pre_result.stage,
                    "reason": pre_result.reason,
                },
            }

        # 执行工具
        try:
            raw_result = execute_fn()
        except Exception as e:
            self.audit.log_tool_execution(tool_name, False, str(e))
            return {
                "status": "error",
                "data": None,
                "security": {"blocked": False, "error": str(e)},
            }

        # 后置数据过滤
        raw_str = str(raw_result.get("data", "")) if isinstance(raw_result, dict) else str(raw_result)
        filtered_str = self.post_filter(tool_name, raw_str)

        # 审计：记录执行结果
        self.audit.log_tool_execution(tool_name, True, filtered_str[:200])

        if isinstance(raw_result, dict):
            raw_result["data"] = filtered_str
            raw_result.setdefault("security", {})
            raw_result["security"]["filtered"] = filtered_str != raw_str
            return raw_result

        return {
            "status": "ok",
            "data": filtered_str,
            "security": {"blocked": False, "filtered": filtered_str != raw_str},
        }
