"""
工具白名单模块
维护合法工具清单，每次调用时精确匹配工具名称
这是防御直接提示注入的第一道防线
"""
import os
import yaml
from typing import Optional
from .audit import AuditLogger


class ToolWhitelist:
    """工具白名单校验器"""

    def __init__(self, config: dict, audit: Optional[AuditLogger] = None):
        """
        Args:
            config: 全局配置字典（包含tools列表）
            audit: 审计日志实例
        """
        self.audit = audit
        self._config_path: Optional[str] = None
        self._last_mtime: float = 0
        self._tools: dict = {}  # tool_name -> tool_config
        self._load_tools(config.get("tools", []))

    def _load_tools(self, tools_config: list) -> None:
        """从配置加载工具清单"""
        self._tools = {}
        for tool in tools_config:
            name = tool.get("name", "")
            if name:
                self._tools[name] = {
                    "description": tool.get("description", ""),
                    "risk_level": tool.get("risk_level", "low"),
                    "required_permission": tool.get("required_permission", "read"),
                    "params": tool.get("params", {}),
                }

    def set_config_path(self, path: str) -> None:
        """设置配置文件路径，启用热加载"""
        self._config_path = path
        if os.path.exists(path):
            self._last_mtime = os.path.getmtime(path)

    def _check_reload(self) -> None:
        """检查配置文件是否变化，如有则热加载"""
        if not self._config_path or not os.path.exists(self._config_path):
            return
        current_mtime = os.path.getmtime(self._config_path)
        if current_mtime > self._last_mtime:
            self._last_mtime = current_mtime
            with open(self._config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            self._load_tools(config.get("tools", []))

    def check(self, tool_name: str) -> bool:
        """
        校验工具是否在白名单中

        Args:
            tool_name: 工具名称

        Returns:
            True=在白名单中, False=不在
        """
        self._check_reload()
        passed = tool_name in self._tools

        if self.audit:
            self.audit.log_whitelist_check(tool_name, passed)
            if not passed:
                self.audit.log_security_violation(
                    "whitelist_reject",
                    f"工具 '{tool_name}' 不在白名单中，已拦截",
                )

        return passed

    def get_tool_config(self, tool_name: str) -> Optional[dict]:
        """获取工具的详细配置"""
        return self._tools.get(tool_name)

    def get_all_tool_names(self) -> list:
        """获取所有白名单工具名称"""
        return list(self._tools.keys())

    def get_risk_level(self, tool_name: str) -> str:
        """获取工具的风险等级"""
        tool = self._tools.get(tool_name)
        return tool.get("risk_level", "low") if tool else "unknown"

    def get_required_permission(self, tool_name: str) -> str:
        """获取工具所需的权限等级"""
        tool = self._tools.get(tool_name)
        return tool.get("required_permission", "read") if tool else "read"
