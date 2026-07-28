"""
控制流与数据流分离模块
对工具返回内容执行关键词/正则过滤
检测疑似注入模式，命中则截断并标记[FILTERED]
"""
import re
from typing import Optional
from .audit import AuditLogger


class DataFilter:
    """工具返回内容过滤器"""

    def __init__(self, config: dict, audit: Optional[AuditLogger] = None):
        """
        Args:
            config: data_filter配置段（含patterns列表）
            audit: 审计日志实例
        """
        self.audit = audit
        # 输出级数据泄露过滤模式
        patterns = config.get("patterns", [])
        self._patterns = []
        for p in patterns:
            try:
                self._patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                print(f"  [警告] 无效正则模式已跳过: {p}")

        # 输入级注入检测模式（仅用于拦截提示注入攻击）
        injection_pats = config.get("injection_patterns", [])
        self._injection_patterns = []
        for p in injection_pats:
            try:
                self._injection_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                print(f"  [警告] 无效注入检测模式已跳过: {p}")

    def filter_result(self, tool_name: str, result: str) -> tuple:
        """
        过滤工具返回内容中的疑似注入模式

        Args:
            tool_name: 工具名称（用于审计）
            result: 工具返回的原始字符串

        Returns:
            (filtered_result, was_filtered, patterns_hit)
            - filtered_result: 过滤后的字符串
            - was_filtered: 是否触发了过滤
            - patterns_hit: 命中的正则模式列表
        """
        if not result or not self._patterns:
            return result, False, []

        original_length = len(result)
        patterns_hit = []
        filtered_result = result

        for pattern in self._patterns:
            matches = pattern.findall(filtered_result)
            if matches:
                # 记录命中的模式原文
                patterns_hit.append(pattern.pattern)
                # 替换匹配内容为[FILTERED]
                filtered_result = pattern.sub("[FILTERED]", filtered_result)

        was_filtered = len(patterns_hit) > 0

        if self.audit:
            self.audit.log_data_filter(
                tool_name,
                original_length=original_length,
                filtered=was_filtered,
                patterns_hit=patterns_hit,
            )
            if was_filtered:
                self.audit.log_security_violation(
                    "data_pollution_detected",
                    f"工具 '{tool_name}' 返回内容中检测到注入模式: {patterns_hit}",
                )

        return filtered_result, was_filtered, patterns_hit

    def check_injection(self, text: str) -> tuple:
        """
        检查用户输入是否包含提示注入攻击（仅使用injection_patterns子集）

        Args:
            text: 用户输入文本

        Returns:
            (is_clean, patterns_hit)
        """
        patterns_hit = []
        for pattern in self._injection_patterns:
            if pattern.search(text):
                patterns_hit.append(pattern.pattern)
        return len(patterns_hit) == 0, patterns_hit

    def check_text(self, text: str) -> tuple:
        """
        检查文本是否包含注入模式（不替换，仅检测）

        Args:
            text: 待检查文本

        Returns:
            (is_clean, patterns_hit)
        """
        patterns_hit = []
        for pattern in self._patterns:
            if pattern.search(text):
                patterns_hit.append(pattern.pattern)
        return len(patterns_hit) == 0, patterns_hit
