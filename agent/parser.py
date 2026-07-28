"""
模型输出容错解析器
处理7B模型tool calling格式不稳定的问题
多层fallback：标准解析 → 正则提取JSON → 跳过本轮
"""
import json
import re
from typing import Optional


class RobustToolCallParser:
    """容错工具调用解析器"""

    def __init__(self, valid_tool_names: list):
        """
        Args:
            valid_tool_names: 合法工具名称列表（用于校验）
        """
        self.valid_tool_names = valid_tool_names

    def parse(self, model_output: str) -> Optional[dict]:
        """
        尝试从模型输出中解析工具调用指令

        多层fallback：
        1. 直接尝试JSON解析（如果输出是纯JSON）
        2. 正则提取JSON块
        3. 正则提取Action/Action Input格式（ReAct标准格式）
        4. 返回None表示无法解析

        Args:
            model_output: 模型的原始文本输出

        Returns:
            {"tool": "tool_name", "arguments": {...}} 或 None
        """
        if not model_output or not model_output.strip():
            return None

        # Fallback 1: 直接JSON解析
        result = self._try_json_parse(model_output.strip())
        if result:
            return result

        # Fallback 2: 提取JSON代码块
        result = self._try_extract_json_block(model_output)
        if result:
            return result

        # Fallback 3: ReAct格式 Action: tool_name \n Action Input: {...}
        result = self._try_react_format(model_output)
        if result:
            return result

        # Fallback 4: 尝试匹配 tool_name + 参数的宽松格式
        result = self._try_loose_format(model_output)
        if result:
            return result

        return None

    def _try_json_parse(self, text: str) -> Optional[dict]:
        """尝试直接JSON解析"""
        try:
            data = json.loads(text)
            return self._normalize_tool_call(data)
        except (json.JSONDecodeError, TypeError):
            return None

    def _try_extract_json_block(self, text: str) -> Optional[dict]:
        """从文本中提取JSON代码块"""
        # 匹配 ```json ... ``` 或 ``` ... ``` 或直接 {...}
        patterns = [
            r'```json\s*(\{.*?\})\s*```',
            r'```\s*(\{.*?\})\s*```',
            r'(\{[^{}]*"tool"[^{}]*\})',
            r'(\{[^{}]*"name"[^{}]*\})',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(1))
                    result = self._normalize_tool_call(data)
                    if result:
                        return result
                except (json.JSONDecodeError, TypeError):
                    continue
        return None

    def _try_react_format(self, text: str) -> Optional[dict]:
        """解析ReAct标准格式"""
        action_match = re.search(r'Action:\s*(\w+)', text)
        input_match = re.search(r'Action Input:\s*(\{.*?\}|\S+)', text, re.DOTALL)

        if action_match:
            tool_name = action_match.group(1).strip()
            arguments = {}
            if input_match:
                input_str = input_match.group(1).strip()
                try:
                    arguments = json.loads(input_str)
                except json.JSONDecodeError:
                    # 可能是单个字符串参数
                    arguments = {"input": input_str.strip('"')}

            if self._is_valid_tool(tool_name):
                return {"tool": tool_name, "arguments": arguments}
        return None

    def _try_loose_format(self, text: str) -> Optional[dict]:
        """尝试宽松格式匹配"""
        for tool_name in self.valid_tool_names:
            if tool_name in text.lower():
                # 尝试提取参数
                args_match = re.search(r'\((.*?)\)', text)
                arguments = {}
                if args_match:
                    args_str = args_match.group(1)
                    try:
                        arguments = json.loads("{" + args_str + "}")
                    except json.JSONDecodeError:
                        # 尝试 key=value 格式
                        for pair in args_str.split(","):
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                arguments[k.strip()] = v.strip().strip('"')
                return {"tool": tool_name, "arguments": arguments}
        return None

    def _normalize_tool_call(self, data: dict) -> Optional[dict]:
        """将不同格式的JSON统一为标准格式"""
        if not isinstance(data, dict):
            return None

        # 尝试不同的key名称
        tool_name = (
            data.get("tool")
            or data.get("name")
            or data.get("tool_name")
            or data.get("function")
        )
        arguments = (
            data.get("arguments")
            or data.get("args")
            or data.get("parameters")
            or data.get("params")
            or data.get("input")
            or {}
        )

        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"input": arguments}

        if tool_name and self._is_valid_tool(tool_name):
            return {"tool": tool_name, "arguments": arguments}
        return None

    def _is_valid_tool(self, tool_name: str) -> bool:
        """检查工具名是否合法"""
        return tool_name in self.valid_tool_names
