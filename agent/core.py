"""
Agent核心调度模块
基于LangChain ReAct Agent，集成安全中间件
"""
import json
import os
from typing import Optional

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

from agent.prompts import build_system_prompt
from security.audit import AuditLogger
from tools.base import SecureToolWrapper


def _patch_tool_with_security(tool, security_wrapper: SecureToolWrapper) -> None:
    """
    猴子补丁：将工具的_run方法包装上安全校验链
    这样AgentExecutor调用tool.invoke()时会自动走安全检查
    用 _secure_patched 标记防止重复包装
    """
    if getattr(tool, "_secure_patched", False):
        return  # 已包装过，跳过

    original_run = tool._run

    def secure_run(*args, **kwargs):
        def execute_fn():
            return original_run(*args, **kwargs)
        result = security_wrapper.full_check_and_execute(
            tool.name, kwargs, execute_fn
        )
        if isinstance(result, dict):
            if result.get("security", {}).get("blocked"):
                reason = result["security"].get("reason", "安全拦截")
                return f"[安全拦截] {reason}"
            return str(result.get("data", ""))
        return str(result)

    tool._run = secure_run
    tool._secure_patched = True


class SecureAgent:
    """安全工具调用智能体"""

    def _create_llm(self, config: dict):
        """根据 provider 配置创建 LLM 实例"""
        provider = config.get("provider", "ollama")

        if provider == "openai":
            # OpenAI 兼容接口（含 DeepSeek、通义千问等）
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=config.get("model", "deepseek-chat"),
                temperature=config.get("temperature", 0),
                api_key=config.get("api_key", ""),
                base_url=config.get("base_url", "https://api.deepseek.com"),
            )
        else:
            # 默认 Ollama 本地部署
            from langchain_ollama import ChatOllama
            return ChatOllama(
                model=config.get("model", "qwen2.5:7b"),
                temperature=config.get("temperature", 0),
                base_url=config.get("base_url", "http://localhost:11434"),
            )

    def __init__(self, config, tools, security_wrapper=None, audit=None, security_enabled=True):
        self.config = config
        self.raw_tools = tools
        self.security_wrapper = security_wrapper
        self.audit = audit
        self.security_enabled = security_enabled
        self.max_iterations = config.get("max_iterations", 10)

        # 初始化LLM
        self.llm = self._create_llm(config)

        # 初始化工具映射
        self._tool_map = {tool.name: tool for tool in tools}

        # 构建Agent
        self._build_agent()

    def _wrap_tools(self, tools: list) -> None:
        """用安全中间件包装每个工具的_run方法（猴子补丁）"""
        if not self.security_wrapper:
            return
        for tool in tools:
            _patch_tool_with_security(tool, self.security_wrapper)

    def _build_agent(self) -> None:
        """构建LangChain Tool Calling Agent（利用模型原生function calling能力）"""
        system_prompt = build_system_prompt(self.raw_tools, include_security=self.security_enabled)

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        # 安全包装工具（猴子补丁_run方法）
        self._wrap_tools(self.raw_tools)

        # 使用模型原生 tool calling 能力
        llm_with_tools = self.llm.bind_tools(self.raw_tools)

        self.agent = create_tool_calling_agent(
            llm_with_tools,
            self.raw_tools,
            prompt,
        )

        self.executor = AgentExecutor(
            agent=self.agent,
            tools=self.raw_tools,
            max_iterations=self.max_iterations,
            verbose=True,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )

    def run(self, user_input: str, task_type: str = "query_task") -> dict:
        """
        执行Agent任务

        Args:
            user_input: 用户输入
            task_type: 任务类型（用于权限分配）

        Returns:
            {
                "output": "最终回答",
                "intermediate_steps": [...],  # 中间步骤
                "tool_calls": [...],          # 工具调用记录
                "security_events": [...]      # 安全事件记录
            }
        """
        # 审计：记录用户输入
        if self.audit:
            self.audit.log_user_input(user_input)

        try:
            result = self.executor.invoke({
                "input": user_input,
                "chat_history": [],
            })

            output = result.get("output", "")
            intermediate_steps = result.get("intermediate_steps", [])

            # 审计：记录Agent最终推理
            if self.audit:
                self.audit.log_agent_reasoning(output)

            # 提取工具调用记录
            tool_calls = []
            for step in intermediate_steps:
                if len(step) >= 2:
                    action, observation = step[0], step[1]
                    obs_str = str(observation)
                    blocked = "[安全拦截]" in obs_str
                    tool_calls.append({
                        "tool": getattr(action, "tool", "unknown"),
                        "arguments": getattr(action, "tool_input", {}),
                        "result": obs_str[:500],
                        "blocked": blocked,
                    })

            return {
                "output": output,
                "intermediate_steps": intermediate_steps,
                "tool_calls": tool_calls,
                "success": True,
            }

        except Exception as e:
            if self.audit:
                self.audit.log_security_violation("agent_error", str(e))
            return {
                "output": f"Agent执行出错: {str(e)}",
                "intermediate_steps": [],
                "tool_calls": [],
                "success": False,
                "error": str(e),
            }

    def run_with_security(self, user_input: str, task_type: str = "query_task") -> dict:
        """
        带完整安全管控的执行流程
        在标准run基础上，对每个工具调用插入安全检查

        注意：这里的安全检查通过SecureToolWrapper在工具_invoke层面实现
        此方法主要用于记录完整的安全审计链
        """
        result = self.run(user_input, task_type)

        # 统计安全事件
        security_summary = {
            "total_tool_calls": len(result["tool_calls"]),
            "security_enabled": self.security_enabled,
        }

        result["security_summary"] = security_summary
        return result
