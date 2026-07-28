"""
安全工具调用智能体系统 - 主入口
启动流程：ollama run qwen2.5:7b → py main.py --config config.yaml
"""
import argparse
import os
import sys
import yaml

from security.audit import AuditLogger
from security.whitelist import ToolWhitelist
from security.permission import PermissionManager
from security.human_confirm import HumanConfirm
from security.data_filter import DataFilter
from tools.base import SecureToolWrapper
from tools.file_read import FileReadTool
from tools.db_query import DbQueryTool
from tools.web_search import WebSearchTool
from tools.send_email import SendEmailTool
from tools.file_write import FileWriteTool
from tools.system_execute import SystemExecuteTool
from agent.core import SecureAgent


def load_config(config_path: str) -> dict:
    """加载YAML配置，支持环境变量覆盖API Key"""
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    # 环境变量 DEEPSEEK_API_KEY 优先于配置文件
    import os
    env_key = os.environ.get("DEEPSEEK_API_KEY")
    if env_key:
        config.setdefault("llm", {})["api_key"] = env_key
    return config


def create_tools(mock_data_dir: str) -> list:
    """创建Mock工具列表（6个工具，覆盖文件/通信/数据/系统四类场景）"""
    return [
        FileReadTool(mock_data_dir=mock_data_dir),
        FileWriteTool(),
        DbQueryTool(),
        WebSearchTool(),
        SendEmailTool(),
        SystemExecuteTool(),
    ]


def create_security_modules(config: dict, audit: AuditLogger) -> dict:
    """创建安全模块实例"""
    whitelist = ToolWhitelist(config, audit)
    permission = PermissionManager(config, audit)
    human_confirm = HumanConfirm(config.get("human_confirm", {}), audit)
    data_filter = DataFilter(config.get("data_filter", {}), audit)

    return {
        "whitelist": whitelist,
        "permission": permission,
        "human_confirm": human_confirm,
        "data_filter": data_filter,
    }


def create_secure_agent(
    config: dict, config_path: str, security_enabled: bool = True, task_type: str = "query_task"
) -> SecureAgent:
    """创建带安全中间件的Agent"""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    mock_data_dir = os.path.join(project_dir, "mock_data")
    tools = create_tools(mock_data_dir)

    # 审计日志
    audit_config = config.get("audit", {})
    audit_log_path = os.path.join(project_dir, audit_config.get("log_file", "audit_log.jsonl"))
    audit = AuditLogger(log_file=audit_log_path, enabled=audit_config.get("enabled", True))

    security_wrapper = None
    if security_enabled:
        sec_modules = create_security_modules(config, audit)
        sec_modules["whitelist"].set_config_path(config_path)
        sec_modules["permission"].set_session_permission(task_type)

        security_wrapper = SecureToolWrapper(
            whitelist=sec_modules["whitelist"],
            permission=sec_modules["permission"],
            human_confirm=sec_modules["human_confirm"],
            data_filter=sec_modules["data_filter"],
            audit=audit,
            security_enabled=True,
        )

    agent = SecureAgent(
        config=config.get("llm", {}),
        tools=tools,
        security_wrapper=security_wrapper,
        audit=audit,
        security_enabled=security_enabled,
    )

    return agent


def interactive_mode(config: dict, config_path: str) -> None:
    """交互式命令行模式"""
    llm_config = config.get("llm", {})
    provider = llm_config.get("provider", "ollama")
    model_name = llm_config.get("model", "qwen2.5:7b")
    provider_label = "DeepSeek API" if provider == "openai" else "Ollama本地"
    security_label = "已启用" if config.get("security", {}).get("enabled", True) else "已关闭"

    print("=" * 60)
    print("  安全工具调用智能体系统")
    print(f"  模型: {model_name} ({provider_label}) | 安全模块: {security_label}")
    print("  输入 'quit' 退出, 'security off/on' 切换安全模块")
    print("=" * 60)

    security_enabled = config.get("security", {}).get("enabled", True)
    task_type = "query_task"
    agent = create_secure_agent(config, config_path, security_enabled, task_type)

    # 创建独立的注入检测器（不依赖Agent实例，始终可用）
    audit_dummy = AuditLogger(log_file="", enabled=False)
    injection_detector = DataFilter(config.get("data_filter", {}), audit_dummy)

    while True:
        try:
            user_input = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            break
        if user_input.lower() == "security off":
            security_enabled = False
            agent = create_secure_agent(config, config_path, security_enabled, task_type)
            print("  安全模块已关闭")
            continue
        if user_input.lower() == "security on":
            security_enabled = True
            agent = create_secure_agent(config, config_path, security_enabled, task_type)
            print("  安全模块已启用")
            continue
        if user_input.lower().startswith("task "):
            task_type = user_input[5:].strip()
            agent = create_secure_agent(config, config_path, security_enabled, task_type)
            print(f"  任务类型切换为: {task_type}")
            continue

        # 输入级注入检测（仅安全模块启用时生效）
        if security_enabled:
            is_clean, hit_patterns = injection_detector.check_injection(user_input)
            if not is_clean:
                print("\n[安全拦截] 检测到提示注入攻击，已拦截以下模式：")
                for p in hit_patterns:
                    print(f"  - {p}")
                print("\n--- 安全摘要 ---")
                print(f"  安全模块: 启用 | 输入级拦截: 是")
                continue

        result = agent.run_with_security(user_input, task_type)

        print(f"\n--- 回答 ---")
        print(result["output"])

        if result["tool_calls"]:
            print(f"\n--- 工具调用记录 ({len(result['tool_calls'])}次) ---")
            for i, tc in enumerate(result["tool_calls"], 1):
                status = "✓" if not tc.get("blocked") else "✗ 已拦截"
                print(f"  {i}. {tc['tool']} {status}")

        if result.get("security_summary"):
            print(f"\n--- 安全摘要 ---")
            print(f"  安全模块: {'启用' if result['security_summary']['security_enabled'] else '关闭'}")


def main():
    parser = argparse.ArgumentParser(description="安全工具调用智能体系统")
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    parser.add_argument("--mode", choices=["interactive", "eval", "baseline", "camel", "protected"], default="interactive",
                       help="运行模式：interactive=交互, eval=三组对照评测, baseline=仅基线, camel=CaMeL式, protected=全防护")
    parser.add_argument("--test-cases", default="eval/test_cases.json", help="评测用例路径")

    args = parser.parse_args()

    # 解析配置路径
    if os.path.isabs(args.config):
        config_path = args.config
    else:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(project_dir, args.config)

    config = load_config(config_path)

    if args.mode == "interactive":
        interactive_mode(config, config_path)
    elif args.mode == "eval":
        # 三组对照评测
        config["human_confirm"]["auto_mode"] = True
        from eval.runner import EvalRunner
        import json, time
        test_cases_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.test_cases)
        runner = EvalRunner(config, config_path)
        report = runner.run_comparison(test_cases_path)
        # 保存结果并生成图表
        results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval", "results")
        os.makedirs(results_dir, exist_ok=True)
        output_file = os.path.join(results_dir, f"eval_result_{time.strftime('%Y%m%d_%H%M%S')}.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n结果已保存到: {output_file}")
        # 自动生成图表
        try:
            from eval.plot_results import (
                plot_tcr_asr_comparison, plot_svr_comparison,
                plot_tcc_comparison, plot_attack_breakdown, generate_summary_table,
            )
            charts_dir = os.path.join(results_dir, "charts")
            os.makedirs(charts_dir, exist_ok=True)
            print("\n自动生成可视化图表...")
            plot_tcr_asr_comparison(report, os.path.join(charts_dir, "tcr_asr_comparison.png"))
            plot_svr_comparison(report, os.path.join(charts_dir, "svr_comparison.png"))
            plot_tcc_comparison(report, os.path.join(charts_dir, "tcc_comparison.png"))
            plot_attack_breakdown(report, os.path.join(charts_dir, "attack_type_breakdown.png"))
            generate_summary_table(report, os.path.join(charts_dir, "summary_table.md"))
            print(f"图表已保存至: {charts_dir}/")
        except Exception as e:
            print(f"[警告] 图表生成失败（不影响评测结果）: {e}")
    elif args.mode in ("baseline", "camel", "protected"):
        config["human_confirm"]["auto_mode"] = True
        from eval.runner import EvalRunner
        import json, time
        test_cases_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.test_cases)
        runner = EvalRunner(config, config_path)
        report = runner.run_evaluation(test_cases_path, mode=args.mode)
        results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval", "results")
        os.makedirs(results_dir, exist_ok=True)
        output_file = os.path.join(results_dir, f"eval_result_{args.mode}_{time.strftime('%Y%m%d_%H%M%S')}.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n结果已保存到: {output_file}")


if __name__ == "__main__":
    main()
