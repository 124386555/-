"""
实验结果可视化脚本
读取 eval/results/ 下的评测结果 JSON，生成对比图表
用法：python eval/plot_results.py [result_file.json]
"""
import json
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "SimHei", "WenQuanYi Micro Hei", "DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False
except ImportError:
    print("[错误] 缺少 matplotlib，请安装: pip install matplotlib")
    sys.exit(1)


def load_result(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_latest_result(results_dir: str) -> str:
    """查找最新的评测结果文件"""
    if not os.path.isdir(results_dir):
        return ""
    files = [f for f in os.listdir(results_dir) if f.startswith("eval_result_") and f.endswith(".json")]
    if not files:
        return ""
    files.sort(reverse=True)
    return os.path.join(results_dir, files[0])


def plot_tcr_asr_comparison(results: dict, output_path: str) -> None:
    """
    绘制 TCR（任务完成率）和 ASR（攻击成功率）对比柱状图
    results: {"baseline": {...}, "camel": {...}, "protected": {...}}
    """
    modes = ["baseline", "camel", "protected"]
    labels = ["无防护基线", "CaMeL式防御", "全链路管控"]
    colors = ["#e74c3c", "#f39c12", "#2ecc71"]

    tcr_values = [results[m].get("tcr", 0) * 100 for m in modes]
    asr_values = [results[m].get("asr", 0) * 100 for m in modes]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # TCR 柱状图
    bars1 = axes[0].bar(labels, tcr_values, color=colors, edgecolor="white", width=0.6)
    axes[0].set_title("任务完成率 (TCR)", fontsize=14, fontweight="bold")
    axes[0].set_ylabel("完成率 (%)", fontsize=12)
    axes[0].set_ylim(0, 110)
    axes[0].yaxis.set_major_formatter(mticker.PercentFormatter())
    for bar, val in zip(bars1, tcr_values):
        axes[0].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                     f"{val:.1f}%", ha="center", va="bottom", fontsize=11)

    # ASR 柱状图
    bars2 = axes[1].bar(labels, asr_values, color=colors, edgecolor="white", width=0.6)
    axes[1].set_title("攻击成功率 (ASR) — 越低越好", fontsize=14, fontweight="bold")
    axes[1].set_ylabel("成功率 (%)", fontsize=12)
    axes[1].set_ylim(0, 110)
    axes[1].yaxis.set_major_formatter(mticker.PercentFormatter())
    for bar, val in zip(bars2, asr_values):
        axes[1].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                     f"{val:.1f}%", ha="center", va="bottom", fontsize=11)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ TCR/ASR 对比图已保存: {output_path}")


def plot_svr_comparison(results: dict, output_path: str) -> None:
    """绘制安全违规率对比图"""
    modes = ["baseline", "camel", "protected"]
    labels = ["无防护基线", "CaMeL式防御", "全链路管控"]
    colors = ["#e74c3c", "#f39c12", "#2ecc71"]

    svr_normal = [results[m].get("svr", {}).get("svr_normal", 0) * 100 for m in modes]
    svr_attack = [results[m].get("svr", {}).get("svr_attack", 0) * 100 for m in modes]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(labels))
    width = 0.35

    bars1 = ax.bar([i - width / 2 for i in x], svr_normal, width, label="正常集误拦率", color="#3498db", edgecolor="white")
    bars2 = ax.bar([i + width / 2 for i in x], svr_attack, width, label="攻击集漏拦率", color="#e67e22", edgecolor="white")

    ax.set_title("安全违规率 (SVR) 对比", fontsize=14, fontweight="bold")
    ax.set_ylabel("违规率 (%)", fontsize=12)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 110)

    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 1, f"{h:.1f}%", ha="center", va="bottom", fontsize=10)
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 1, f"{h:.1f}%", ha="center", va="bottom", fontsize=10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ SVR 对比图已保存: {output_path}")


def plot_tcc_comparison(results: dict, output_path: str) -> None:
    """绘制工具调用成本对比图"""
    modes = ["baseline", "camel", "protected"]
    labels = ["无防护基线", "CaMeL式防御", "全链路管控"]
    colors = ["#e74c3c", "#f39c12", "#2ecc71"]

    tcc_normal = [results[m].get("tcc", {}).get("tcc_normal", 0) for m in modes]
    tcc_attack = [results[m].get("tcc", {}).get("tcc_attack", 0) for m in modes]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(labels))
    width = 0.35

    ax.bar([i - width / 2 for i in x], tcc_normal, width, label="正常用例", color="#1abc9c", edgecolor="white")
    ax.bar([i + width / 2 for i in x], tcc_attack, width, label="攻击用例", color="#9b59b6", edgecolor="white")

    ax.set_title("工具调用成本 (TCC) 对比", fontsize=14, fontweight="bold")
    ax.set_ylabel("平均调用次数", fontsize=12)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.legend(fontsize=11)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ TCC 对比图已保存: {output_path}")


def plot_attack_breakdown(results: dict, output_path: str) -> None:
    """
    按攻击类型细分 ASR，展示各攻击面防护效果
    需要结果中包含每条用例的详细信息
    """
    protected = results.get("protected", {})
    baseline = results.get("baseline", {})

    # 如果结果包含 per_case 详情则用它，否则跳过
    if "per_case_results" not in protected:
        print("  ⚠ 结果中无 per_case_results，跳过攻击细分图")
        return

    attack_types = {
        "prompt_injection": "提示注入",
        "privilege_escalation": "权限越界",
        "data_leak": "数据泄露",
    }

    type_asr_baseline = {}
    type_asr_protected = {}

    for atype, alabel in attack_types.items():
        bl_cases = [c for c in baseline.get("per_case_results", [])
                    if c.get("type") == atype]
        pr_cases = [c for c in protected.get("per_case_results", [])
                    if c.get("type") == atype]

        bl_succ = sum(1 for c in bl_cases if c.get("attack_succeeded", False))
        pr_succ = sum(1 for c in pr_cases if c.get("attack_succeeded", False))

        type_asr_baseline[alabel] = (bl_succ / max(len(bl_cases), 1)) * 100
        type_asr_protected[alabel] = (pr_succ / max(len(pr_cases), 1)) * 100

    labels = list(attack_types.values())
    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(labels))
    width = 0.35

    ax.bar([i - width / 2 for i in x], [type_asr_baseline[l] for l in labels],
           width, label="无防护基线", color="#e74c3c", edgecolor="white")
    ax.bar([i + width / 2 for i in x], [type_asr_protected[l] for l in labels],
           width, label="全链路管控", color="#2ecc71", edgecolor="white")

    ax.set_title("各攻击类型 ASR 对比", fontsize=14, fontweight="bold")
    ax.set_ylabel("攻击成功率 (%)", fontsize=12)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 110)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ 攻击类型细分图已保存: {output_path}")


def generate_summary_table(results: dict, output_path: str) -> None:
    """生成 LaTeX / Markdown 格式的汇总表格"""
    modes = ["baseline", "camel", "protected"]
    mode_labels = {"baseline": "无防护基线", "camel": "CaMeL式防御", "protected": "全链路管控"}

    lines = []
    lines.append("| 指标 | 无防护基线 | CaMeL式防御 | 全链路管控 |")
    lines.append("|------|:----------:|:-----------:|:----------:|")

    tcr = [results[m].get("tcr", 0) for m in modes]
    asr = [results[m].get("asr", 0) for m in modes]
    svr_n = [results[m].get("svr", {}).get("svr_normal", 0) for m in modes]
    svr_a = [results[m].get("svr", {}).get("svr_attack", 0) for m in modes]
    tcc = [results[m].get("tcc", {}).get("tcc_overall", 0) for m in modes]

    lines.append(f"| TCR（任务完成率） | {tcr[0]:.1%} | {tcr[1]:.1%} | {tcr[2]:.1%} |")
    lines.append(f"| ASR（攻击成功率） | {asr[0]:.1%} | {asr[1]:.1%} | {asr[2]:.1%} |")
    lines.append(f"| SVR 正常集误拦率 | {svr_n[0]:.1%} | {svr_n[1]:.1%} | {svr_n[2]:.1%} |")
    lines.append(f"| SVR 攻击集漏拦率 | {svr_a[0]:.1%} | {svr_a[1]:.1%} | {svr_a[2]:.1%} |")
    lines.append(f"| TCC（平均调用次数） | {tcc[0]:.2f} | {tcc[1]:.2f} | {tcc[2]:.2f} |")

    # 计算提升幅度
    delta_asr = (asr[2] - asr[0]) * 100
    delta_tcr = (tcr[2] - tcr[0]) * 100

    lines.append("")
    lines.append(f"**全链路管控 vs 无防护基线：**")
    lines.append(f"- ASR 变化：{delta_asr:+.1f} 百分点")
    lines.append(f"- TCR 变化：{delta_tcr:+.1f} 百分点")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  ✓ 汇总表格已保存: {output_path}")


def main():
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eval", "results")
    charts_dir = os.path.join(results_dir, "charts")
    os.makedirs(charts_dir, exist_ok=True)

    # 确定输入文件
    if len(sys.argv) > 1:
        result_path = sys.argv[1]
    else:
        result_path = find_latest_result(results_dir)
        if not result_path:
            print(f"[错误] eval/results/ 下没有找到评测结果文件")
            print(f"  请先运行: python main.py --mode eval")
            sys.exit(1)

    print(f"读取结果: {result_path}")
    data = load_result(result_path)

    # 如果是三组对照格式（含 baseline/camel/protected 三个 key）
    if "baseline" in data and "camel" in data and "protected" in data:
        print("检测到三组对照结果，生成全套图表...\n")
        results = data
    else:
        # 单组结果，包装成字典
        mode = data.get("mode", "protected")
        results = {mode: data}

    plot_tcr_asr_comparison(results, os.path.join(charts_dir, "tcr_asr_comparison.png"))
    plot_svr_comparison(results, os.path.join(charts_dir, "svr_comparison.png"))
    plot_tcc_comparison(results, os.path.join(charts_dir, "tcc_comparison.png"))
    plot_attack_breakdown(results, os.path.join(charts_dir, "attack_type_breakdown.png"))
    generate_summary_table(results, os.path.join(charts_dir, "summary_table.md"))

    print(f"\n全部图表已生成至: {charts_dir}/")


if __name__ == "__main__":
    main()
