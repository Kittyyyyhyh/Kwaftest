#!/usr/bin/env python3
"""
报告生成器 — 从 JSONL 结果文件生成多格式分析报告

用法:
    python scripts/report.py samples/results/run_001.jsonl
    python scripts/report.py samples/results/run_001.jsonl --format markdown
    python scripts/report.py samples/results/run_001.jsonl --format summary
"""
import sys
import io
import os
import json
import argparse
from datetime import datetime
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.utils import read_jsonl, count_lines

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def analyze(results: list[dict]) -> dict:
    """分析结果数据"""
    stats = {
        "total": len(results),
        "waf_on": [],
        "waf_off": [],
        "by_scenario": defaultdict(lambda: {"total": 0, "blocked": 0, "flag": 0, "success": 0}),
        "by_level": defaultdict(lambda: {"total": 0, "blocked": 0, "flag": 0}),
        "by_encoding": defaultdict(lambda: {"total": 0, "blocked": 0, "flag": 0}),
        "by_category": defaultdict(lambda: {"total": 0, "blocked": 0, "flag": 0}),
        "errors": [],
    }

    for r in results:
        waf_on = r.get("waf_enabled", True)
        scenario = r.get("scenario", "unknown")
        level = r.get("level", 0)
        blocked = r.get("waf_blocked", False)
        flag = r.get("flag_captured")
        success = r.get("attack_successful", False)
        encoding_ids = r.get("encoding_ids", [])
        category = r.get("category", "")
        error = r.get("error_message")

        if waf_on:
            stats["waf_on"].append(r)
        else:
            stats["waf_off"].append(r)

        # 按场景
        s_key = scenario
        stats["by_scenario"][s_key]["total"] += 1
        if blocked:
            stats["by_scenario"][s_key]["blocked"] += 1
        if flag:
            stats["by_scenario"][s_key]["flag"] += 1
        if success:
            stats["by_scenario"][s_key]["success"] += 1

        # 按关卡
        l_key = f"{scenario}/L{level}"
        stats["by_level"][l_key]["total"] += 1
        if blocked:
            stats["by_level"][l_key]["blocked"] += 1
        if flag:
            stats["by_level"][l_key]["flag"] += 1

        # 按编码
        if encoding_ids:
            for eid in encoding_ids:
                stats["by_encoding"][eid]["total"] += 1
                if blocked:
                    stats["by_encoding"][eid]["blocked"] += 1
                if flag:
                    stats["by_encoding"][eid]["flag"] += 1
        else:
            stats["by_encoding"]["none"]["total"] += 1
            if blocked:
                stats["by_encoding"]["none"]["blocked"] += 1
            if flag:
                stats["by_encoding"]["none"]["flag"] += 1

        # 按类别
        if category:
            stats["by_category"][category]["total"] += 1
            if blocked:
                stats["by_category"][category]["blocked"] += 1
            if flag:
                stats["by_category"][category]["flag"] += 1

        if error:
            stats["errors"].append(r)

    return stats


def report_summary(results: list[dict], stats: dict) -> str:
    """纯文本摘要"""
    waf_on = stats["waf_on"]
    waf_off = stats["waf_off"]
    waf_on_blocked = sum(1 for r in waf_on if r.get("waf_blocked"))
    waf_on_flag = sum(1 for r in waf_on if r.get("flag_captured"))
    waf_off_flag = sum(1 for r in waf_off if r.get("flag_captured"))
    bypass_rate = round((len(waf_on) - waf_on_blocked) / len(waf_on) * 100, 1) if waf_on else 0

    lines = [
        "=" * 70,
        "  WAF 靶场攻击测试报告",
        f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  总样本数: {stats['total']}",
        "=" * 70,
        "",
        f"  WAF OFF 基准: {len(waf_off)} 次, {waf_off_flag} 拿flag",
        f"  WAF ON  实战: {len(waf_on)} 次, {waf_on_flag} 拿flag",
        f"  WAF 拦截:     {waf_on_blocked}/{len(waf_on)} ({round(waf_on_blocked/len(waf_on)*100,1)}%)" if waf_on else "",
        f"  WAF 绕过率:   {bypass_rate}%",
        f"  错误:         {len(stats['errors'])}",
        "",
        "  ── 按场景 ──",
    ]

    for scenario in ["sqli", "cmdi", "upload"]:
        s = stats["by_scenario"].get(scenario)
        if s and s["total"] > 0:
            rate = round((s["total"] - s["blocked"]) / s["total"] * 100, 1)
            lines.append(f"  {scenario:6s}: {s['total']:3d}次 | blocked={s['blocked']:2d} | flag={s['flag']:2d} | bypass={rate}%")

    lines += ["", "  ── 按编码 ──"]
    for eid, s in sorted(stats["by_encoding"].items(), key=lambda x: x[1]["total"], reverse=True):
        if s["total"] > 0:
            rate = round((s["total"] - s["blocked"]) / s["total"] * 100, 1)
            lines.append(f"  {eid:15s}: {s['total']:3d}次 | blocked={s['blocked']:2d} | flag={s['flag']:2d} | bypass={rate}%")

    lines += ["", "  ── 按类别 ──"]
    for cat, s in sorted(stats["by_category"].items()):
        if s["total"] > 0:
            rate = round((s["total"] - s["blocked"]) / s["total"] * 100, 1)
            lines.append(f"  {cat:20s}: {s['total']:3d}次 | blocked={s['blocked']:2d} | flag={s['flag']:2d} | bypass={rate}%")

    # 成功绕过详情
    successes = [r for r in waf_on if r.get("attack_successful")]
    if successes:
        lines += ["", "  ── 成功绕过详情 ──"]
        for r in successes[:20]:
            enc = "+".join(r.get("encoding_ids", [])) or "none"
            lines.append(f"  ✅ {r['scenario']}/L{r['level']}: {r.get('flag_captured','')} (enc={enc})")

    if stats["errors"]:
        lines += ["", f"  ⚠️ 错误: {len(stats['errors'])} 条"]

    lines += ["", "=" * 70]
    return "\n".join(lines)


def report_markdown(results: list[dict], stats: dict) -> str:
    """Markdown 格式报告"""
    summary = report_summary(results, stats)
    # 简单转换：保留原样，后续可增强为真正的 Markdown 表格
    return f"# WAF 靶场攻击测试报告\n\n```\n{summary}\n```"


def report_json(results: list[dict], stats: dict) -> str:
    """JSON 格式"""
    return json.dumps(stats, ensure_ascii=False, indent=2, default=str)


FORMATTERS = {
    "summary": report_summary,
    "markdown": report_markdown,
    "json": report_json,
}


def main():
    parser = argparse.ArgumentParser(description="WAF结果报告生成器")
    parser.add_argument("results", help="结果 JSONL 文件")
    parser.add_argument("--format", default="summary", choices=["summary", "markdown", "json"])
    parser.add_argument("--output", default=None, help="输出文件路径")
    args = parser.parse_args()

    results = list(read_jsonl(args.results))
    if not results:
        print("❌ 结果文件为空或不存在")
        return

    stats = analyze(results)
    formatter = FORMATTERS.get(args.format, report_summary)
    output = formatter(results, stats)

    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"📁 报告已保存: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
