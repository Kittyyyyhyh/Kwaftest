#!/usr/bin/env python3
"""
WAF 靶场攻击测试报告生成器
从 samples.csv 读取数据，生成 Markdown 格式的攻击报告

用法:
    python scripts/generate_report.py [--csv logs/samples.csv] [--output reports/report.md]
"""

import csv
import json
import os
import sys
import io
from datetime import datetime
from collections import defaultdict, Counter

# Fix Windows GBK encoding issue
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CSV = os.path.join(BASE_DIR, 'logs', 'samples.csv')
DEFAULT_OUTPUT = os.path.join(BASE_DIR, 'reports', f'report_{datetime.now().strftime("%Y-%m-%d")}.md')


def parse_csv(csv_path):
    """解析 samples.csv"""
    samples = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                samples.append(row)
    except FileNotFoundError:
        print(f"❌ CSV 文件不存在: {csv_path}")
        print("   请先运行攻击测试（curl 手动测试或 API 批量测试）")
        sys.exit(1)
    return samples


def analyze(samples):
    """分析样本数据"""
    stats = {
        'total': len(samples),
        'by_scenario': defaultdict(lambda: {'total': 0, 'blocked': 0, 'passed': 0, 'passed_flag': 0}),
        'by_level': defaultdict(lambda: {'total': 0, 'blocked': 0, 'passed': 0, 'passed_flag': 0}),
        'by_encoding': defaultdict(lambda: {'total': 0, 'blocked': 0, 'passed_flag': 0}),
        'waf_rules': Counter(),
        'bypass_samples': [],
        'waf_on_total': 0,
        'waf_on_passed': 0,
    }

    for s in samples:
        scenario = s.get('scenario', 'unknown')
        level = s.get('level', 'unknown')
        result = s.get('result', 'unknown')
        waf = s.get('waf', 'on')
        encoding = s.get('encoding', 'none')
        rule_id = s.get('waf_rule_id', '')
        flag = s.get('flag', '')

        # 场景统计
        stats['by_scenario'][scenario]['total'] += 1
        if result == 'blocked':
            stats['by_scenario'][scenario]['blocked'] += 1
        elif result in ('passed_flag', 'passed_noflag'):
            stats['by_scenario'][scenario]['passed'] += 1
        if result == 'passed_flag':
            stats['by_scenario'][scenario]['passed_flag'] += 1

        # 关卡统计
        level_key = f"{scenario}/{level}"
        stats['by_level'][level_key]['total'] += 1
        if result == 'blocked':
            stats['by_level'][level_key]['blocked'] += 1
        elif result in ('passed_flag', 'passed_noflag'):
            stats['by_level'][level_key]['passed'] += 1
        if result == 'passed_flag':
            stats['by_level'][level_key]['passed_flag'] += 1

        # 编码统计
        stats['by_encoding'][encoding]['total'] += 1
        if result == 'blocked':
            stats['by_encoding'][encoding]['blocked'] += 1
        if result == 'passed_flag':
            stats['by_encoding'][encoding]['passed_flag'] += 1

        # 规则统计
        if rule_id and rule_id != '-':
            stats['waf_rules'][rule_id] += 1

        # 绕过样本
        if waf == 'on' and result == 'passed_flag' and flag and flag != '-':
            stats['bypass_samples'].append(s)

        # WAF 开启统计
        if waf == 'on':
            stats['waf_on_total'] += 1
            if result in ('passed_flag', 'passed_noflag'):
                stats['waf_on_passed'] += 1

    stats['bypass_rate'] = round(stats['waf_on_passed'] / stats['waf_on_total'] * 100, 1) if stats['waf_on_total'] > 0 else 0
    return stats


def generate_report(samples, stats, output_path):
    """生成 Markdown 报告"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    report = f"""# WAF 靶场攻击测试报告

> 生成时间: {now}
> WAF: OWASP ModSecurity CRS Paranoia Level 4
> 靶场: PHP-Apache (SQL注入 + 命令注入 + 文件上传)

---

## 一、总体统计

| 指标 | 数值 |
|------|------|
| 总攻击次数 | {stats['total']} |
| WAF 开启次数 | {stats['waf_on_total']} |
| WAF 拦截次数 | {stats['waf_on_total'] - stats['waf_on_passed']} |
| 绕过 WAF 次数 | {stats['waf_on_passed']} |
| **WAF 绕过率** | **{stats['bypass_rate']}%** |
| 成功拿 flag 次数 | {sum(1 for s in samples if s.get('result') == 'passed_flag')} |

### 四类样本统计

| 样本类型 | 数量 | 说明 |
|----------|------|------|
| ① 完整过程用例 (WAF关) | {sum(1 for s in samples if s.get('waf') == 'off' and s.get('result') == 'passed_flag')} | 明文攻击成功 |
| ② 语义层 bypass | {sum(1 for s in stats['bypass_samples'] if s.get('encoding') == 'none')} | 语义变形绕过 |
| ③ 编码层 bypass | {sum(1 for s in stats['bypass_samples'] if s.get('encoding') != 'none')} | 编码变形绕过 |
| ④ 组合 bypass | 待分类 | 语义×编码组合 |

---

## 二、按场景统计

| 场景 | 总攻击 | 被拦截 | 通过WAF | 成功拿flag | 绕过率 |
|------|--------|--------|---------|------------|--------|
"""

    scenario_names = {'sqli': 'SQL注入', 'cmdi': '命令注入', 'upload': '文件上传'}
    for key, name in scenario_names.items():
        s = stats['by_scenario'].get(key, {'total': 0, 'blocked': 0, 'passed': 0, 'passed_flag': 0})
        rate = round((s['passed'] / s['total'] * 100), 1) if s['total'] > 0 else 0
        report += f"| {name} | {s['total']} | {s['blocked']} | {s['passed']} | {s['passed_flag']} | {rate}% |\n"

    report += "\n---\n\n## 三、按关卡统计\n\n"
    report += "| 场景/关卡 | 总攻击 | 被拦截 | 通过WAF | 成功flag | 绕过率 |\n"
    report += "|-----------|--------|--------|---------|----------|--------|\n"

    for level_key in sorted(stats['by_level'].keys()):
        s = stats['by_level'][level_key]
        rate = round((s['passed'] / s['total'] * 100), 1) if s['total'] > 0 else 0
        flag_icon = '✅' if s['passed_flag'] > 0 else '⬜'
        report += f"| {level_key} | {s['total']} | {s['blocked']} | {s['passed']} | {s['passed_flag']} {flag_icon} | {rate}% |\n"

    report += "\n---\n\n## 四、触发规则排行 (Top 10)\n\n"
    report += "| 规则 ID | 触发次数 | 占比 |\n"
    report += "|---------|----------|------|\n"

    total_blocks = sum(stats['waf_rules'].values())
    for rule_id, count in stats['waf_rules'].most_common(10):
        pct = round(count / total_blocks * 100, 1) if total_blocks > 0 else 0
        bar = '█' * int(pct / 5)
        report += f"| {rule_id} | {count} | {pct}% {bar} |\n"

    report += "\n---\n\n## 五、编码绕过统计\n\n"
    report += "| 编码方式 | 总攻击 | 被拦截 | 成功flag | 绕过率 |\n"
    report += "|----------|--------|--------|----------|--------|\n"

    for enc, s in sorted(stats['by_encoding'].items(), key=lambda x: x[1]['total'], reverse=True):
        rate = round(((s['total'] - s['blocked']) / s['total'] * 100), 1) if s['total'] > 0 else 0
        report += f"| {enc} | {s['total']} | {s['blocked']} | {s['passed_flag']} | {rate}% |\n"

    report += "\n---\n\n## 六、成功绕过样本 (Top 20)\n\n"

    # 去重并按场景排列
    seen = set()
    unique_bypass = []
    for s in stats['bypass_samples']:
        key = (s.get('scenario'), s.get('level'), s.get('payload', '')[:50])
        if key not in seen:
            seen.add(key)
            unique_bypass.append(s)

    report += "| 场景 | 关卡 | Payload (截断) | 编码 | Flag |\n"
    report += "|------|------|---------------|------|------|\n"

    for s in unique_bypass[:20]:
        payload_preview = s.get('payload', '')[:60].replace('|', '\\|')
        report += f"| {s.get('scenario')} | {s.get('level')} | `{payload_preview}...` | {s.get('encoding', 'none')} | `{s.get('flag', '-')[:30]}` |\n"

    report += f"""
---

## 七、关键发现

1. **WAF 最有效的检测规则**: 规则 `{stats['waf_rules'].most_common(1)[0][0] if stats['waf_rules'] else 'N/A'}` 触发了最多拦截
2. **最容易绕过的场景**: 待分析
3. **最难绕过的场景**: 待分析
4. **最有效的编码方式**: 待分析
5. **语义绕过 vs 编码绕过**: 待对比分析

---

> 🤖 本报告由 generate_report.py 自动生成
> 📊 原始数据: logs/samples.csv
> 🎯 靶场: OWASP ModSecurity CRS PL4 + PHP-Apache
"""

    # 写入文件
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    return report


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV
    output_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT

    print(f"📊 读取样本数据: {csv_path}")
    samples = parse_csv(csv_path)
    print(f"📋 共 {len(samples)} 条攻击记录")

    print("🔍 分析中...")
    stats = analyze(samples)

    print(f"📝 生成报告: {output_path}")
    generate_report(samples, stats, output_path)

    print(f"""
✅ 报告生成完成!

📈 关键数据:
   总攻击: {stats['total']} 次
   绕过率: {stats['bypass_rate']}%
   拿flag: {sum(1 for s in samples if s.get('result') == 'passed_flag')} 次

📁 报告位置: {output_path}
""")


if __name__ == '__main__':
    main()
