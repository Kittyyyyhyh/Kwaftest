"""
正交矩阵剪枝逻辑 — 两阶段探测-扩展 (Probe-then-Scale)

阶段一: 跑完矩阵所有单元格
阶段二: 按行(技法)和列(路径)分别剪枝

剪枝规则:
  规则A — 行剪枝: 如果某个技法在 P0/P1/P2 全被拦 → 技法被WAF识别 → 删除该行
  规则B — 列剪枝: 如果某个路径对所有技法都返回403 → 路径触发WAF → 删除该列
"""

from typing import List, Dict, Tuple


def probe_matrix(
    techniques: List[str],    # [";cat", "|cat", "||cat", ...]
    targets: List[Tuple[str, str]],  # [("P0-/etc/motd", "/etc/motd"), ...]
    probe_fn,                  # (technique, target_path) -> ProbeResult
) -> Dict[str, Dict[str, str]]:
    """
    运行全矩阵探测，返回 {technique: {target: result}}
    """
    matrix = {}
    for tech in techniques:
        matrix[tech] = {}
        for target_id, target_path in targets:
            matrix[tech][target_id] = probe_fn(tech, target_path)
    return matrix


def prune_matrix(
    matrix: Dict[str, Dict[str, str]],
    blocked_token: str = "BLOCKED",
) -> Tuple[List[str], List[str], Dict[str, Dict[str, str]]]:
    """
    剪枝矩阵，返回 (保留技法, 保留目标, 剪枝后矩阵)

    规则A — 行剪枝: 技法的所有目标都是 BLOCKED → 技法被WAF识别 → 移除
    规则B — 列剪枝: 目标的所有技法都是 BLOCKED → 路径被WAF保护 → 移除
    """
    techniques = list(matrix.keys())
    # 取所有技法的target并集（支持稀疏矩阵）
    targets = list(set().union(*[set(matrix[t].keys()) for t in techniques])) if techniques else []

    # 规则A: 行剪枝 — 全拦的技法（跳过None/空值）
    blocked_techs = set()
    for tech in techniques:
        results = [matrix[tech].get(t, "") for t in targets]
        results = [r for r in results if r]  # 跳过未测试
        if results and all(r == blocked_token for r in results):
            blocked_techs.add(tech)

    # 规则B: 列剪枝 — 全拦的路径
    blocked_targets = set()
    for target in targets:
        results = [matrix[t].get(target, "") for t in techniques]
        results = [r for r in results if r]
        if results and all(r == blocked_token for r in results):
            blocked_targets.add(target)

    # 构建剪枝后矩阵
    keep_techs = [t for t in techniques if t not in blocked_techs]
    keep_targets = [t for t in targets if t not in blocked_targets]

    pruned = {}
    for tech in keep_techs:
        pruned[tech] = {}
        for target in keep_targets:
            pruned[tech][target] = matrix[tech][target]

    return keep_techs, keep_targets, pruned


def format_matrix(
    matrix: Dict[str, Dict[str, str]],
    techniques: List[str],
    targets: List[str],
) -> str:
    """格式化矩阵为文本表格"""
    lines = []
    header = f'  {"技法":<10}'
    for t in targets:
        header += f' {t:<22}'
    lines.append(header)
    lines.append('  ' + '-' * (12 + 22 * len(targets)))

    for tech in techniques:
        row = f'  {tech:<10}'
        for target in targets:
            cell = matrix.get(tech, {}).get(target, "—")
            row += f' {cell:<22}'
        lines.append(row)
    return '\n'.join(lines)


def analyze_prune(
    probes: Dict[str, Dict[str, str]],
) -> dict:
    """
    完整剪枝分析流程，返回结构化报告
    """
    techniques = list(probes.keys())
    targets = list(set().union(*[set(probes[t].keys()) for t in techniques])) if techniques else []

    # 规则A分析（跳过 — 标记为未测试的格）
    tech_analysis = {}
    for tech in techniques:
        results = [probes[tech].get(t, "") for t in targets]
        results = [r for r in results if r]  # 跳过空值(未测试)
        blocked = sum(1 for r in results if r == "BLOCKED")
        tech_analysis[tech] = {
            "blocked_count": blocked,
            "total": len(results),
            "fully_blocked": blocked == len(results) and len(results) > 0,
        }

    # 规则B分析（同上）
    target_analysis = {}
    for target in targets:
        results = [probes[t].get(target, "") for t in techniques]
        results = [r for r in results if r]
        blocked = sum(1 for r in results if r == "BLOCKED")
        target_analysis[target] = {
            "blocked_count": blocked,
            "total": len(results),
            "fully_blocked": blocked == len(results) and len(results) > 0,
        }

    # 剪枝
    keep_techs, keep_targets, pruned = prune_matrix(probes)

    # 只计算有数据的单元格
    total_cells = sum(1 for t in techniques for tg in targets if probes[t].get(tg))
    kept_cells = sum(1 for t in keep_techs for tg in keep_targets if probes[t].get(tg))
    return {
        "total_cells": total_cells,
        "kept_cells": kept_cells,
        "saved_cells": total_cells - kept_cells,
        "removed_techniques": [t for t in techniques if t not in keep_techs],
        "removed_targets": [t for t in targets if t not in keep_targets],
        "tech_analysis": tech_analysis,
        "target_analysis": target_analysis,
        "pruned_matrix": pruned,
    }
