#!/usr/bin/env python3
"""
正交矩阵生成器 — 技法 × 目标 × 编码 = 三维笛卡尔积

用法:
    python scripts/generate_matrix.py --scenario cmdi
    python scripts/generate_matrix.py --scenario cmdi --quick
    python scripts/generate_matrix.py --scenario cmdi --tier P1,P2
"""
import sys,io,os,json,argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.models import Sample
from scripts.lib.encoders import apply_encoding_chain, ENCODE_FUNCTIONS
from scripts.lib.utils import load_json, write_jsonl

if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_json_file(path):
    return load_json(path)


def _generate_from(techs: list, targets: list, scenario: str,
                   waf="on", quick=False, nested_depth=0) -> tuple:
    """技法 × 目标 × 编码 → (样本列表, 矩阵单元格数)"""
    recipes_data = load_json_file(os.path.join(BASE_DIR, "samples", "encodings", "recipes.json"))

    samples = []
    matrix_count = 0

    for tech in techs:
        for target in targets:
            # 检查level匹配: 技法levels包含目标的level
            tech_levels = tech.get("levels", [1])
            tgt_level = target.get("level", 1)
            if tgt_level not in tech_levels:
                continue

            # 构建payload
            payload = tech["template"].replace("{PAYLOAD}", target["payload"])

            # 验证
            check_type = target.get("success_on", {}).get("check", "response_contains")
            check_value = target.get("success_on", {}).get("value", "")

            # Transport: 非response_contains类型的用direct
            transport = "direct" if check_type != "response_contains" else "api"
            if tech["id"] in ("dollar", "backtick"):
                transport = "direct"

            matrix_count += 1

            # ---- 明文(无编码) ----
            seed_id = f"{scenario}-{tech['id']}-{target['id']}"
            s = Sample(
                sample_id=f"{seed_id}__none",
                seed_id=seed_id,
                scenario=scenario, level=1,
                category=tech["category"],
                encoding_ids=[],
                applied_payload=payload,
                transport=transport,
                http_method="GET",
                http_target=f"/{scenario}/level{target.get('level',1)}.php",
                url_params={target.get("url_param", "cmd" if scenario == "cmdi" else "id"): "${payload}"},
                verify_type=check_type,
                verify_pattern=check_value,
                success_on=target.get("success_on", {}),
                pre_setup=target.get("pre_setup", {}),
                waf=waf,
            )
            samples.append(s.to_dict())

            # ---- 编码样本 ----
            for recipe in recipes_data:
                if scenario not in recipe.get("applicable_scenarios", []):
                    continue
                if recipe["encode_function"] not in ENCODE_FUNCTIONS:
                    continue
                if quick and recipe["id"] not in ("url", "double_url", "base64_cmd", "hex_encoding"):
                    continue

                try:
                    encoded = apply_encoding_chain(payload, [recipe["encode_function"]])
                except Exception:
                    continue

                cat = "encoding_bypass" if tech["category"] == "baseline" else "combo"
                s = Sample(
                    sample_id=f"{seed_id}__{recipe['id']}",
                    seed_id=seed_id,
                    scenario=scenario, level=1,
                    category=cat,
                    encoding_ids=[recipe["id"]],
                    applied_payload=encoded,
                    transport="direct",  # 有编码必须direct
                    http_method="GET",
                    http_target=f"/{scenario}/level1.php",
                    url_params={"cmd" if scenario == "cmdi" else "id": "${payload}"},
                    verify_type=check_type,
                    verify_pattern=check_value,
                    waf=waf,
                )
                samples.append(s.to_dict())

            # ---- 嵌套编码 ----
            if nested_depth >= 1:
                nestable = [r for r in recipes_data if r.get("nestable") and scenario in r.get("applicable_scenarios", [])]
                for r1 in nestable:
                    for r2 in nestable:
                        if r1["id"] == r2["id"]: continue
                        if quick and r1["id"] not in ("url", "double_url"): continue
                        try:
                            encoded = apply_encoding_chain(payload, [r1["encode_function"], r2["encode_function"]])
                        except Exception:
                            continue
                        s = Sample(
                            sample_id=f"{seed_id}__{r1['id']}+{r2['id']}",
                            seed_id=seed_id,
                            scenario=scenario, level=1,
                            category="combo",
                            encoding_ids=[r1["id"], r2["id"]],
                            applied_payload=encoded,
                            transport="direct",
                            http_method="GET",
                            http_target=f"/{scenario}/level1.php",
                            url_params={"cmd": "${payload}"},
                            verify_type=check_type,
                            verify_pattern=check_value,
                            waf=waf,
                        )
                        samples.append(s.to_dict())

    return samples, matrix_count


def load_probe_cache(cache_path: str) -> dict:
    """加载探针缓存 {tech_id: {target_id: BLOCKED/FLAG/PASSED}}"""
    if not os.path.exists(cache_path):
        return {}
    return load_json(cache_path)


def apply_prune(techniques: list, targets: list, probes: dict) -> tuple:
    """剪枝: 删除全拦行和全拦列"""
    removed_techs = set()
    removed_targets = set()

    # 规则A: 技法在P0/P1/P2全拦 → 删行
    for tech in techniques:
        results = [probes.get(tech["id"], {}).get(t["id"], "") for t in targets]
        if results and all(r == "BLOCKED" for r in results):
            removed_techs.add(tech["id"])

    # 规则B: 目标在所有技法全拦 → 删列
    for target in targets:
        results = [probes.get(t["id"], {}).get(target["id"], "") for t in techniques]
        if results and all(r == "BLOCKED" for r in results):
            removed_targets.add(target["id"])

    keep_techs = [t for t in techniques if t["id"] not in removed_techs]
    keep_targets = [t for t in targets if t["id"] not in removed_targets]

    return keep_techs, keep_targets, removed_techs, removed_targets


def main():
    parser = argparse.ArgumentParser(description="正交矩阵生成器")
    parser.add_argument("--scenario", default="cmdi", help="场景")
    parser.add_argument("--output", default=None)
    parser.add_argument("--waf", default="on", choices=["on", "off"])
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--tier", help="逗号分隔tier,如 P0,P1")
    parser.add_argument("--nested-depth", type=int, default=0)
    parser.add_argument("--prune-cache", help="探针缓存路径,自动剪枝全拦行/列")
    args = parser.parse_args()

    tiers = args.tier.split(",") if args.tier else None

    if not args.output:
        args.output = os.path.join(BASE_DIR, "samples", "batches",
                                   f"matrix_{args.scenario}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")

    # 加载技法/目标
    techs = load_json_file(os.path.join(BASE_DIR, "samples", "techniques", f"{args.scenario}.json"))
    targets = load_json_file(os.path.join(BASE_DIR, "samples", "targets", f"{args.scenario}.json"))
    if tiers:
        targets = [t for t in targets if t["tier"] in tiers]

    # 剪枝
    if args.prune_cache:
        probes = load_probe_cache(args.prune_cache)
        if probes:
            keep_techs, keep_targets, removed_techs, removed_targets = apply_prune(techs, targets, probes)
            print(f"✂️  剪枝: 技法 {len(techs)}→{len(keep_techs)} (删 {removed_techs or '无'})")
            print(f"         目标 {len(targets)}→{len(keep_targets)} (删 {removed_targets or '无'})")
            saved = len(techs)*len(targets) - len(keep_techs)*len(keep_targets)
            print(f"         节省 {saved} 单元格 ({round(saved/(len(techs)*len(targets))*100) if len(techs)*len(targets) else 0}%)")
            techs = keep_techs
            targets = keep_targets
        else:
            print("⚠️  探针缓存为空，跳过剪枝")

    # 用剪枝后的技法/目标生成矩阵
    # 构造临时的 techniques/targets 文件内容传给 generate_matrix_impl
    samples, matrix_cells = _generate_from(techs, targets, args.scenario,
                                            waf=args.waf, quick=args.quick,
                                            nested_depth=args.nested_depth)

    for s in samples:
        write_jsonl(args.output, s)

    print(f"✅ 矩阵生成: {matrix_cells} 个单元格 (技法×目标)")
    print(f"   总样本: {len(samples)} 条 (含编码变体)")
    print(f"   → {args.output}")

    # 打印矩阵结构（用剪枝后的）
    print(f"\n  矩阵结构 ({len(techs)}×{len(targets)}):")
    header = "  " + "".join(f"{t['id']:<16}" for t in targets)
    print(header)
    print("  " + "-" * (16 * len(targets)))
    for tech in techs:
        row = f"  {tech['name']:<2}"
        row += "".join("  ●" for _ in targets)
        print(row)
    print(f"  ● = 1个单元格 (= 1条明文 + {len(samples)//matrix_cells - 1}条编码变体)")


if __name__ == "__main__":
    main()
