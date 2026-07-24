#!/usr/bin/env python3
"""
样本生成器 — 种子 × 编码 = 笛卡尔积 → JSONL 批次文件

用法:
    # 全量生成（所有种子 × 所有编码，单层）
    python scripts/generate_samples.py --output samples/batches/batch_001.jsonl

    # 快速测试模式（精选种子 × 精选编码）
    python scripts/generate_samples.py --quick

    # 指定场景和嵌套深度
    python scripts/generate_samples.py --scenario cmdi --nested-depth 1

    # 仅WAF关（基准测试）
    python scripts/generate_samples.py --waf off
"""
import sys
import io
import os
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.models import Seed, EncodingRecipe, Sample
from lib.encoders import apply_encoding_chain, ENCODE_FUNCTIONS
from lib.utils import load_json, write_jsonl, count_lines

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEEDS_DIR = os.path.join(BASE_DIR, "samples", "seeds")
ENCODINGS_FILE = os.path.join(BASE_DIR, "samples", "encodings", "recipes.json")


def load_seeds(scenarios=None, levels=None, categories=None) -> list[Seed]:
    """加载种子文件"""
    seeds = []
    for fname in os.listdir(SEEDS_DIR):
        if not fname.endswith('.json'):
            continue
        scenario = fname.replace('.json', '')
        if scenarios and scenario not in scenarios:
            continue
        data = load_json(os.path.join(SEEDS_DIR, fname))
        for item in data:
            seed = Seed.from_dict(item)
            if levels and seed.level not in levels:
                continue
            if categories and seed.category not in categories:
                continue
            seeds.append(seed)
    return seeds


def load_encodings(scenarios=None) -> list[EncodingRecipe]:
    """加载编码配方"""
    data = load_json(ENCODINGS_FILE)
    recipes = []
    for item in data:
        recipe = EncodingRecipe.from_dict(item)
        if scenarios:
            # 检查是否至少有一个场景匹配
            overlap = set(recipe.applicable_scenarios) & set(scenarios)
            if not overlap:
                continue
        recipes.append(recipe)
    return recipes


def auto_select_transport(seed: Seed, encoding_ids: list[str]) -> str:
    """根据种子和编码自动选择传输模式"""
    # Upload 场景使用专用传输
    if seed.scenario == "upload":
        return "upload_waf"  # 默认 WAF ON，WAF OFF 用命令行 --waf off 切换

    # 有编码的样本必须用 direct 模式（避免 API urlencode 二次编码）
    if encoding_ids:
        return "direct"

    # output验证类型必须用direct（API只支持蜜标hp-xxx）
    if getattr(seed, 'verify_type', 'honeytoken') == 'output':
        return "direct"
    # 种子标记为 direct only
    if seed.applicable_transports == ["direct"]:
        return "direct"
    # 默认：无编码走 API
    return "api"


def resolve_target(scenario: str, level: int) -> str:
    """解析 HTTP 目标路径"""
    return f"/{scenario}/level{level}.php"


def generate_samples(seeds: list[Seed], recipes: list[EncodingRecipe],
                     waf: str = "on", nested_depth: int = 0,
                     quick: bool = False) -> list[dict]:
    """生成样本批次"""
    samples = []

    for seed in seeds:
        # ---- 无编码样本（baseline + semantic_bypass）----
        if seed.category in ("baseline", "semantic_bypass"):
            transport = auto_select_transport(seed, [])
            # Upload 用专用传输
            if seed.scenario == "upload":
                transport = "upload_direct" if waf == "off" else "upload_waf"

            s = Sample(
                sample_id=f"{seed.id}__none",
                seed_id=seed.id,
                scenario=seed.scenario,
                level=seed.level,
                category=seed.category,
                encoding_ids=[],
                applied_payload=seed.payload,
                transport=transport,
                http_method=seed.http_method,
                http_target=resolve_target(seed.scenario, seed.level),
                url_params=seed.url_params,
                expected_flag_pattern=seed.verify_pattern,
                verify_type=getattr(seed, 'verify_type', 'honeytoken'),
                verify_pattern=seed.verify_pattern,
                waf=waf,
                filename=seed.filename,
                content_type=seed.content_type,
                extra_fields=seed.extra_fields,
            )
            samples.append(s.to_dict())

        # ---- 编码样本（encoding_bypass + combo）----
        for recipe in recipes:
            # 快速模式下跳过非关键编码
            if quick and recipe.id not in ("url", "double_url", "base64_cmd", "hex_encoding"):
                continue

            if seed.scenario not in recipe.applicable_scenarios:
                continue

            # 无编码函数？跳过
            if recipe.encode_function not in ENCODE_FUNCTIONS:
                print(f"  ⚠ 编码函数 {recipe.encode_function} 未实现，跳过")
                continue

            try:
                encoded_payload = apply_encoding_chain(seed.payload, [recipe.encode_function])
            except Exception as e:
                print(f"  ⚠ 编码失败 {seed.id} × {recipe.id}: {e}")
                continue

            # 类别确定
            if seed.category == "baseline":
                new_category = "encoding_bypass"
            elif seed.category == "semantic_bypass":
                new_category = "combo"
            else:
                new_category = seed.category

            transport = auto_select_transport(seed, [recipe.id])
            if seed.scenario == "upload":
                transport = "upload_direct" if waf == "off" else "upload_waf"

            s = Sample(
                sample_id=f"{seed.id}__{recipe.id}",
                seed_id=seed.id,
                scenario=seed.scenario,
                level=seed.level,
                category=new_category,
                encoding_ids=[recipe.id],
                applied_payload=encoded_payload,
                transport=transport,
                http_method=seed.http_method,
                http_target=resolve_target(seed.scenario, seed.level),
                url_params=seed.url_params,
                expected_flag_pattern=seed.verify_pattern,
                verify_type=getattr(seed, 'verify_type', 'honeytoken'),
                verify_pattern=seed.verify_pattern,
                waf=waf,
                filename=seed.filename,
                content_type=seed.content_type,
                extra_fields=seed.extra_fields,
            )
            samples.append(s.to_dict())

        # ---- 嵌套编码（depth >= 1）----
        if nested_depth >= 1:
            nestable = [r for r in recipes if r.nestable and seed.scenario in r.applicable_scenarios]
            for r1 in nestable:
                for r2 in nestable:
                    if r1.id == r2.id:
                        continue
                    if quick and r1.id not in ("url", "double_url") and r2.id not in ("url", "double_url"):
                        continue

                    # 跳过无实现函数的
                    if r1.encode_function not in ENCODE_FUNCTIONS or r2.encode_function not in ENCODE_FUNCTIONS:
                        continue

                    try:
                        encoded = apply_encoding_chain(seed.payload,
                                                       [r1.encode_function, r2.encode_function])
                    except Exception:
                        continue

                    transport = "direct"  # 多层编码必须 direct
                    if seed.scenario == "upload":
                        continue  # Upload 暂不支持嵌套编码

                    s = Sample(
                        sample_id=f"{seed.id}__{r1.id}+{r2.id}",
                        seed_id=seed.id,
                        scenario=seed.scenario,
                        level=seed.level,
                        category="combo",
                        encoding_ids=[r1.id, r2.id],
                        applied_payload=encoded,
                        transport=transport,
                        http_method=seed.http_method,
                        http_target=resolve_target(seed.scenario, seed.level),
                        url_params=seed.url_params,
                        expected_flag_pattern=seed.expected_flag_pattern,
                        waf=waf,
                    )
                    samples.append(s.to_dict())

    return samples


def main():
    parser = argparse.ArgumentParser(description="WAF样本生成器")
    parser.add_argument("--seeds", default=SEEDS_DIR, help="种子目录")
    parser.add_argument("--encodings", default=ENCODINGS_FILE, help="编码配方文件")
    parser.add_argument("--output", default=None, help="输出批次文件路径")
    parser.add_argument("--scenario", nargs="*", help="限定场景 (sqli cmdi upload)")
    parser.add_argument("--level", type=int, nargs="*", help="限定关卡 (1-5)")
    parser.add_argument("--category", nargs="*", help="限定类别")
    parser.add_argument("--waf", default="on", choices=["on", "off"], help="WAF开关")
    parser.add_argument("--nested-depth", type=int, default=0, help="嵌套编码深度 (0=单层, 1=双层)")
    parser.add_argument("--quick", action="store_true", help="快速模式（精选种子×精选编码）")
    args = parser.parse_args()

    # 默认输出
    if not args.output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = os.path.join(BASE_DIR, "samples", "batches", f"batch_{ts}.jsonl")

    # 加载
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    seeds = load_seeds(args.scenario, args.level, args.category)
    recipes = load_encodings(args.scenario)

    print(f"📦 种子加载: {len(seeds)} 条")
    for s in seeds:
        print(f"   [{s.scenario}/L{s.level}] [{s.category}] {s.name}")
    print(f"📦 编码加载: {len(recipes)} 条")
    for r in recipes:
        print(f"   [{r.id}] {r.name} (nestable={r.nestable})")

    # 生成
    samples = generate_samples(seeds, recipes,
                               waf=args.waf, nested_depth=args.nested_depth,
                               quick=args.quick)

    # 写入
    for s in samples:
        write_jsonl(args.output, s)

    # 统计
    by_scenario = {}
    by_category = {}
    for s in samples:
        by_scenario[s["scenario"]] = by_scenario.get(s["scenario"], 0) + 1
        by_category[s["category"]] = by_category.get(s["category"], 0) + 1

    print(f"\n✅ 生成 {len(samples)} 条样本 → {args.output}")
    print(f"   按场景: {dict(by_scenario)}")
    print(f"   按类别: {dict(by_category)}")
    print(f"   WAF: {args.waf} | 嵌套深度: {args.nested_depth}")


if __name__ == "__main__":
    main()
