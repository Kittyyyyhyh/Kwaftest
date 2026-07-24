#!/usr/bin/env python3
"""
正交矩阵完整流程 — 探针 → 剪枝 → 生成 → 执行 → 报告

用法:
    python scripts/run_matrix.py                          # 完整流程
    python scripts/run_matrix.py --scenario cmdi          # 单场景
    python scripts/run_matrix.py --skip-probe             # 跳过探针(用缓存)
    python scripts/run_matrix.py --probe-only             # 只跑探针
"""
import sys,io,os,json,argparse,time
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.models import Seed, Sample
from lib.utils import read_jsonl, write_jsonl, load_json, save_json
from lib.transport import execute_sample
from lib.prune import analyze_prune

if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEEDS_DIR = os.path.join(BASE_DIR, "samples", "seeds")
ENCODINGS_FILE = os.path.join(BASE_DIR, "samples", "encodings", "recipes.json")
PROBE_CACHE = os.path.join(BASE_DIR, "logs", "probe_cache.json")


def load_seeds(scenarios=None):
    seeds = []
    for fname in os.listdir(SEEDS_DIR):
        if not fname.endswith('.json'): continue
        scenario = fname.replace('.json', '')
        if scenarios and scenario not in scenarios: continue
        data = load_json(os.path.join(SEEDS_DIR, fname))
        for item in data:
            seeds.append(Seed.from_dict(item))
    return seeds


def run_probes(seeds, run_id):
    """阶段一: 跑探针 (只测明文无编码)"""
    probes = defaultdict(dict)
    results = []

    for seed in seeds:
        transport = "api"
        if getattr(seed, 'verify_type', 'honeytoken') == 'output':
            transport = "direct"
        if seed.applicable_transports == ["direct"]:
            transport = "direct"
        if seed.scenario == "upload":
            transport = "upload_waf"

        sample_dict = {
            "sample_id": f"{seed.id}__probe",
            "seed_id": seed.id,
            "scenario": seed.scenario, "level": seed.level,
            "category": seed.category,
            "encoding_ids": [],
            "applied_payload": seed.payload,
            "transport": transport,
            "http_method": seed.http_method,
            "http_target": f"/{seed.scenario}/level{seed.level}.php",
            "url_params": seed.url_params,
            "verify_type": seed.verify_type,
            "verify_pattern": seed.verify_pattern,
            "expected_flag_pattern": seed.verify_pattern,
            "waf": "on",
            "filename": seed.filename,
            "content_type": seed.content_type,
            "extra_fields": seed.extra_fields,
        }

        r = execute_sample(sample_dict, run_id)
        results.append(r)

        # 记录到探针矩阵: 技法名 → 目标 → BLOCKED/FLAG/PASSED
        tech_name = seed.name.split(":")[0] if ":" in seed.name else seed.name[:25]
        if seed.scenario == "cmdi":
            # 提取分隔符和目标
            payload = seed.payload
            if payload.startswith(";cat"): sep = ";cat"
            elif payload.startswith(";whoami"): sep = ";whoami"
            elif payload.startswith(";id"): sep = ";id"
            elif payload.startswith("|cat"): sep = "|cat"
            elif payload.startswith("|whoami"): sep = "|whoami"
            elif payload.startswith("||cat"): sep = "||cat"
            elif payload.startswith("||whoami"): sep = "||whoami"
            elif payload.startswith("&&cat"): sep = "&&cat"
            elif payload.startswith("$(cat"): sep = "$(cat)"
            elif payload.startswith("$(whoami"): sep = "$(whoami)"
            elif payload.startswith("`cat"): sep = "`cat`"
            elif payload.startswith(";env"): sep = ";env"
            elif payload.startswith(";uname"): sep = ";uname"
            else: sep = seed.id[-15:]

            if "cat " in payload:
                path = payload.split("cat ", 1)[1]
                if "/etc/motd" in path: target = "P0-motd"
                elif "/etc/hostname" in path: target = "P0-host"
                elif "/srv/app/settings" in path: target = "P1-set"
                elif "/srv/app/data" in path: target = "P1-data"
                elif "/srv/data/db" in path: target = "P2-db"
                else: target = path[-20:]
            else:
                target = payload.split(";")[-1] if ";" in payload else payload

            probes[sep][target] = "BLOCKED" if r.get("waf_blocked") else (
                "FLAG" if r.get("attack_successful") else "PASSED"
            )

    return dict(probes), results


def main():
    parser = argparse.ArgumentParser(description="正交矩阵完整流程")
    parser.add_argument("--scenario", nargs="*", help="限定场景")
    parser.add_argument("--skip-probe", action="store_true", help="跳过探针(用缓存)")
    parser.add_argument("--probe-only", action="store_true", help="只跑探针")
    parser.add_argument("--cache", default=PROBE_CACHE, help="探针缓存路径")
    args = parser.parse_args()

    run_id = f"matrix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    seeds = load_seeds(args.scenario)

    # ================================================================
    # 阶段一: 探针
    # ================================================================
    probes = None
    if not args.skip_probe and os.path.exists(args.cache):
        probes = load_json(args.cache)
        print(f"📦 加载缓存探针: {args.cache}")

    if probes is None:
        print("═" * 80)
        print("  阶段一: 探针探测")
        print(f"  种子: {len(seeds)} 条 | 场景: {args.scenario or 'all'}")
        print("═" * 80)
        probes, probe_results = run_probes(seeds, run_id)

        # 保存探针缓存
        save_json(args.cache, probes)
        # 保存探针结果
        probe_out = os.path.join(BASE_DIR, "samples", "results", f"{run_id}_probes.jsonl")
        for r in probe_results:
            write_jsonl(probe_out, r)

        # 打印探针矩阵
        if probes:
            print()
            techniques = list(probes.keys())
            targets = list(probes[techniques[0]].keys())
            h = f'  {"":<10}'
            for t in targets: h += f' {t:<18}'
            print(h)
            print('  ' + '-' * (12 + 18 * len(targets)))
            for tech in techniques:
                row = f'  {tech:<10}'
                for target in targets:
                    row += f' {probes[tech].get(target, "—"):<18}'
                print(row)

    if args.probe_only:
        return

    # ================================================================
    # 阶段二: 剪枝
    # ================================================================
    print()
    print("═" * 80)
    print("  阶段二: 剪枝分析")
    print("═" * 80)

    if probes:
        analysis = analyze_prune(probes)
        print(f"  规则A(行-技法): 删除 {analysis['removed_techniques'] or '无'}")
        print(f"  规则B(列-路径): 删除 {analysis['removed_targets'] or '无'}")
        print(f"  成本: {analysis['total_cells']} → {analysis['kept_cells']} 次 "
              f"(节省 {analysis['saved_cells']} 次, {round(analysis['saved_cells']/analysis['total_cells']*100) if analysis['total_cells'] else 0}%)")
    else:
        print("  ⚠️ 无探针数据，跳过剪枝")

    # ================================================================
    # 阶段三: 快速生成+执行
    # ================================================================
    print()
    print("═" * 80)
    print("  阶段三: 生成+执行 (快速模式)")
    print("═" * 80)

    from generate_samples import generate_samples, generate_probes
    from lib.models import EncodingRecipe
    from execute_batch import execute_batch

    recipes = [EncodingRecipe.from_dict(r) for r in load_json(ENCODINGS_FILE)]
    batch_samples = generate_samples(seeds, recipes, waf="on", quick=True)

    batch_path = os.path.join(BASE_DIR, "samples", "batches", f"{run_id}.jsonl")
    for s in batch_samples:
        write_jsonl(batch_path, s)

    result_path = os.path.join(BASE_DIR, "samples", "results", f"{run_id}.jsonl")
    print(f"  样本: {len(batch_samples)} 条 → {batch_path}")
    execute_batch(batch_path, result_path, run_id=run_id, progress_every=30)

    print()
    print("═" * 80)
    print(f"  完成! 探针缓存: {args.cache}")
    print(f"  结果: {result_path}")
    print("═" * 80)


if __name__ == "__main__":
    main()
