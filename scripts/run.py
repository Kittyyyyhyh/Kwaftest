#!/usr/bin/env python3
"""
统一入口 — 探针 → 剪枝 → 生成 → 执行 → 报告
Skill 直接调这一个脚本即可

用法:
    python scripts/run.py --scenario cmdi                    # 完整流程(有缓存直接用)
    python scripts/run.py --scenario cmdi --probe-first       # 强制重新探针
    python scripts/run.py --scenario cmdi --probe-only        # 只跑探针
    python scripts/run.py --scenario cmdi --skip-execute      # 只生成不执行
    python scripts/run.py --scenario cmdi --quick             # 快速模式

输出:
    logs/probe_cache.json          — 探针缓存(自动复用)
    samples/batches/latest.jsonl   — 最新生成样本
    samples/results/latest.jsonl   — 最新执行结果
"""
import sys,os,json,argparse,time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(BASE, "logs", "probe_cache.json")
LATEST_BATCH = os.path.join(BASE, "samples", "batches", "latest.jsonl")
LATEST_RESULT = os.path.join(BASE, "samples", "results", "latest.jsonl")


def step_probe(scenario, force=False):
    """阶段一: 探针"""
    if not force and os.path.exists(CACHE):
        probes = json.load(open(CACHE, encoding="utf-8"))
        print(f"[probe] 使用缓存 ({len(probes)} 技法, {sum(len(v) for v in probes.values())} 格)")
        return probes

    print(f"[probe] 探测 {scenario}...")
    from probe import run as probe_run
    return probe_run(scenario, CACHE)


def step_generate(scenario, quick=False):
    """阶段二: 生成全矩阵"""
    print(f"[generate] 生成 {scenario} 矩阵...")
    sys.path.insert(0, BASE)
    from scripts.generate_matrix import _generate_from, load_json_file

    techs = load_json_file(os.path.join(BASE, "samples", "techniques", f"{scenario}.json"))
    targets = load_json_file(os.path.join(BASE, "samples", "targets", f"{scenario}.json"))

    samples, cells = _generate_from(techs, targets, scenario, waf="on", quick=quick)
    os.makedirs(os.path.dirname(LATEST_BATCH), exist_ok=True)
    with open(LATEST_BATCH, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"[generate] {cells} 格 × 编码 = {len(samples)} 条 → {LATEST_BATCH}")
    return LATEST_BATCH


def step_execute(batch_path):
    """阶段四: 执行"""
    print(f"[execute] 执行 {batch_path}...")
    # 清空上次结果
    if os.path.exists(LATEST_RESULT):
        os.remove(LATEST_RESULT)
    from execute_batch import execute_batch
    run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    execute_batch(batch_path, LATEST_RESULT, run_id=run_id, progress_every=30)
    return LATEST_RESULT


def step_report(result_path):
    """阶段五: 报告"""
    print(f"[report] 分析 {result_path}...")
    from lib.utils import read_jsonl
    results = list(read_jsonl(result_path))
    if not results:
        print("  (无结果)")
        return

    blocked = sum(1 for r in results if r.get("waf_blocked"))
    flags = sum(1 for r in results if r.get("attack_successful"))
    errors = sum(1 for r in results if r.get("error_message"))
    total = len(results)

    print(f"  {total} 条 | blocked={blocked} | flag={flags} | error={errors}")
    print(f"  绕过率: {round((total-blocked)/total*100,1) if total else 0}%")
    return results


def main():
    parser = argparse.ArgumentParser(description="WAF矩阵测试统一入口")
    parser.add_argument("--scenario", default="cmdi", help="场景")
    parser.add_argument("--probe-first", action="store_true", help="强制重新探针")
    parser.add_argument("--probe-only", action="store_true", help="只跑探针")
    parser.add_argument("--skip-execute", action="store_true", help="只生成不执行")
    parser.add_argument("--quick", action="store_true", help="快速模式")
    args = parser.parse_args()

    t0 = time.time()

    # 1. 探针
    probes = step_probe(args.scenario, force=args.probe_first)
    if args.probe_only:
        return

    # 2. 生成
    batch_path = step_generate(args.scenario, quick=args.quick)
    if args.skip_execute:
        print(f"\n[skip] 跳过执行. 样本: {batch_path}")
        return

    # 3. 执行
    result_path = step_execute(batch_path)

    # 4. 报告
    step_report(result_path)

    print(f"\n总耗时: {time.time()-t0:.0f}s")
    print(f"样本: {batch_path}")
    print(f"结果: {result_path}")


if __name__ == "__main__":
    main()
