"""一轮完整机械循环：AI探针 → 入库(去重) → Layer2派生 → 远程执行 → 学习回写 → 摘要。

用法:
  python3 scripts/run_round.py --scenario sqli --input probes.jsonl [--dry-run] [--limit N]

输入 probes.jsonl 每行一个 AI 探针（须含 payload / mechanism.primitives / generation.reason，
否则被 AI 门禁拒绝）。AI 门禁是"生成质量"的第一道机械闸门：
  - payload 非空
  - mechanism.primitives 非空（必须归因一个绕过原语）
  - generation.reason 非空且≥20字符（必须写出为什么能绕）
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import schema  # noqa: E402
from lib import util  # noqa: E402
from lib import executor  # noqa: E402
from lib import generator  # noqa: E402
from lib import analysis  # noqa: E402

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
SAMPLES_PATH = CORPUS_DIR / "samples.jsonl"
TESTS_PATH = CORPUS_DIR / "tests.jsonl"


def ai_gate(probe: dict) -> list:
    """返回探针错误列表；空 = 通过门禁。"""
    errs = []
    payload = probe.get("payload")
    if isinstance(payload, dict):
        payload = payload.get("raw", "")
    if not isinstance(payload, str) or not payload.strip():
        errs.append("payload 为空")
    prims = (probe.get("mechanism") or {}).get("primitives", [])
    if not prims or not all(p.get("id") for p in prims):
        errs.append("mechanism.primitives 必须非空且含 id")
    reason = (probe.get("generation") or {}).get("reason", "")
    if not reason or len(reason) < 20:
        errs.append("generation.reason 必须非空且 ≥20 字符（写出为什么能绕）")
    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=schema.SCENARIOS)
    ap.add_argument("--input", required=True, help="AI 探针 JSONL")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--name", default=None, help="run_id")
    ap.add_argument("--derive", action="store_true", default=True,
                    help="是否对种子做 Layer2 模板派生（默认开）")
    ap.add_argument("--iterate-synonyms", type=int, default=0,
                    help="取 corpus 中该场景前 N 个已成功样本做同义近义迭代（skill 变强）")
    args = ap.parse_args()

    profile = executor.load_profile()
    target = executor.get_target(profile)
    block_signals = profile.get("block_signals", {})
    rate_signals = profile.get("rate_limit_signals", {})
    tracking_headers = profile.get("tracking_headers")
    ex = profile.get("executor", {})

    # 1. 读 AI 探针 + 门禁
    probes = util.read_jsonl(args.input)
    accepted, rejected = [], []
    for p in probes:
        errs = ai_gate(p)
        if errs:
            rejected.append({"payload": p.get("payload"), "errs": errs})
        else:
            accepted.append(p)
    print("AI probes: %d accepted, %d rejected by gate" % (len(accepted), len(rejected)))
    for r in rejected[:5]:
        print("  REJECT:", (r["payload"] if isinstance(r["payload"], str) else ""), r["errs"])

    # 2. 入库（去重）
    existing = schema.load_samples(SAMPLES_PATH)
    new_samples = []
    for p in accepted:
        rec = schema.build_sample_from_probe(p)
        if rec["sample_id"] in existing:
            continue
        existing[rec["sample_id"]] = rec
        new_samples.append(rec)

    # 3. Layer2 派生
    if args.derive:
        variants = generator.derive(new_samples, max_depth=2)
        for v in variants:
            if v["sample_id"] not in existing:
                existing[v["sample_id"]] = v
                new_samples.append(v)

    # 3.5 同义近义迭代（skill 变强）：对已成功样本派生新表达
    syn_count = 0
    if args.iterate_synonyms > 0:
        passed = sorted(
            [s for s in existing.values() if s.get("scenario") == args.scenario
             and s.get("status") in ("passed", "verifying")],
            key=lambda s: -{"high": 3, "medium": 2, "low": 1, "boundary_marker": 0}.get(
                s.get("quality", {}).get("overall", ""), 1))[:args.iterate_synonyms]
        for rec in generator.derive_success_iteration(passed):
            if rec["sample_id"] not in existing:
                existing[rec["sample_id"]] = rec
                new_samples.append(rec)
                syn_count += 1

    print("new samples: %d (AI %d + derived %d + synonym_iter %d)" % (
        len(new_samples), sum(1 for s in new_samples if s["generation"]["source"] == "ai"),
        sum(1 for s in new_samples if "template" in (s["generation"].get("template_ids") or []) and
            "synonym_mutation" not in (s["generation"].get("template_ids") or [])),
        syn_count))

    if args.dry_run or not new_samples:
        return

    # 4. 追加样本 + 远程执行
    util.append_jsonl(SAMPLES_PATH, new_samples)
    run_id = args.name or ("run_" + util.sha1_id(util.now_iso()))
    state = analysis.load_state()
    round_num = int(state.get("scenarios", {}).get(args.scenario, {}).get("round", 0)) + 1
    items = new_samples[:args.limit] if args.limit else new_samples
    tests, stats = executor.execute_remote_batch(
        items, target, block_signals, rate_signals,
        concurrency=ex.get("concurrency", 3), min_interval_ms=ex.get("min_interval_ms", 300),
        jitter_ms=ex.get("jitter_ms", 150), timeout=ex.get("timeout_ms", 10000) / 1000.0,
        retries=ex.get("retries", 2), run_id=run_id, round_num=round_num,
        param_name=target.get("params", {}).get(args.scenario, "q"),
        tracking_headers=tracking_headers)
    util.append_jsonl(TESTS_PATH, tests)

    # 5. 学习回写 + 状态同步 + 知识缺口自检
    analysis.recompute_state(existing, tests, state, args.scenario)
    sc = state["scenarios"][args.scenario]
    analysis.write_confirmed(existing, args.scenario, sc["confirmed_techniques"])
    gaps = analysis.compute_knowledge_gaps(existing, tests, state)
    merged = {g["scenario"] + "|" + g["signal"]: g
              for g in state.get("knowledge_gaps", [])}
    for g in gaps:
        merged[g["scenario"] + "|" + g["signal"]] = g
    state["knowledge_gaps"] = list(merged.values())
    analysis.save_state(state)
    analysis.sync_statuses(SAMPLES_PATH, TESTS_PATH)

    # 6. 摘要
    print(json.dumps({
        "run_id": run_id, "scenario": args.scenario, "round": sc["round"],
        "stats": stats,
        "confirmed_techniques": sc["confirmed_techniques"],
        "dead_primitives": sc["dead_primitives"][-5:],
        "pending_directions": sc["pending_directions"],
        "knowledge_gaps": state.get("knowledge_gaps", [])[:4],
        "top_dimensions": sorted(sc.get("dimension_stats", {}).items(),
                                 key=lambda kv: -kv[1]["pass_rate"])[:8],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
