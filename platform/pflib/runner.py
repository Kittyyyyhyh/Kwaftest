"""远程批量测试编排 — 选样本 → 调 skill executor → 结果回写 corpus。"""
import sys
from pathlib import Path

from . import storage


def run_batch(cfg, *, scenario=None, category=None, status="pending", tag=None,
              limit=None, dry_run=False, run_id=None, concurrency=None, round_num=1):
    """从 corpus 选样本 → 远程实测 → 追加 tests → 重算 status。返回 (stats, run_id)。"""
    sd = storage.ensure_skill_import(cfg)
    from lib import util, executor
    samples, tests = storage.load_corpus(cfg)
    selected = storage.query_samples(samples, scenario=scenario, category=category,
                                     status=status, tag=tag, limit=limit)
    if not selected:
        from collections import Counter
        cur = Counter(s.get("status") for s in samples.values())
        print("[no samples selected] 过滤条件 scenario=%s category=%s status=%s limit=%s" %
              (scenario, category, status, limit))
        print("当前 corpus 状态构成: %s" % dict(cur))
        print("提示: 库中已无可测样本。先 `waf-cli corpus add` / `import` 新样本，"
              "或放宽 --status（如 --status passed 复测已确认样本）。")
        return {"total": 0, "skipped": True}, None
    print("selected %d samples to test" % len(selected))

    profile = executor.load_profile()
    target = executor.get_target(profile, cfg.get("default_target"))
    block_signals = profile.get("block_signals", {})
    rate_signals = profile.get("rate_limit_signals", {})
    tracking_headers = profile.get("tracking_headers")
    ex = profile.get("executor", {})
    concurrency = concurrency or ex.get("concurrency", 3)

    if dry_run:
        return {"total": len(selected), "dry_run": True}, None

    run_id = run_id or ("run_" + util.sha1_id(util.now_iso()))
    # 按场景分组（不同场景 param 名不同）
    tests_new = []
    by_scenario = {}
    for s in selected:
        by_scenario.setdefault(s["scenario"], []).append(s)
    for scen, items in by_scenario.items():
        param_name = target.get("params", {}).get(scen, "q")
        ts, stats = executor.execute_remote_batch(
            items, target, block_signals, rate_signals,
            concurrency=concurrency, min_interval_ms=ex.get("min_interval_ms", 300),
            jitter_ms=ex.get("jitter_ms", 150),
            timeout=ex.get("timeout_ms", 10000) / 1000.0, retries=ex.get("retries", 2),
            run_id=run_id, round_num=round_num, param_name=param_name,
            tracking_headers=tracking_headers)
        tests_new.extend(ts)
    util.append_jsonl(sd / "corpus" / "tests.jsonl", tests_new)

    # 重算 status 并落盘
    samples, tests = storage.load_corpus(cfg)
    changed = storage.derive_statuses(samples, tests)
    util.write_jsonl(sd / "corpus" / "samples.jsonl", list(samples.values()))
    print("statuses updated: %d changed | tests appended: %d" % (changed, len(tests_new)))

    from collections import Counter
    counter = Counter(t["result"]["waf_decision"] for t in tests_new)
    return dict(counter), run_id


def run_one(cfg, sample_id, dry_run=False):
    """单条样本实测。"""
    sd = storage.ensure_skill_import(cfg)
    from lib import util, executor
    samples, tests = storage.load_corpus(cfg)
    s = samples.get(sample_id)
    if not s:
        return {"error": "sample not found: %s" % sample_id}
    profile = executor.load_profile()
    target = executor.get_target(profile, cfg.get("default_target"))
    ex = profile.get("executor", {})
    param_name = target.get("params", {}).get(s["scenario"], "q")
    test = executor.execute_one(
        s, target=target, block_signals=profile.get("block_signals", {}),
        rate_signals=profile.get("rate_limit_signals", {}),
        timeout=ex.get("timeout_ms", 10000) / 1000.0, retries=ex.get("retries", 2),
        run_id="manual", round_num=0, param_name=param_name,
        tracking_headers=profile.get("tracking_headers"))
    if not dry_run:
        util.append_jsonl(sd / "corpus" / "tests.jsonl", [test])
        samples, tests = storage.load_corpus(cfg)
        storage.derive_statuses(samples, tests)
        util.write_jsonl(sd / "corpus" / "samples.jsonl", list(samples.values()))
    return test
