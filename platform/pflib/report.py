"""统计报表 — 已确认样本集构成 / 原语覆盖 / 有效样本 / WAF UUID。

注意：corpus 经整理后只保留"远程实测通过"的样本，因此绕过率恒为 100%。
本报表以"已确认样本集"为口径呈现构成（场景/类别/原语覆盖/有效样本），
不再表述为一次测试扫描的通过率。
"""
from collections import Counter, defaultdict

from . import storage


def build_stats(cfg) -> dict:
    samples, tests = storage.load_corpus(cfg)
    total = len(samples)
    # 每个样本的最新判定（用于标记；通过样本的判定均为 passed）
    latest = {}
    for t in tests:
        latest.setdefault(t["sample_id"], t)
    decided = {}
    for sid, t in latest.items():
        if sid in samples:
            decided[sid] = t["result"]["waf_decision"]
    passed = sum(1 for d in decided.values() if d == "passed")
    tested = len(decided)
    confirmed_rate = round(passed / tested * 100, 1) if tested else 0.0

    # 唯一 payload 数（同 payload×不同原语 → 独立样本，这里按字面量去重计数）
    unique_payloads = len({(s["payload"]["raw"], s["scenario"]) for s in samples.values()})

    # 已确认技法数（knowledge/confirmed_techniques.jsonl）
    confirmed_count = 0
    sd = storage.ensure_skill_import(cfg)
    try:
        from lib import util as _u
        confirmed_count = len(_u.read_jsonl(sd / "knowledge" / "confirmed_techniques.jsonl"))
    except Exception:
        confirmed_count = 0

    # 场景维度
    by_scenario = defaultdict(lambda: {"count": 0, "passed": 0})
    for sid, s in samples.items():
        sc = s["scenario"]
        by_scenario[sc]["count"] += 1
        if decided.get(sid) == "passed":
            by_scenario[sc]["passed"] += 1

    # 类别占比
    by_category = Counter(s["category"] for s in samples.values())

    # 主原语维度（覆盖计数，非通过率——集内全部通过）
    dim = defaultdict(lambda: {"count": 0})
    for sid, s in samples.items():
        prims = (s.get("mechanism") or {}).get("primitives", [])
        prim = prims[-1].get("id", "none") if prims else "none"
        dim[prim]["count"] += 1
    top_dimensions = sorted(dim.items(), key=lambda kv: kv[1]["count"], reverse=True)[:15]

    # 有效样本（已通过 WAF，按危害排序）
    eff_samples = []
    for sid, s in samples.items():
        if decided.get(sid) == "passed":
            eff_samples.append({
                "sample_id": sid, "scenario": s["scenario"], "category": s["category"],
                "payload": s["payload"]["raw"], "primitives": [p["id"] for p in s["mechanism"]["primitives"]],
                "overall": s["quality"].get("overall", ""),
            })
    eff_samples.sort(key=lambda x: (x["overall"], x["payload"]))

    # WAF UUID
    uuids = set()
    for t in tests:
        u = (t.get("result") or {}).get("block_signals", {}).get("x_waf_uuid")
        if u:
            uuids.add(u)

    return {
        "total_samples": total, "unique_payloads": unique_payloads,
        "tested": tested, "passed": passed, "blocked": tested - passed,
        "confirmed_rate_pct": confirmed_rate, "confirmed_techniques": confirmed_count,
        "by_scenario": {k: dict(v) for k, v in by_scenario.items()},
        "by_category": dict(by_category),
        "top_dimensions": [{"primitive": k, **v} for k, v in top_dimensions],
        "effective_samples": eff_samples,
        "distinct_waf_uuids": len(uuids),
    }


def render_markdown(stats) -> str:
    L = []
    L.append("# WAF 语义测试样本集（已确认：远程实测全部通过）\n")
    L.append("## 总览\n")
    L.append("| 指标 | 值 |\n|---|---|")
    L.append("| 样本总数 | %d |" % stats["total_samples"])
    L.append("| 唯一 payload 数 | %d |" % stats["unique_payloads"])
    L.append("| 已实测 | %d |" % stats["tested"])
    L.append("| 已确认通过(WAF放行) | %d |" % stats["passed"])
    L.append("| **样本集通过率** | **%.1f%%** |" % stats["confirmed_rate_pct"])
    L.append("| 已确认技法 | %d |" % stats["confirmed_techniques"])
    L.append("| 不同 WAF UUID | %d |" % stats["distinct_waf_uuids"])
    L.append("\n> 口径：corpus 只保留远程实测通过（HTTP 200 / waf_decision=passed）的样本，"
             "通过率恒为 100%。本报表描述样本集构成，不再是一次测试扫描的通过率统计。\n")
    L.append("\n## 场景维度\n")
    L.append("| 场景 | 样本数 | 已确认通过 |\n|---|---|---|")
    for sc, v in sorted(stats["by_scenario"].items()):
        L.append("| %s | %d | %d |" % (sc, v["count"], v["passed"]))
    L.append("\n## 类别占比\n")
    for c, n in stats["by_category"].items():
        L.append("- %s: %d" % (c, n))
    L.append("\n## 原语覆盖排行（按样本数）\n")
    L.append("| 原语 | 样本数 |\n|---|---|")
    for d in stats["top_dimensions"][:15]:
        L.append("| %s | %d |" % (d["primitive"], d["count"]))
    L.append("\n## 通过 WAF 的有效样本\n")
    L.append("| id | 场景 | 类别 | payload | 原语 |\n|---|---|---|---|---|")
    for s in stats["effective_samples"][:40]:
        L.append("| %s | %s | %s | `%s` | %s |" % (
            s["sample_id"][:10], s["scenario"], s["category"],
            s["payload"][:70].replace("|", "\\|"), ";".join(s["primitives"])[:40]))
    return "\n".join(L)
