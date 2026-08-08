"""种子策展 — 从通过样本按攻击结构类提炼进化种子库。

治本机制的一部分：把"AI 有意识地更新种子"变成系统行为。
- 从 corpus 通过样本中，按 (scenario, structure_class) 分组
- 每类选最好 2-4 条（原语数/层数/质量加权）
- 写入 knowledge/seeds.jsonl（run_round --seeds 读取派生）

用法:
  python3 scripts/curate_seeds.py [--per-class 3] [--min-passed 1]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import util, structures  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "corpus" / "samples.jsonl"
SEEDS = ROOT / "knowledge" / "seeds.jsonl"
SCENARIOS = ["sqli", "cmdi", "xss", "upload", "log4j2"]


def _score(s):
    """种子质量分：原语数×2 + 层数 + 质量权重。"""
    prims = len((s.get("mechanism") or {}).get("primitives", []))
    layers = len((s.get("mechanism") or {}).get("layers", []))
    q = {"high": 3, "medium": 2, "low": 1, "boundary_marker": 0}.get(
        (s.get("quality") or {}).get("overall", "medium"), 1)
    return prims * 2 + layers + q


def curate(per_class=3, min_passed=1):
    samples = [json.loads(l) for l in open(SAMPLES, encoding="utf-8")]
    passed = [s for s in samples if s["status"] in ("passed", "verifying")
              and (s.get("quality") or {}).get("overall") != "boundary_marker"]
    # 分组
    groups = {}
    for s in passed:
        st = structures.classify(s["payload"]["raw"], s["scenario"])
        groups.setdefault((s["scenario"], st), []).append(s)

    existing = {json.loads(l)["sample_id"] for l in open(SEEDS, encoding="utf-8")} if SEEDS.exists() else set()
    new_seeds, added = [], 0
    for (sc, st), items in sorted(groups.items()):
        # 每类按质量分排序取前 per_class
        items.sort(key=_score, reverse=True)
        for s in items[:per_class]:
            if s["sample_id"] in existing:
                continue
            # 精简为种子记录（保留机制/质量，标记结构类）
            rec = {
                "sample_id": s["sample_id"], "seed_id": s.get("seed_id") or s["sample_id"],
                "seed_of": s["sample_id"],
                "scenario": sc, "structure_class": st, "category": "semantic_bypass",
                "payload": s["payload"], "mechanism": s["mechanism"],
                "generation": dict(s.get("generation", {}), source="seed_curated",
                                   reason="[种子策展] %s 类：%s" % (st, s["generation"].get("reason", ""))),
                "quality": s["quality"], "semantic_confirmation": s["semantic_confirmation"],
                "tags": sorted(set(s.get("tags", [])) | {"seed"}),
                "context": s["context"], "intent": s["intent"], "status": "passed",
            }
            new_seeds.append(rec)
            existing.add(s["sample_id"])
            added += 1

    if new_seeds:
        util.append_jsonl(str(SEEDS), new_seeds)
    print("种子库: 新增 %d 条 | 覆盖 %d 个结构类 | 总数 %d" % (
        added, len(set(g[0] for g in groups)), len(existing)))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=3)
    ap.add_argument("--min-passed", type=int, default=1)
    args = ap.parse_args()
    curate(args.per_class, args.min_passed)
