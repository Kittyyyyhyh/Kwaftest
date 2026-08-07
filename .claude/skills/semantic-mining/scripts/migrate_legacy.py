"""迁移旧样本（本地 lab 时代的 batches/results）到 corpus v2。

用法:
  python3 scripts/migrate_legacy.py --input ../../../../samples/batches/latest.jsonl \
      --output corpus/samples.jsonl

范围：只迁移纯语义样本（legacy category ∈ {baseline, semantic_bypass}）。
编码变体（encoding_bypass/combo）属未来 encoding-bypass skill，跳过。
旧测试结果（针对本地 CRS PL4）不迁移——对新远程 WAF 无意义。
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import schema  # noqa: E402
from lib import util  # noqa: E402

LEGACY_CAT_MAP = {"baseline": "plaintext", "semantic_bypass": "semantic_bypass"}
RUN_ID = "run_20260724_204522"


def migrate_one(legacy: dict) -> dict:
    raw = legacy.get("applied_payload", "")
    if not raw:
        return None
    cat = LEGACY_CAT_MAP.get(legacy.get("category"))
    if cat is None:
        return None  # encoding_bypass / combo → 跳过
    seed = legacy.get("seed_id", "") or legacy.get("sample_id", "")
    ctx = {"transport": "direct", "placements": ["query"],
           "http": {"method": "GET", "path": "/", "params": {"cmd": "${payload}"}}}
    mechanism = {
        "layers": ["syntactic"],
        "primitives": [{"id": "cmdi:syntactic:legacy_seed"}],
        "encodings": [],
        "summary": "旧本地lab样本迁移（分隔符拼接读文件）",
    }
    generation = {"source": "migrated", "reason": "legacy migration from %s (local CRS PL4)" % RUN_ID}
    quality = {"effectiveness": "B", "harmfulness": "L3", "insight": "B",
               "usability": "B", "overall": "medium", "notes": "migrated, 未在远程实测"}
    confirm = {"method": "knowledge", "result": True, "evidence": "legacy:cmdi:local_lab"}
    rec = schema.build_sample(
        payload=raw, scenario="cmdi", category=cat,
        mechanism=mechanism, generation=generation, quality=quality,
        semantic_confirmation=confirm, context=ctx,
        tags=["legacy", seed], seed_id=seed,
    )
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", default="corpus/samples.jsonl")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    legacy = util.read_jsonl(args.input)
    records, skipped = [], 0
    for l in legacy:
        rec = migrate_one(l)
        if rec is None:
            skipped += 1
            continue
        errs = schema.validate_sample(rec)
        if errs:
            print("SKIP invalid:", rec.get("sample_id"), errs)
            skipped += 1
            continue
        records.append(rec)

    # 去重（sample_id 内容哈希）
    seen, deduped = set(), []
    for rec in records:
        if rec["sample_id"] in seen:
            continue
        seen.add(rec["sample_id"])
        deduped.append(rec)

    print("legacy=%d migrated=%d (deduped) skipped=%d" % (len(legacy), len(deduped), skipped))
    if args.dry_run:
        return
    util.append_jsonl(args.output, deduped)
    print("wrote ->", args.output)


if __name__ == "__main__":
    main()
