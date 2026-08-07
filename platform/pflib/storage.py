"""样本库管理 — 查询 / 过滤 / 去重 / 导入导出。

只读 skill 的 corpus；写入测试结果走 runner.py。
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parent.parent


def skill_dir(cfg) -> Path:
    return PLATFORM_ROOT.parent / cfg.get("skill_dir", ".claude/skills/semantic-mining")


def ensure_skill_import(cfg):
    """把 skill lib 加入 sys.path，供 schema 复用。"""
    sd = skill_dir(cfg)
    if str(sd) not in sys.path:
        sys.path.insert(0, str(sd))
    return sd


def load_corpus(cfg) -> tuple:
    """返回 (samples dict, tests list)。"""
    ensure_skill_import(cfg)
    from lib import schema  # noqa: F401（路径注入后导入）
    from lib import util
    sd = skill_dir(cfg)
    samples = util.read_jsonl(sd / "corpus" / "samples.jsonl")
    tests = util.read_jsonl(sd / "corpus" / "tests.jsonl")
    return {s["sample_id"]: s for s in samples}, tests


def query_samples(samples, *, scenario=None, category=None, status=None, tag=None,
                  q=None, limit=None):
    """按条件过滤样本列表。"""
    out = []
    for s in samples.values():
        if scenario and s.get("scenario") != scenario:
            continue
        if category and s.get("category") != category:
            continue
        if status and s.get("status") != status:
            continue
        if tag and tag not in s.get("tags", []):
            continue
        if q and q not in s["payload"]["raw"]:
            continue
        out.append(s)
    if limit:
        out = out[:limit]
    return out


def derive_statuses(samples, tests, scenario_whitelist=None):
    """用最新测试事件重算所有样本 status（就地更新）。"""
    from lib import schema
    by_sid = {}
    for t in tests:
        by_sid.setdefault(t["sample_id"], []).append(t)
    changed = 0
    for sid, s in samples.items():
        if scenario_whitelist and s.get("scenario") not in scenario_whitelist:
            continue
        new = schema.derive_status(s, by_sid.get(sid, []))
        if new != s.get("status"):
            s["status"] = new
            changed += 1
    return changed


def dedup_report(samples):
    """去重报告，区分两类"重复"。

    样本 id = hash(payload, transport, placement, primitives)，因此：
      - identical   ：payload + 原语完全相同 → 真冗余，可删（当前应为 0）
      - payload_var ：payload 相同但原语不同 → 设计上独立（同一载荷的不同技法路径），不删
    """
    by_payload = defaultdict(list)
    for s in samples.values():
        by_payload[(s["payload"]["raw"], s.get("scenario"))].append(s)
    identical = []      # (sample_id, other_id)
    payload_variant = {}  # (payload, scenario) -> [sample_id, ...]
    for key, items in by_payload.items():
        if len(items) < 2:
            continue
        # 按原语分组
        by_prims = defaultdict(list)
        for s in items:
            prims = tuple(p["id"] for p in s["mechanism"]["primitives"])
            by_prims[prims].append(s["sample_id"])
        if len(by_prims) == 1:
            ids = list(by_prims.values())[0]
            for i in range(1, len(ids)):
                identical.append((ids[i], ids[0]))
        else:
            payload_variant[key] = [sid for v in by_prims.values() for sid in v]
    return {"identical": identical, "payload_variant": payload_variant}


def unique_payload_count(samples) -> int:
    """唯一 payload 数（同 payload×不同原语合并为 1）。"""
    return len({(s["payload"]["raw"], s.get("scenario")) for s in samples.values()})


def export_records(records, out_path, fmt="jsonl"):
    from lib import util
    if fmt == "jsonl":
        util.write_jsonl(out_path, records)
    elif fmt == "json":
        util.save_json(out_path, records)
    elif fmt == "csv":
        _export_csv(records, out_path)
    elif fmt == "md":
        _export_md(records, out_path)
    else:
        raise ValueError("fmt must be jsonl/json/csv/md")
    return out_path


def _export_csv(records, out_path):
    import csv
    fields = ["sample_id", "scenario", "category", "status", "payload", "primitives",
              "reason", "overall"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({
                "sample_id": r["sample_id"], "scenario": r["scenario"],
                "category": r["category"], "status": r["status"],
                "payload": r["payload"]["raw"],
                "primitives": ";".join(p["id"] for p in r["mechanism"]["primitives"]),
                "reason": r["generation"].get("reason", ""),
                "overall": r["quality"].get("overall", ""),
            })


def _export_md(records, out_path):
    lines = ["| id | scenario | category | status | payload | primitives |",
             "|---|---|---|---|---|---|"]
    for r in records:
        prims = ";".join(p["id"] for p in r["mechanism"]["primitives"])
        raw = r["payload"]["raw"].replace("|", "\\|")
        lines.append("| %s | %s | %s | %s | `%s` | %s |" % (
            r["sample_id"][:10], r["scenario"], r["category"], r["status"],
            raw[:60], prims))
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
