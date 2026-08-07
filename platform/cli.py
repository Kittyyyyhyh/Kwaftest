#!/usr/bin/env python3
"""waf-cli — 样本平台命令行入口。

用法:
  waf-cli corpus list|query|add|tag|dedup|export|import
  waf-cli test  run|one|status
  waf-cli report [--format md|json] [--out PATH]
  waf-cli config show|set KEY VALUE
  waf-cli server [--port N]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from pflib import storage, runner, report  # noqa: E402
from pflib import util as putil  # noqa: E402

CONFIG_PATH = ROOT / "config.json"


def load_cfg():
    return putil.load_json(str(CONFIG_PATH), {})


def save_cfg(cfg):
    putil.save_json(str(CONFIG_PATH), cfg)


# ── corpus ────────────────────────────────────────────────────

def cmd_corpus(args):
    cfg = load_cfg()
    if args.action == "list":
        samples, _ = storage.load_corpus(cfg)
        rows = storage.query_samples(samples, scenario=args.scenario, category=args.category,
                                     status=args.status, tag=args.tag, q=args.q, limit=args.limit)
        for s in rows:
            prims = ";".join(p["id"] for p in s["mechanism"]["primitives"])
            print("%-12s %-6s %-16s %-10s %-55s %s" % (
                s["sample_id"][:12], s["scenario"], s["category"], s["status"],
                s["payload"]["raw"][:55], prims[:30]))
        print("total: %d" % len(rows))
    elif args.action == "query":
        samples, _ = storage.load_corpus(cfg)
        rows = storage.query_samples(samples, q=args.q, status=args.status, limit=args.limit)
        print(json.dumps(rows, ensure_ascii=False, indent=2)[:4000])
    elif args.action == "add":
        samples, _ = storage.load_corpus(cfg)
        sd = storage.ensure_skill_import(cfg)
        from lib import schema, util
        probe = {"payload": args.payload, "scenario": args.scenario,
                 "category": args.category or "semantic_bypass",
                 "mechanism": {"layers": ["syntactic"],
                               "primitives": [{"id": args.primitive or ("gen:%s:manual" % args.scenario)}],
                               "encodings": []},
                 "generation": {"source": "human", "reason": args.reason or "手工添加"},
                 "quality": {"overall": "medium"}}
        rec = schema.build_sample_from_probe(probe)
        if rec["sample_id"] in samples:
            print("duplicate, sample already exists:", rec["sample_id"])
        else:
            util.append_jsonl(sd / "corpus" / "samples.jsonl", [rec])
            print("added:", rec["sample_id"], rec["payload"]["raw"][:50])
    elif args.action == "tag":
        samples, _ = storage.load_corpus(cfg)
        sd = storage.ensure_skill_import(cfg)
        from lib import util
        rec = samples.get(args.id)
        if not rec:
            print("not found:", args.id)
            return
        tags = set(rec.get("tags", []))
        for t in (args.add or []):
            tags.add(t)
        for t in (args.del_ or []):
            tags.discard(t)
        rec["tags"] = sorted(tags)
        util.write_jsonl(sd / "corpus" / "samples.jsonl", list(samples.values()))
        print("tags updated:", rec["tags"])
    elif args.action == "dedup":
        samples, _ = storage.load_corpus(cfg)
        rep = storage.dedup_report(samples)
        ident, pvar = rep["identical"], rep["payload_variant"]
        total = sum(len(v) for v in pvar.values())
        print("identical(真冗余, 可删): %d 对" % len(ident))
        for a, b in ident[:10]:
            print("  %s <-> %s" % (a[:12], b[:12]))
        print("payload_variant(同载荷不同原语, 设计独立): %d 组 / %d 样本" % (len(pvar), total))
        for key, ids in list(pvar.items())[:5]:
            print("  [%s] %s (%d 条原语路径)" % (key[1], key[0][:45], len(ids)))
        print("唯一 payload 数: %d / %d" % (storage.unique_payload_count(samples), len(samples)))
    elif args.action == "export":
        samples, _ = storage.load_corpus(cfg)
        rows = storage.query_samples(samples, scenario=args.scenario, category=args.category,
                                     status=args.status, tag=args.tag, limit=args.limit)
        path = storage.export_records(rows, args.out or ("export." + (args.format or "jsonl")),
                                      args.format or "jsonl")
        print("exported %d records -> %s" % (len(rows), path))
    elif args.action == "import":
        sd = storage.ensure_skill_import(cfg)
        from lib import util
        recs = putil.read_jsonl(args.file)
        existing = {r["sample_id"] for r in util.read_jsonl(sd / "corpus" / "samples.jsonl")}
        new = [r for r in recs if r.get("sample_id") and r["sample_id"] not in existing]
        util.append_jsonl(sd / "corpus" / "samples.jsonl", new)
        print("imported %d new records (skipped %d existing)" % (len(new), len(recs) - len(new)))


# ── test ──────────────────────────────────────────────────────

def cmd_test(args):
    cfg = load_cfg()
    if args.action == "run":
        stats, run_id = runner.run_batch(
            cfg, scenario=args.scenario, category=args.category, status=args.status,
            limit=args.limit, dry_run=args.dry_run, run_id=args.name,
            concurrency=args.concurrency, round_num=args.round)
        print("run_id:", run_id)
        print("stats:", json.dumps(stats, ensure_ascii=False))
    elif args.action == "one":
        res = runner.run_one(cfg, args.id, dry_run=args.dry_run)
        print(json.dumps(res, ensure_ascii=False, indent=2)[:1500])
    elif args.action == "status":
        samples, tests = storage.load_corpus(cfg)
        from collections import Counter
        sc = Counter(s.get("status") for s in samples.values())
        tc = Counter(t["result"]["waf_decision"] for t in tests)
        print("sample status:", dict(sc))
        print("test decisions:", dict(tc))


# ── report / config ───────────────────────────────────────────

def cmd_report(args):
    cfg = load_cfg()
    stats = report.build_stats(cfg)
    if args.format == "json":
        text = json.dumps(stats, ensure_ascii=False, indent=2)
    else:
        text = report.render_markdown(stats)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print("report ->", args.out)
    else:
        print(text)


def cmd_config(args):
    cfg = load_cfg()
    if args.action == "show":
        print(json.dumps(cfg, ensure_ascii=False, indent=2))
    else:
        cfg[args.key] = json.loads(args.value) if args.value[:1] in "{[\"" else args.value
        save_cfg(cfg)
        print("set", args.key, "=", cfg[args.key])


def cmd_server(args):
    print("starting dashboard on :%d ... (ctrl-c to stop)" % args.port)
    sys.path.insert(0, str(ROOT))
    import server as srv
    srv.run(host=args.host, port=args.port)


# ── main ──────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(prog="waf-cli", description="WAF 语义测试样本平台")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("corpus")
    p.add_argument("action", choices=["list", "query", "add", "tag", "dedup", "export", "import"])
    p.add_argument("--scenario", choices=["sqli", "cmdi", "xss", "upload", "log4j2"])
    p.add_argument("--category")
    p.add_argument("--status")
    p.add_argument("--tag")
    p.add_argument("--q")
    p.add_argument("--limit", type=int)
    p.add_argument("--payload")
    p.add_argument("--primitive")
    p.add_argument("--reason")
    p.add_argument("--id")
    p.add_argument("--add", action="append")
    p.add_argument("--del", dest="del_", action="append")
    p.add_argument("--out")
    p.add_argument("--format", choices=["jsonl", "json", "csv", "md"])
    p.add_argument("--file")
    p.set_defaults(fn=cmd_corpus)

    p = sub.add_parser("test")
    p.add_argument("action", choices=["run", "one", "status"])
    p.add_argument("--scenario", choices=["sqli", "cmdi", "xss", "upload", "log4j2"])
    p.add_argument("--category")
    p.add_argument("--status", default="pending")
    p.add_argument("--limit", type=int)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--name")
    p.add_argument("--concurrency", type=int)
    p.add_argument("--round", type=int, default=1)
    p.add_argument("--id")
    p.set_defaults(fn=cmd_test)

    p = sub.add_parser("report")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("config")
    p.add_argument("action", choices=["show", "set"])
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.set_defaults(fn=cmd_server)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
