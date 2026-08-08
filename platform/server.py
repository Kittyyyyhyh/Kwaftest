#!/usr/bin/env python3
"""WAF 语义测试样本库 · 展示平台（Flask 仪表盘）。

定位：把文件夹里的样本数据（corpus 已确认样本 / 实测证据 / skill 学习状态 / 知识库）
用美观完整的界面展示。只读展示，不运行测试、不修改数据。

运行: python3 server.py [--port 8787]
"""
import html as _html
import re
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, render_template, request, send_file, abort
    from markupsafe import Markup
except ImportError:
    print("flask not installed; run: pip install flask")
    sys.exit(1)

from pflib import storage, report  # noqa: E402
from pflib import util as putil    # noqa: E402

CONFIG_PATH = ROOT / "config.json"
app = Flask(__name__)

SCENARIO_COLORS = {
    "sqli": "#60a5fa", "cmdi": "#34d399", "xss": "#fb7185",
    "upload": "#a78bfa", "log4j2": "#fbbf24",
}
SORT_KEYS = {
    "id":       lambda s: s["sample_id"],
    "scenario": lambda s: s["scenario"],
    "status":   lambda s: s.get("status", ""),
    "length":   lambda s: s["payload"]["length"],
    "created":  lambda s: s.get("created_at", ""),
}
PAGE_SIZE = 20


# ── 工具 ────────────────────────────────────────────────────

def load_cfg():
    return putil.load_json(str(CONFIG_PATH), {})


def primary_prim(s) -> str:
    prims = (s.get("mechanism") or {}).get("primitives", [])
    return prims[-1].get("id", "none") if prims else "none"


def q_url(filters, page=1, **extra):
    """构造样本库链接 query 串（正确 URL 编码，剔除空值）。"""
    params = {k: v for k, v in (filters or {}).items() if v}
    params["page"] = page
    params.update({k: v for k, v in extra.items() if v})
    return urllib.parse.urlencode(params)


app.jinja_env.globals["q_url"] = q_url


def _md_inline(text: str) -> str:
    """行内 markdown：**加粗** / `行内代码`（输入已转义）。"""
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+?)`", r'<code class="inline">\1</code>', text)
    return text


def render_markdown(text: str) -> Markup:
    """最小 markdown 渲染（先转义，安全）：# 标题 / 列表 / 代码块 / 引用。"""
    escaped = _html.escape(text)
    out, code_buf, in_code = [], [], False
    for line in escaped.split("\n"):
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                out.append("<pre><code>" + "\n".join(code_buf) + "</code></pre>")
                code_buf, in_code = [], False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if stripped.startswith("### "):
            out.append("<h3>" + _md_inline(line[4:]) + "</h3>")
        elif stripped.startswith("## "):
            out.append("<h2>" + _md_inline(line[3:]) + "</h2>")
        elif stripped.startswith("# "):
            out.append("<h1>" + _md_inline(line[2:]) + "</h1>")
        elif stripped.startswith("> "):
            out.append("<blockquote>" + _md_inline(line[2:]) + "</blockquote>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            out.append("<li>" + _md_inline(line[2:]) + "</li>")
        elif stripped == "":
            out.append("")
        elif re.match(r"^\d+\.\s", stripped):
            out.append("<li>" + _md_inline(re.sub(r"^\d+\.\s", "", line)) + "</li>")
        else:
            out.append("<p>" + _md_inline(line) + "</p>")
    if in_code:
        out.append("<pre><code>" + "\n".join(code_buf) + "</code></pre>")
    return Markup("\n".join(out))


def _read_filters():
    def g(k, strip=True):
        v = request.args.get(k)
        return (v.strip() if strip and v else v) or None
    return {
        "q": g("q"), "scenario": g("scenario"), "category": g("category"),
        "status": g("status"), "primitive": g("primitive"), "sort": g("sort") or "id",
    }


# ── 路由 ────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    cfg = load_cfg()
    stats = report.build_stats(cfg)
    st = report.build_state_summary(cfg)
    scenario_rows = sorted(
        ({"name": sc, "count": v["count"], "passed": v["passed"]}
         for sc, v in stats["by_scenario"].items()),
        key=lambda x: x["count"], reverse=True)
    return render_template("dashboard.html", active="dashboard", stats=stats,
                           state=st, scenario_rows=scenario_rows,
                           sc_colors=SCENARIO_COLORS)


@app.route("/samples")
def samples():
    cfg = load_cfg()
    samples_map, _ = storage.load_corpus(cfg)
    f = _read_filters()

    rows = storage.query_samples(samples_map, scenario=f["scenario"],
                                 category=f["category"], status=f["status"], q=f["q"])
    if f["primitive"]:
        rows = [s for s in rows if primary_prim(s) == f["primitive"]]
    rows.sort(key=SORT_KEYS.get(f["sort"], SORT_KEYS["id"]))

    total = len(rows)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    page = min(page, total_pages)
    paged = rows[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]

    for s in paged:
        s["primary_prim"] = primary_prim(s)

    all_scenarios = sorted({s["scenario"] for s in samples_map.values()})
    all_categories = sorted({s["category"] for s in samples_map.values()})
    all_statuses = sorted({s.get("status", "pending") for s in samples_map.values()})
    all_prims = sorted({primary_prim(s) for s in samples_map.values()})

    return render_template(
        "samples.html", active="samples", samples=paged, total=total,
        page=page, total_pages=total_pages, filters=f,
        q=f["q"], scenario=f["scenario"], category=f["category"],
        status=f["status"], primitive=f["primitive"], sort=f["sort"],
        options={"scenarios": all_scenarios, "categories": all_categories,
                 "statuses": all_statuses, "primitives": all_prims,
                 "sorts": [("id", "默认"), ("scenario", "场景"), ("status", "状态"),
                           ("length", "载荷长度"), ("created", "创建时间")]})


@app.route("/samples/<sample_id>")
def sample_detail(sample_id):
    cfg = load_cfg()
    samples_map, tests = storage.load_corpus(cfg)
    s = samples_map.get(sample_id)
    if not s:
        abort(404)
    hist = [t for t in tests if t.get("sample_id") == sample_id]
    hist.sort(key=lambda x: x.get("timestamp", ""))
    return render_template("sample_detail.html", active="samples", s=s, tests=hist)


@app.route("/knowledge")
def knowledge():
    cfg = load_cfg()
    sd = storage.ensure_skill_import(cfg)
    path = sd / "knowledge" / "advanced_bypass.md"
    md = path.read_text(encoding="utf-8", errors="replace") if path.exists() else "（知识库文件缺失）"
    return render_template("knowledge.html", active="knowledge", kb_html=render_markdown(md))


@app.route("/state")
def state():
    cfg = load_cfg()
    st = report.build_state_summary(cfg)
    sd = storage.ensure_skill_import(cfg)
    raw = (sd / "skill_state.json").read_text(encoding="utf-8", errors="replace") \
        if (sd / "skill_state.json").exists() else "{}"
    return render_template("state.html", active="state", state=st, raw_json=raw)


@app.route("/export")
def export():
    cfg = load_cfg()
    samples_map, _ = storage.load_corpus(cfg)
    f = _read_filters()
    fmt = request.args.get("format", "jsonl")
    if fmt not in ("csv", "md", "jsonl", "json"):
        fmt = "jsonl"

    rows = storage.query_samples(samples_map, scenario=f["scenario"],
                                 category=f["category"], status=f["status"], q=f["q"])
    if f["primitive"]:
        rows = [s for s in rows if primary_prim(s) == f["primitive"]]

    out_path = ROOT / ("tmp_export.%s" % fmt)
    storage.export_records(rows, str(out_path), fmt)
    mime = {"csv": "text/csv", "md": "text/markdown",
            "jsonl": "application/x-ndjson", "json": "application/json"}[fmt]
    return send_file(str(out_path), mimetype=mime, as_attachment=True,
                     download_name="samples_export.%s" % fmt)


@app.errorhandler(404)
def not_found(e):
    return "<h1 style='text-align:center;margin-top:80px;color:#5d6879'>404 — 样本不存在</h1>", 404


# ── 入口 ────────────────────────────────────────────────────

def run(host="127.0.0.1", port=8787):
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    run(args.host, args.port)
