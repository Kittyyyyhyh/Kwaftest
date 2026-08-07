#!/usr/bin/env python3
"""WAF 语义测试样本平台 — Flask 仪表盘。

依赖: flask（已安装）。CLI 不依赖本文件。
运行: python3 server.py [--port 8787]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, request, render_template_string, jsonify
except ImportError:
    print("flask not installed; run: pip install flask")
    sys.exit(1)

from pflib import storage, runner, report  # noqa: E402
from pflib import util as putil  # noqa: E402

CONFIG_PATH = ROOT / "config.json"
app = Flask(__name__)

BASE_HTML = """<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>WAF 语义测试样本平台</title>
<style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}
a{color:#58a6ff;text-decoration:none} a:hover{text-decoration:underline}
h1{color:#58a6ff} h2{color:#79c0ff} h3{color:#a5d6ff}
.nav{background:#161b22;padding:10px;border-radius:6px;margin-bottom:20px}
.nav a{margin-right:16px}
table{border-collapse:collapse;width:100%;background:#161b22;border-radius:6px}
th,td{padding:6px 10px;border-bottom:1px solid #30363d;text-align:left;font-size:13px}
th{color:#8b949e} tr:hover{background:#1f2937}
.pass{color:#3fb950} .block{color:#f85149} .pending{color:#d29922} .verify{color:#a5d6ff}
.card{background:#161b22;border-radius:6px;padding:15px;margin:12px 0}
pre{background:#0d1117;border:1px solid #30363d;padding:10px;border-radius:4px;overflow-x:auto}
.kv{color:#8b949e} .mono{font-family:monospace;word-break:break-all}
input,select,button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:5px 8px;border-radius:4px;margin:2px}
button{background:#238636;border:none;cursor:pointer}
.filter{margin:10px 0}
</style></head><body>
<div class="nav">
  <a href="/">📊 总览</a>
  <a href="/samples">🗂 样本库</a>
  <a href="/knowledge">📚 知识库</a>
  <a href="/state">🧠 Skill 状态</a>
  <a href="/test">⚡ 测试</a>
</div>
{{ CONTENT }}
</body></html>"""


def page(html):
    return render_template_string(BASE_HTML.replace("{{ CONTENT }}", html))


@app.route("/")
def index():
    cfg = putil.load_json(str(CONFIG_PATH), {})
    st = report.build_stats(cfg)
    rows = ""
    for sc, v in sorted(st["by_scenario"].items()):
        rows += "<tr><td>%s</td><td>%d</td><td class='pass'>%d</td></tr>" % (sc, v["count"], v["passed"])
    cats = " ".join("<span class='card' style='display:inline-block;margin:4px'>%s: <b>%d</b></span>" % (c, n)
                    for c, n in st["by_category"].items())
    dims = ""
    for d in st["top_dimensions"][:12]:
        dims += "<tr><td>%s</td><td>%d</td></tr>" % (d["primitive"], d["count"])
    eff = ""
    for s in st["effective_samples"][:15]:
        prims = ";".join(s["primitives"][-1:])
        eff += "<tr><td><a href='/samples/%s'>%s</a></td><td>%s</td><td>%s</td><td class='mono'>%s</td><td>%s</td></tr>" % (
            s["sample_id"], s["sample_id"][:10], s["scenario"], s["category"],
            s["payload"][:60].replace("<", "&lt;").replace(">", "&gt;"), prims)
    return page("""
<h1>📊 WAF 语义测试样本集</h1>
<p class='kv'>口径：样本库只保留远程实测通过（HTTP 200 / waf_decision=passed）的样本，通过率恒为 100%%。</p>
<div class='card'>
  <h3>核心指标</h3>
  <table><tr><th>样本总数</th><th>唯一 payload</th><th>已确认通过</th><th>已确认技法</th><th>样本集通过率</th><th>WAF UUID数</th></tr>
  <tr><td>%d</td><td>%d</td><td class='pass'>%d</td><td>%d</td>
  <td class='pass'>%.1f%%</td><td>%d</td></tr></table>
</div>
<div class='card'><h3>场景维度</h3><table><tr><th>场景</th><th>样本数</th><th>已确认通过</th></tr>%s</table></div>
<div class='card'><h3>类别分布</h3>%s</div>
<div class='card'><h3>原语覆盖排行</h3><table><tr><th>原语</th><th>样本数</th></tr>%s</table></div>
<div class='card'><h3>通过 WAF 的有效样本</h3><table><tr><th>id</th><th>场景</th><th>类别</th><th>payload</th><th>原语</th></tr>%s</table></div>
""" % (st["total_samples"], st["unique_payloads"], st["passed"], st["confirmed_techniques"],
       st["confirmed_rate_pct"], st["distinct_waf_uuids"], rows, cats, dims, eff))


@app.route("/samples")
def samples():
    cfg = putil.load_json(str(CONFIG_PATH), {})
    samples_map, _ = storage.load_corpus(cfg)
    scenario = request.args.get("scenario") or None
    category = request.args.get("category") or None
    status = request.args.get("status") or None
    q = request.args.get("q") or None
    page_no = int(request.args.get("page", "1"))
    rows = storage.query_samples(samples_map, scenario=scenario, category=category,
                                 status=status, q=q)
    total = len(rows)
    psize = 50
    rows = rows[(page_no - 1) * psize: page_no * psize]
    tr = ""
    for s in rows:
        st = {"passed": "pass", "blocked": "block", "verifying": "verify", "pending": "pending"}.get(s["status"], "pending")
        prims = ";".join(p["id"] for p in s["mechanism"]["primitives"])
        tr += "<tr><td><a href='/samples/%s'>%s</a></td><td>%s</td><td>%s</td><td class='%s'>%s</td><td class='mono'>%s</td><td>%s</td></tr>" % (
            s["sample_id"], s["sample_id"][:10], s["scenario"], s["category"], st, s["status"],
            s["payload"]["raw"][:55].replace("<", "&lt;").replace(">", "&gt;"), prims[:36])
    opts = lambda items: "".join("<option value='%s'>%s</option>" % (i, i) for i in items)
    sel = lambda v, cur: "selected" if v == cur else ""
    return page("""
<h1>🗂 样本库</h1>
<div class='filter'>
<form method='get'>
  <select name='scenario'><option value=''>场景</option>%s</select>
  <select name='category'><option value=''>类别</option>%s</select>
  <select name='status'><option value=''>状态</option>%s</select>
  <input name='q' placeholder='payload 搜索' value='%s'>
  <button>过滤</button> <span class='kv'>共 %d 条</span>
</form></div>
<table><tr><th>id</th><th>场景</th><th>类别</th><th>状态</th><th>payload</th><th>原语</th></tr>%s</table>
<div style='margin-top:10px'>
%s
</div>
""" % (opts(["sqli", "cmdi", "xss", "upload", "log4j2"]), opts(["plaintext", "semantic_bypass", "encoding_bypass", "combo"]),
       opts(["pending", "passed", "blocked", "ambiguous", "verifying"]), q or "", total, tr,
       " | ".join("<a href='/samples?page=%d%s'>%s</a>" % (p,
          "&scenario=%s&category=%s&status=%s&q=%s" % (scenario or "", category or "", status or "", q or ""),
          p) for p in range(1, max(2, (total // psize) + 2)))))


@app.route("/samples/<sample_id>")
def sample_detail(sample_id):
    cfg = putil.load_json(str(CONFIG_PATH), {})
    samples_map, tests = storage.load_corpus(cfg)
    s = samples_map.get(sample_id)
    if not s:
        return page("<h2>样本不存在</h2>")
    history = [t for t in tests if t.get("sample_id") == sample_id]
    hist = ""
    for t in sorted(history, key=lambda x: x.get("timestamp", "")):
        r = t["result"]
        dcls = "pass" if r["waf_decision"] == "passed" else ("block" if r["waf_decision"] == "blocked" else "pending")
        hist += "<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%s</td><td>%s</td></tr>" % (
            t.get("timestamp", ""), r.get("http_status"), dcls, r["waf_decision"],
            r.get("latency_ms"), (r.get("block_signals") or {}).get("x_waf_uuid", "")[:16] or "-")
    prims = "".join("<li><b>%s</b> %s</li>" % (p["id"], p.get("kb_ref", "")) for p in s["mechanism"]["primitives"])
    return page("""
<h2>样本详情</h2>
<div class='card'><h3>payload</h3><pre class='mono'>%s</pre></div>
<div class='card'><h3>机制</h3><ul>%s</ul><p class='kv'>%s</p></div>
<div class='card'><h3>生成理由</h3><p>%s</p>
<p class='kv'>来源: %s | 模板: %s</p></div>
<div class='card'><h3>质量 / 语义确认</h3>
<p>质量: %s（效 %s / 危 %s / 洞察 %s / 可用 %s）</p>
<p>语义确认: %s = %s（%s）</p>
<p>状态: %s | 标签: %s</p></div>
<div class='card'><h3>测试历史</h3><table><tr><th>时间</th><th>状态码</th><th>判定</th><th>耗时ms</th><th>WAF UUID</th></tr>%s</table></div>
<a href='/samples'>&larr; 返回样本库</a>
""" % (s["payload"]["raw"].replace("<", "&lt;").replace(">", "&gt;"), prims,
       s["mechanism"].get("summary", ""), s["generation"].get("reason", ""),
       s["generation"].get("source", ""), s["generation"].get("template_ids", []),
       json.dumps(s["quality"], ensure_ascii=False), s["quality"].get("effectiveness", ""),
       s["quality"].get("harmfulness", ""), s["quality"].get("insight", ""),
       s["quality"].get("usability", ""), s["semantic_confirmation"].get("method", ""),
       s["semantic_confirmation"].get("result", ""), s["semantic_confirmation"].get("evidence", ""),
       s["status"], ", ".join(s.get("tags", [])), hist))


@app.route("/knowledge")
def knowledge():
    cfg = putil.load_json(str(CONFIG_PATH), {})
    sd = storage.ensure_skill_import(cfg)
    md = (sd / "knowledge" / "advanced_bypass.md").read_text(encoding="utf-8")
    return page("<h1>📚 高级绕过知识库</h1><pre class='mono'>%s</pre>" %
                md.replace("<", "&lt;").replace(">", "&gt;")[:60000])


@app.route("/state")
def state_view():
    cfg = putil.load_json(str(CONFIG_PATH), {})
    sd = storage.ensure_skill_import(cfg)
    st = json.loads((sd / "skill_state.json").read_text(encoding="utf-8"))
    cur = st.get("corpus_curation")
    note = ""
    if cur:
        note = ("<div class='card'><h3>样本库整理说明</h3><p class='kv'>%s</p>"
                "<p class='kv'>时间: %s | 归档: %s</p>"
                "<p class='kv'>影响: %s</p></div>") % (
            cur.get("note", ""), cur.get("applied_at", ""),
            cur.get("archived", ""), cur.get("impact", ""))
    return page("<h1>🧠 Skill 状态</h1>%s<pre>%s</pre>" %
                (note, json.dumps(st, ensure_ascii=False, indent=2)))


@app.route("/test", methods=["GET", "POST"])
def test_page():
    cfg = putil.load_json(str(CONFIG_PATH), {})
    msg = ""
    if request.method == "POST":
        scenario = request.form.get("scenario") or None
        limit = int(request.form.get("limit") or "10")
        dry = request.form.get("dry") == "on"
        stats, run_id = runner.run_batch(cfg, scenario=scenario, status="pending",
                                         limit=limit, dry_run=dry, round_num=1)
        msg = "<div class='card'>run_id=%s<br>stats=%s</div>" % (run_id, json.dumps(stats, ensure_ascii=False))
    return page("""
<h1>⚡ 远程测试</h1>
<div class='card'><form method='post'>
  场景: <select name='scenario'><option value=''>全部</option>
    <option>sqli</option><option>cmdi</option><option>xss</option><option>upload</option><option>log4j2</option>
  </select>
  数量上限: <input name='limit' value='10'>
  试跑(不发请求): <input type='checkbox' name='dry'>
  <button>执行批量测试</button>
</form>
<p class='kv'>对远程腾讯云 WAF 实测 pending 样本，200=放行(绕过成功)，403=被拦。</p></div>
%s
""" % msg)


def run(host="127.0.0.1", port=8787):
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    run(args.host, args.port)
