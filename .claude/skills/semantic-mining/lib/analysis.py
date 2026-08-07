"""学习循环 — 维度统计 / confirmed-dead 分档 / 方向选择 / 回写。

每轮执行后调用 recompute_state()：
  1. 按样本的主原语（mechanism.primitives 最后一个）聚合 tested/passed → pass_rate
  2. 分档：dead / confirmed / boundary / exploring
  3. 依据熵 info=p(1-p) 生成数据驱动方向 → pending_directions
  4. 更新 skill_state.json + confirmed_techniques.jsonl + seen_waf_uuids

核心哲学：不靠人设判断"什么技法高级"，靠实测数据让有效技法浮出水面。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import util  # noqa: E402

MIN_SAMPLES = 8          # 达到该测试量才允许 confirmed/dead 判定
CONFIRMED_RATE = 0.6     # ≥60% 通过 → confirmed
TOP_K_DIRECTIONS = 3
SKILL_STATE = "skill_state.json"
CONFIRMED_TECH = "knowledge/confirmed_techniques.jsonl"


def primary_prim(sample) -> str:
    prims = (sample.get("mechanism") or {}).get("primitives", [])
    return prims[-1].get("id", "none") if prims else "none"


def _tier_for(tested, rate):
    if tested >= MIN_SAMPLES and rate == 0:
        return "dead"
    if tested >= MIN_SAMPLES and rate >= CONFIRMED_RATE:
        return "confirmed"
    if 0.2 < rate < 0.8:
        return "boundary"
    return "exploring"


def recompute_state(samples, tests, state, scenario):
    """返回更新后的 state（就地修改并返回）。"""
    dim = {}
    for t in tests:
        s = samples.get(t.get("sample_id"))
        if not s or s.get("scenario") != scenario:
            continue
        prim = primary_prim(s)
        d = dim.setdefault(prim, {"tested": 0, "passed": 0})
        d["tested"] += 1
        if (t.get("result") or {}).get("waf_decision") == "passed":
            d["passed"] += 1

    sc = state.setdefault("scenarios", {}).setdefault(scenario, {})
    sc.setdefault("round", 0)
    sc["round"] = int(sc.get("round", 0)) + 1
    sc["last_run"] = util.now_iso()

    dimension_stats = {}
    confirmed, dead = [], []
    for prim, d in dim.items():
        rate = d["passed"] / d["tested"] if d["tested"] else 0.0
        tier = _tier_for(d["tested"], rate)
        dimension_stats[prim] = {"tested": d["tested"], "passed": d["passed"],
                                 "pass_rate": round(rate, 3), "tier": tier}
        if tier == "confirmed":
            confirmed.append(prim)
        elif tier == "dead":
            dead.append(prim)
    sc["dimension_stats"] = dimension_stats
    sc["confirmed_techniques"] = list(dict.fromkeys(
        sc.get("confirmed_techniques", []) + confirmed))
    sc["dead_primitives"] = list(dict.fromkeys(
        sc.get("dead_primitives", []) + dead))

    # 数据驱动方向：熵优先
    dirs = []
    for prim, d in dimension_stats.items():
        if d["tier"] in ("boundary", "confirmed") and d["tested"] > 0:
            info = round(d["pass_rate"] * (1 - d["pass_rate"]), 3)
            dirs.append({"desc": "深挖 %s（通过率 %.0f%%，已测 %d）" % (
                prim, d["pass_rate"] * 100, d["tested"]),
                "basis": "%s:%s" % (d["tier"], prim), "priority": info})
    dirs.sort(key=lambda x: -x["priority"])
    sc["pending_directions"] = dirs[:TOP_K_DIRECTIONS]

    # WAF UUID 追踪（检测规则升级）
    uuids = set()
    for t in tests:
        u = (t.get("result") or {}).get("block_signals", {}).get("x_waf_uuid")
        if u:
            uuids.add(u)
    tgt = state.setdefault("targets", {}).setdefault("tencent_waf_prod", {})
    seen = set(tgt.get("seen_waf_uuids", []))
    new_uuids = uuids - seen
    if new_uuids and seen:
        tgt["waf_update_warning"] = "检测到新的 X-WAF-UUID，WAF 可能已更新规则，建议重基线: %s" % list(new_uuids)[:3]
    tgt["seen_waf_uuids"] = sorted(seen | uuids)[-200:]
    tgt["last_run"] = util.now_iso()

    sc.setdefault("history", []).append({
        "round": sc["round"], "tested": len(tests), "note": "round %d" % sc["round"]})
    return state


def write_confirmed(samples, scenario, confirmed_ids, path=CONFIRMED_TECH):
    """confirmed 原语回写 confirmed_techniques.jsonl（含证据样本）。"""
    existing = {r.get("primitive_id"): r for r in util.read_jsonl(path)}
    for pid in confirmed_ids:
        evidence = [s["sample_id"] for s in samples.values()
                    if s.get("scenario") == scenario and primary_prim(s) == pid][:10]
        rec = {"primitive_id": pid, "scenario": scenario,
               "first_confirmed_at": util.now_iso(), "last_seen": util.now_iso(),
               "evidence_sample_ids": evidence}
        existing[pid] = rec
    util.write_jsonl(path, list(existing.values()))


def sync_statuses(samples_path, tests_path):
    """用最新测试事件重算所有样本 status 并落盘。返回变更数。"""
    from lib import schema
    samples = {s["sample_id"]: s for s in util.read_jsonl(samples_path)}
    tests = util.read_jsonl(tests_path)
    by_sid = {}
    for t in tests:
        by_sid.setdefault(t["sample_id"], []).append(t)
    changed = 0
    for sid, s in samples.items():
        new = schema.derive_status(s, by_sid.get(sid, []))
        if new != s.get("status"):
            s["status"] = new
            changed += 1
    if changed:
        util.write_jsonl(samples_path, list(samples.values()))
    return changed


def load_state(path=SKILL_STATE) -> dict:
    return util.load_json(str(Path(__file__).resolve().parent.parent / path),
                          {"schema_version": 2, "scenarios": {}, "targets": {}})


# ── 知识缺口自检（skill 变强的主动机制）─────────────────────────

def compute_knowledge_gaps(samples, tests, state, kb_path="knowledge/advanced_bypass.md"):
    """检测"当前知识不够"的信号，返回缺口清单。

    信号：
      1. 场景已测≥10 且 0% 通过 → 全拦，缺冷门技法，建议联网检索
      2. 场景已测≥10 且 <5% 通过 → 接近全拦
      3. 已用原语数 / 知识库原语数 < 50% → 覆盖不足，建议先探索未用原语
      4. 连续两轮绕过率无提升 → 停滞，建议换方向或检索
    返回 [{scenario, signal, suggestion, research_topics}]。
    """
    from collections import defaultdict
    gaps = []
    decided = {}
    for t in tests:
        decided.setdefault(t["sample_id"], t)
    scen_stats = defaultdict(lambda: {"tested": 0, "passed": 0})
    for sid, t in decided.items():
        s = samples.get(sid)
        if not s:
            continue
        sc = s["scenario"]
        scen_stats[sc]["tested"] += 1
        if (t.get("result") or {}).get("waf_decision") == "passed":
            scen_stats[sc]["passed"] += 1
    for sc, st in scen_stats.items():
        if st["tested"] < 10:
            continue
        rate = st["passed"] / st["tested"]
        if rate == 0:
            gaps.append({"scenario": sc, "signal": "全拦（%d 测 0 过）" % st["tested"],
                         "suggestion": "纯语义层当前全部被拦，需联网检索冷门技法扩充知识库",
                         "research_topics": ["%s 绕 WAF 冷门技法 2024-2025" % sc,
                                             "cloud WAF %s bypass" % sc]})
        elif rate < 0.05:
            gaps.append({"scenario": sc, "signal": "接近全拦（%.0f%% 过）" % (rate * 100),
                         "suggestion": "当前技法几乎全被拦，建议检索 %s 语义引擎盲区" % sc,
                         "research_topics": ["%s semantic WAF blindspot" % sc]})

    # 知识库覆盖度
    kb_path = str(Path(__file__).resolve().parent.parent / kb_path)
    kb_text = ""
    if Path(kb_path).exists():
        kb_text = Path(kb_path).read_text(encoding="utf-8", errors="replace")
    import re as _re
    kb_prims = set(_re.findall(r"^### ([a-z0-9]+:[a-z0-9]+:[a-z0-9_]+)", kb_text, _re.M))
    used_prims = set()
    for s in samples.values():
        for p in (s.get("mechanism") or {}).get("primitives", []):
            if p.get("id", "").startswith(("gen:", "ai:")):
                continue
            used_prims.add(p["id"])
    if kb_prims:
        coverage = len(used_prims & kb_prims) / len(kb_prims)
        if coverage < 0.5:
            unexplored = sorted(kb_prims - used_prims)[:8]
            gaps.append({"scenario": "all", "signal": "知识库覆盖不足（%.0f%%）" % (coverage * 100),
                         "suggestion": "知识库大量原语未实测，先探索未用原语再决定是否检索",
                         "research_topics": [],
                         "unexplored_primitives": unexplored})

    # 停滞检测：连续两轮无提升
    for sc, scd in state.get("scenarios", {}).items():
        hist = scd.get("history", [])
        if len(hist) >= 2 and (hist[-2].get("passed", 0) == hist[-1].get("passed", 0)
                               or hist[-1].get("tested", 0) == 0):
            gaps.append({"scenario": sc, "signal": "停滞（两轮通过数无提升）",
                         "suggestion": "该方向已榨干，换方向或联网检索新技法",
                         "research_topics": ["%s WAF bypass new technique" % sc]})
    return gaps


def save_state(state, path=SKILL_STATE):
    util.save_json(str(Path(__file__).resolve().parent.parent / path), state)
