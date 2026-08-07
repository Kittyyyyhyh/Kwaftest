"""统一 schema 事实来源 — SampleRecord + TestEvent 双流。

corpus/samples.jsonl 每样本一行 SampleRecord（静态元数据 + 质量 + 语义确认 + 派生 status）
corpus/tests.jsonl   每次测试一行 TestEvent（追加事件流，天然增量）

任何写入前必须 validate。语义挖掘 skill v2 只产出 ①②（plaintext / semantic_bypass），
③④（encoding_bypass / combo）与 encodings 字段为未来 encoding-bypass skill 预留。
"""
from . import util

SCHEMA_VERSION = 2

SCENARIOS = ["sqli", "cmdi", "xss", "upload", "log4j2"]
CATEGORIES = ["plaintext", "semantic_bypass", "encoding_bypass", "combo"]
LAYERS = ["lexical", "syntactic", "semantic", "protocol", "encoding"]
SOURCES = ["ai", "template", "human", "migrated"]
QUALITY_LEVELS = {
    "effectiveness": ["S", "A", "B", "F"],
    "harmfulness": ["L1", "L2", "L3", "L4", "L5"],
    "insight": ["S", "A", "B", "C", "F"],
    "usability": ["S", "A", "B", "C", "F"],
}
OVERALL_LEVELS = ["high", "medium", "low", "boundary_marker"]
DECISIONS = ["passed", "blocked", "ambiguous", "rate_limited"]
STATUSES = ["pending", "passed", "blocked", "ambiguous", "verifying", "obsolete"]
DEFAULT_PLACEMENT = "query"


# ── SampleRecord ────────────────────────────────────────────────

def sample_id_of(payload, transport="direct", placement=DEFAULT_PLACEMENT, primitive_ids=()):
    """确定性内容哈希：相同载荷/运输/位置/原语 → 相同 id（去重）。"""
    return util.sha1_id("sample", payload, transport, placement, ",".join(sorted(primitive_ids)))


def build_sample(*, payload, scenario, category, mechanism, generation, quality,
                 semantic_confirmation, context=None, intent=None, tags=None,
                 seed_id=None, status="pending", created_by="semantic-mining@v2"):
    """由探针构建 SampleRecord。payload 必须非空。"""
    if context is None:
        context = {"transport": "direct", "placements": [DEFAULT_PLACEMENT],
                   "http": {"method": "GET", "path": "/", "params": {"q": "${payload}"}}}
    placements = context.get("placements") or [DEFAULT_PLACEMENT]
    primitive_ids = [p.get("id", "") for p in (mechanism or {}).get("primitives", [])]
    rec = {
        "schema_version": SCHEMA_VERSION,
        "kind": "sample",
        "sample_id": sample_id_of(payload, context.get("transport", "direct"),
                                  placements[0], primitive_ids),
        "seed_id": seed_id,
        "scenario": scenario,
        "category": category,
        "payload": {"raw": payload, "length": len(payload)},
        "intent": intent or {"attack": "", "target": "", "success_hint": ""},
        "context": context,
        "mechanism": mechanism or {"layers": [], "primitives": [], "encodings": [], "summary": ""},
        "generation": generation or {"source": "ai", "reason": ""},
        "quality": quality,
        "semantic_confirmation": semantic_confirmation
        or {"method": "knowledge", "result": True, "evidence": ""},
        "tags": tags or [],
        "status": status,
        "created_at": util.now_iso(),
        "created_by": created_by,
    }
    return rec


DEFAULT_QUALITY = {"effectiveness": "B", "harmfulness": "L3", "insight": "B",
                   "usability": "B", "overall": "medium", "notes": "AI 未提供质量评估"}


def build_sample_from_probe(probe, status="pending"):
    """探针（AI/模板产出，无 id）→ SampleRecord。quality/semantic_confirmation 缺省自动补。"""
    quality = probe.get("quality") or dict(DEFAULT_QUALITY)
    if not quality.get("overall"):
        quality = dict(DEFAULT_QUALITY)
    confirm = probe.get("semantic_confirmation") or {"method": "knowledge", "result": True, "evidence": ""}
    return build_sample(
        payload=probe["payload"],
        scenario=probe["scenario"],
        category=probe.get("category", "semantic_bypass"),
        mechanism=probe.get("mechanism", {}),
        generation=probe.get("generation", {}),
        quality=quality,
        semantic_confirmation=confirm,
        context=probe.get("context"),
        intent=probe.get("intent"),
        tags=probe.get("tags"),
        seed_id=probe.get("seed_id"),
        status=status,
    )


def validate_sample(rec) -> list:
    """返回错误列表；空 = 合法。"""
    errs = []
    if rec.get("kind") != "sample":
        errs.append("kind != sample")
    if rec.get("schema_version") != SCHEMA_VERSION:
        errs.append("schema_version != %s" % SCHEMA_VERSION)
    if rec.get("scenario") not in SCENARIOS:
        errs.append("bad scenario %r" % rec.get("scenario"))
    if rec.get("category") not in CATEGORIES:
        errs.append("bad category %r" % rec.get("category"))
    raw = (rec.get("payload") or {}).get("raw", "")
    if not isinstance(raw, str) or not raw.strip():
        errs.append("payload.raw empty")
    layers = (rec.get("mechanism") or {}).get("layers", [])
    for l in layers:
        if l not in LAYERS:
            errs.append("bad layer %r" % l)
    prims = (rec.get("mechanism") or {}).get("primitives", [])
    if not isinstance(prims, list) or not all(isinstance(p, dict) and p.get("id") for p in prims):
        errs.append("mechanism.primitives must be [{id,...}]")
    if not (rec.get("generation") or {}).get("reason"):
        errs.append("generation.reason required")
    if (rec.get("generation") or {}).get("source") not in SOURCES:
        errs.append("bad generation.source %r" % (rec.get("generation") or {}).get("source"))
    q = rec.get("quality") or {}
    if q.get("overall") not in OVERALL_LEVELS:
        errs.append("quality.overall must be %s" % OVERALL_LEVELS)
    if rec.get("status") not in STATUSES:
        errs.append("bad status %r" % rec.get("status"))
    return errs


# ── TestEvent ──────────────────────────────────────────────────

def build_test(*, sample_id, run_id, round_num, target, result):
    """target={name,ip,host,placement}; result={http_status,waf_decision,block_signals,latency_ms,error}"""
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "test",
        "test_id": "t_" + util.sha1_id(sample_id, run_id, util.now_iso(),
                                       target.get("placement", DEFAULT_PLACEMENT)),
        "sample_id": sample_id,
        "run_id": run_id,
        "round": round_num,
        "target": target,
        "result": result,
        "timestamp": util.now_iso(),
    }


def validate_test(rec) -> list:
    errs = []
    if rec.get("kind") != "test":
        errs.append("kind != test")
    if rec.get("schema_version") != SCHEMA_VERSION:
        errs.append("schema_version != %s" % SCHEMA_VERSION)
    if not rec.get("sample_id"):
        errs.append("sample_id required")
    res = rec.get("result") or {}
    if res.get("waf_decision") not in DECISIONS:
        errs.append("bad waf_decision %r" % res.get("waf_decision"))
    return errs


# ── 加载与派生状态 ─────────────────────────────────────────────

def load_samples(path) -> dict:
    """sample_id -> SampleRecord 内存索引。"""
    out = {}
    for rec in util.read_jsonl(path):
        if rec.get("kind") == "sample":
            out[rec["sample_id"]] = rec
    return out


def latest_tests_for(sample_id, tests):
    return [t for t in tests if t.get("sample_id") == sample_id]


def derive_status(sample, tests) -> str:
    """由该样本的最新测试事件派生 status。"""
    if not tests:
        return "pending"
    last = max(tests, key=lambda t: t.get("timestamp", ""))
    decision = (last.get("result") or {}).get("waf_decision")
    if decision == "passed":
        if sample.get("scenario") in ("xss", "log4j2"):
            return "verifying"  # 需浏览器/OOB 二次确认
        return "passed"
    if decision == "blocked":
        return "blocked"
    return "ambiguous"
