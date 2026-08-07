"""模板派生引擎（Layer2）— 对种子 payload 施加语义保持变换批量派生变体。

每个变换是确定性纯函数：输入 (payload, scenario)，输出变体或 None（不适用）。
变换只做词法/语法/语义层表达变换，**不含编码维度**（编码归未来 encoding-bypass skill）。

derive(seeds, ...) 对每种子：单变换 → 链式组合（深度2）→ 去重 → 过滤超长。
派生结果仍是 SampleRecord（category=semantic_bypass，generation.source=template）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import schema  # noqa: E402
from lib import util  # noqa: E402

MAX_PAYLOAD_LEN = 2048

# 同义近义词表（knowledge/synonyms.json）—— 成功样本迭代的燃料
SYNONYMS = util.load_json(str(Path(__file__).resolve().parent.parent / "knowledge" / "synonyms.json"), {})

# 各场景关键字表（词法变换的作用目标）
SQL_KEYWORDS = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
                "TABLE", "NULL", "INFORMATION_SCHEMA", "SCHEMATA", "GROUP", "HAVING",
                "LIMIT", "SLEEP", "BENCHMARK", "IF", "CASE", "WHEN", "THEN", "ELSE",
                "END", "CONCAT", "SUBSTR", "MID", "ASCII", "CHAR", "LOAD_FILE",
                "EXTRACTVALUE", "UPDATEXML", "GTID_SUBSET", "GTID_SUBTRACT",
                "NAME_CONST", "PREPARE", "EXECUTE", "SET", "JOIN", "VERSION",
                "DATABASE", "USER", "SESSION_USER", "CURRENT_USER", "PASSWORD"]
CMDI_COMMANDS = ["cat", "cut", "ls", "whoami", "id", "dd", "tee", "sort", "awk",
                 "tr", "file", "head", "tail", "base64", "nslookup", "curl", "wget",
                 "find", "grep", "sed", "echo", "bash", "sh", "chmod", "python",
                 "perl", "nc", "netcat", "sleep", "ping", "fold", "hexdump", "cmp",
                 "diff", "strings", "wc", "uname", "hostname", "readlink", "realpath"]
XSS_HANDLERS = ["onerror", "onload", "onfocus", "ontoggle", "onclick", "onscroll",
                "onstart", "onmouseover", "onauxclick", "onpointerenter"]
XSS_TAGS = ["script", "img", "svg", "iframe", "details", "input", "video", "marquee",
            "body", "a", "form", "noscript", "template", "source"]


# ── 变换实现 ──────────────────────────────────────────────────

def _find_keyword(payload, kw_list, case_insensitive=False):
    """返回 payload 中第一个命中的关键字（原文）。"""
    for kw in kw_list:
        if case_insensitive:
            low = payload.lower()
            idx = low.find(kw.lower())
            if idx >= 0:
                return kw, idx
        else:
            idx = payload.find(kw)
            if idx >= 0:
                return kw, idx
    return None, -1


def _insert_split(payload, kw, idx, joiner):
    """把关键字从中点拆开插入 joiner。"""
    mid = max(1, len(kw) // 2)
    first = kw[:mid]
    rest = kw[mid:]
    return payload[:idx] + first + joiner + rest + payload[idx + len(kw):]


def t_comment_split(payload, scenario):
    """UN/**/ION — 关键字注释拆分。"""
    if scenario not in ("sqli", "xss"):
        return None
    kw, idx = _find_keyword(payload, SQL_KEYWORDS if scenario == "sqli" else XSS_HANDLERS, case_insensitive=True)
    if kw is None or len(kw) < 3:
        return None
    return _insert_split(payload, kw, idx, "/**/")


def t_version_comment(payload, scenario):
    """/*!50000UNION*/ — MySQL 版本注释。"""
    if scenario != "sqli":
        return None
    kw, idx = _find_keyword(payload, SQL_KEYWORDS, case_insensitive=True)
    if kw is None or len(kw) < 3:
        return None
    inner = payload[idx:idx + len(kw)]
    return payload[:idx] + "/*!50000%s*/" % inner + payload[idx + len(kw):]


def t_whitespace_sub(payload, scenario):
    """空格 → %a0（MySQL 视为分隔符）。"""
    if scenario != "sqli":
        return None
    if " " not in payload:
        return None
    return payload.replace(" ", "%a0", 1)


def t_case_flip(payload, scenario):
    """关键字大小写混写。"""
    kws = SQL_KEYWORDS if scenario == "sqli" else (XSS_HANDLERS if scenario == "xss" else None)
    if kws is None:
        return None
    kw, idx = _find_keyword(payload, kws, case_insensitive=True)
    if kw is None:
        return None
    flipped = "".join(c.upper() if c.islower() else c.lower() for c in kw)
    return payload[:idx] + flipped + payload[idx + len(kw):]


def t_double_write(payload, scenario):
    """UNIunionON SELselectECT — 关键字双重写。"""
    if scenario != "sqli":
        return None
    kw, idx = _find_keyword(payload, SQL_KEYWORDS, case_insensitive=True)
    if kw is None or len(kw) < 3:
        return None
    return payload[:idx] + kw + kw.lower() + payload[idx + len(kw):]


def t_operator_swap(payload, scenario):
    """AND→&& / OR→|| — 运算符替代。"""
    if scenario != "sqli":
        return None
    low = payload.lower()
    if " and " in low:
        idx = low.find(" and ")
        return payload[:idx] + " && " + payload[idx + 5:]
    if " or " in low:
        idx = low.find(" or ")
        return payload[:idx] + " || " + payload[idx + 4:]
    if "=" in payload:
        idx = payload.find("=")
        return payload[:idx] + " LIKE " + payload[idx + 1:]
    return None


def t_null_replacement(payload, scenario):
    """NULL → char(0x4e554c4c) / false / 0。"""
    if scenario != "sqli":
        return None
    low = payload.lower()
    idx = low.find("null")
    if idx < 0:
        return None
    return payload[:idx] + "char(0x4e554c4c)" + payload[idx + 4:]


def t_quote_split(payload, scenario):
    """c'a't / UN'ION' — 引号拆分。"""
    if scenario not in ("sqli", "cmdi"):
        return None
    kws = CMDI_COMMANDS if scenario == "cmdi" else SQL_KEYWORDS
    kw, idx = _find_keyword(payload, kws, case_insensitive=(scenario == "sqli"))
    if kw is None or len(kw) < 2:
        return None
    return _insert_split(payload, kw, idx, "'")


def t_backslash_split(payload, scenario):
    """\\c\\a\\t — 反斜杠拆分（CMDi）。"""
    if scenario != "cmdi":
        return None
    kw, idx = _find_keyword(payload, CMDI_COMMANDS)
    if kw is None or len(kw) < 2:
        return None
    return _insert_split(payload, kw, idx, "\\")


def t_ifs_sub(payload, scenario):
    """cat${IFS}/path — 空白替换为 ${IFS}。"""
    if scenario != "cmdi":
        return None
    if " " not in payload:
        return None
    return payload.replace(" ", "${IFS}", 1)


def t_logical_chain(payload, scenario):
    """无害命令稀释：:;true && <payload>。"""
    if scenario != "cmdi":
        return None
    return ":;true && " + payload


def t_handler_split(payload, scenario):
    """on/**/error — XSS 属性名注释切片。"""
    if scenario != "xss":
        return None
    kw, idx = _find_keyword(payload, XSS_HANDLERS, case_insensitive=True)
    if kw is None or len(kw) < 5:
        return None
    return _insert_split(payload, kw, idx, "/**/")


def t_tag_case(payload, scenario):
    """<ScRiPt> — 标签大小写。"""
    if scenario != "xss":
        return None
    for tag in XSS_TAGS:
        low = payload.lower()
        idx = low.find("<" + tag)
        if idx >= 0:
            t = payload[idx + 1:idx + 1 + len(tag)]
            flipped = "".join(c.upper() if c.islower() else c.lower() for c in t)
            return payload[:idx] + "<" + flipped + payload[idx + 1 + len(tag):]
    return None


# ── 目录 ──────────────────────────────────────────────────────

TRANSFORMS = [
    {"id": "comment_split",     "layer": "lexical",   "scenarios": ["sqli", "xss"],   "fn": t_comment_split},
    {"id": "version_comment",   "layer": "lexical",   "scenarios": ["sqli"],          "fn": t_version_comment},
    {"id": "whitespace_sub",    "layer": "lexical",   "scenarios": ["sqli"],          "fn": t_whitespace_sub},
    {"id": "case_flip",         "layer": "lexical",   "scenarios": ["sqli", "xss"],   "fn": t_case_flip},
    {"id": "double_write",      "layer": "lexical",   "scenarios": ["sqli"],          "fn": t_double_write},
    {"id": "operator_swap",     "layer": "syntactic", "scenarios": ["sqli"],          "fn": t_operator_swap},
    {"id": "null_replacement",  "layer": "syntactic", "scenarios": ["sqli"],          "fn": t_null_replacement},
    {"id": "quote_split",       "layer": "lexical",   "scenarios": ["sqli", "cmdi"],  "fn": t_quote_split},
    {"id": "backslash_split",   "layer": "lexical",   "scenarios": ["cmdi"],          "fn": t_backslash_split},
    {"id": "ifs_sub",           "layer": "lexical",   "scenarios": ["cmdi"],          "fn": t_ifs_sub},
    {"id": "logical_chain",     "layer": "syntactic", "scenarios": ["cmdi"],          "fn": t_logical_chain},
    {"id": "handler_split",     "layer": "lexical",   "scenarios": ["xss"],           "fn": t_handler_split},
    {"id": "tag_case",          "layer": "lexical",   "scenarios": ["xss"],           "fn": t_tag_case},
]

TRANSFORM_MAP = {t["id"]: t for t in TRANSFORMS}


def apply_transform(tid, payload, scenario):
    """应用单个变换；不适用返回 None。"""
    t = TRANSFORM_MAP.get(tid)
    if t is None or scenario not in t["scenarios"]:
        return None
    try:
        out = t["fn"](payload, scenario)
    except Exception:  # noqa: BLE001 变换防御
        return None
    if out is None or out == payload or len(out) > MAX_PAYLOAD_LEN:
        return None
    return out


def _variant_record(seed, new_payload, tid, layer):
    """种子 → 变体 SampleRecord。"""
    prim_id = "gen:" + tid
    mech = dict(seed.get("mechanism", {}))
    mech["layers"] = list(seed.get("mechanism", {}).get("layers", [])) + [layer]
    prims = list(seed.get("mechanism", {}).get("primitives", []))
    prims = prims + [{"id": prim_id, "kb_ref": "advanced_bypass.md"}]
    mech["primitives"] = prims
    mech["encodings"] = list(seed.get("mechanism", {}).get("encodings", []))
    gen = dict(seed.get("generation", {}))
    gen["source"] = "template"
    gen["template_ids"] = list(seed.get("generation", {}).get("template_ids", [])) + [tid]
    gen["reason"] = "模板派生 %s（种子 %s）：%s" % (tid, seed["seed_id"] or seed["sample_id"],
                                                   TRANSFORM_MAP[tid]["id"])
    rec = schema.build_sample_from_probe({
        "payload": new_payload,
        "scenario": seed["scenario"],
        "category": "semantic_bypass",
        "mechanism": mech,
        "generation": gen,
        "quality": dict(seed.get("quality", {})),
        "semantic_confirmation": dict(seed.get("semantic_confirmation", {})),
        "context": dict(seed.get("context", {})),
        "intent": dict(seed.get("intent", {})),
        "tags": list(seed.get("tags", [])) + [tid],
        "seed_id": seed["sample_id"],
    })
    return rec


def derive(seeds, max_depth=2, max_variants=None):
    """种子列表 → 派生变体列表（去重）。"""
    out = []
    seen = set()
    for seed in seeds:
        sid = seed["sample_id"]
        if sid in seen:
            continue
        seen.add(sid)
        out.append(seed)
        variants = []
        scenario = seed["scenario"]
        for t in TRANSFORMS:
            if scenario not in t["scenarios"]:
                continue
            v = apply_transform(t["id"], seed["payload"]["raw"], scenario)
            if v:
                variants.append(_variant_record(seed, v, t["id"], t["layer"]))
        # 链式组合（深度2）：先取单变换变体，再对它们施加同层/跨层第二变换
        if max_depth >= 2:
            chained = []
            for v1 in variants:
                for t2 in TRANSFORMS:
                    if scenario not in t2["scenarios"] or t2["id"] == v1["generation"]["template_ids"][-1]:
                        continue
                    v2 = apply_transform(t2["id"], v1["payload"]["raw"], scenario)
                    if v2 and v2 not in [x["payload"]["raw"] for x in chained]:
                        chained.append(_variant_record(seed, v2, t2["id"], t2["layer"]))
            variants.extend(chained)
        for v in variants:
            if v["sample_id"] in seen:
                continue
            seen.add(v["sample_id"])
            out.append(v)
    if max_variants:
        out = out[:max_variants]
    return out


# ── 同义近义迭代（对成功样本派生新表达）────────────────────────

def mutate_synonyms(payload, scenario, syns_per_key=2, max_variants=8):
    """对 payload 中命中的同义词键做"一换多"派生。

    返回 [(new_payload, key, synonym), ...]，每个命中键产出最多 syns_per_key 个变体。
    """
    cat = SYNONYMS.get(scenario, {})
    variants, seen = [], set()
    for group in cat.values():
        for key, syns in group.items():
            if key not in payload:
                continue
            made = 0
            for s in syns:
                new = payload.replace(key, s, 1)
                if new != payload and new not in seen and len(new) <= MAX_PAYLOAD_LEN:
                    seen.add(new)
                    variants.append((new, key, s))
                    made += 1
                    if made >= syns_per_key or len(variants) >= max_variants:
                        break
            if len(variants) >= max_variants:
                return variants
    return variants


def _synonym_record(seed, new_payload, key, syn):
    """成功样本 → 同义迭代变体 SampleRecord。"""
    mech = dict(seed.get("mechanism", {}))
    prims = list(mech.get("primitives", [])) + [
        {"id": "gen:synonym:%s" % key[:20], "kb_ref": "knowledge/synonyms.json"}]
    mech["primitives"] = prims
    mech["encodings"] = list(mech.get("encodings", []))
    gen = dict(seed.get("generation", {}))
    gen["source"] = "template"
    gen["template_ids"] = list(seed.get("generation", {}).get("template_ids", [])) + ["synonym_mutation"]
    gen["reason"] = "对成功样本 %s 的同义迭代：%s → %s（同意图不同表达）" % (
        seed["sample_id"][:10], key, syn)
    rec = schema.build_sample_from_probe({
        "payload": new_payload,
        "scenario": seed["scenario"],
        "category": "semantic_bypass",
        "mechanism": mech,
        "generation": gen,
        "quality": dict(seed.get("quality", {})),
        "semantic_confirmation": dict(seed.get("semantic_confirmation", {})),
        "context": dict(seed.get("context", {})),
        "intent": dict(seed.get("intent", {})),
        "tags": list(seed.get("tags", [])) + ["synonym_iter"],
        "seed_id": seed["sample_id"],
    })
    return rec


def derive_success_iteration(passed_samples, syns_per_key=2, max_variants_per_sample=8):
    """对已成功样本做同义近义迭代，派生新表达样本（skill 变强能力的实体）。

    两条腿：
      1. 同义替换（mutate_synonyms）—— 同意图不同表达
      2. 对已过样本施加词法/语法变换 —— 已知绕过模式的混淆加深
    passed_samples: status 为 passed/verifying 的 SampleRecord 列表。
    返回新的候选样本列表（去重由调用方做）。
    """
    out, seen = [], set()
    for s in passed_samples:
        scenario = s["scenario"]
        cands = []
        for new, key, syn in mutate_synonyms(s["payload"]["raw"], scenario,
                                             syns_per_key, max_variants_per_sample):
            cands.append(_synonym_record(s, new, key, syn))
        for t in TRANSFORMS:
            if scenario not in t["scenarios"]:
                continue
            v = apply_transform(t["id"], s["payload"]["raw"], scenario)
            if v:
                cands.append(_variant_record(s, v, t["id"], t["layer"]))
        for rec in cands:
            if rec["sample_id"] in seen:
                continue
            seen.add(rec["sample_id"])
            out.append(rec)
    return out
