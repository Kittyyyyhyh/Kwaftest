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
    """UN/**/ION — 关键字注释拆分（仅 sqli；XSS 的属性名不能用 /**/ 拆分，会失效）。"""
    if scenario != "sqli":
        return None
    kw, idx = _find_keyword(payload, SQL_KEYWORDS, case_insensitive=True)
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
    if scenario == "cmdi":
        # shell 引号拆分：包裹中间字符 → c'a't（c'at / ca't 是未闭合引号，语法错误）
        mid = max(1, len(kw) // 2)
        if mid >= len(kw):
            return None
        split = kw[:mid] + "'" + kw[mid] + "'" + kw[mid + 1:]
        return payload[:idx] + split + payload[idx + len(kw):]
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
    """无害命令稀释：:;true <payload>（payload 开头是分隔符）或 :;true && <payload>。

    不能无脑 `:;true && `：若 payload 以 ;|& 开头会拼成 `true && ;`（语法错误）。
    """
    if scenario != "cmdi":
        return None
    if payload[:1] in (";", "|", "&"):
        return ":;true " + payload
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


# ── 组合派生：全关键字 / 多层矩阵（把单技法变换放大成深度攻击）─────────

def _kw_pattern(kws, min_len=3):
    """构建单遍正则（长关键字优先，避免子串误命中），一次替换所有出现。"""
    import re
    ordered = sorted((k for k in kws if len(k) >= min_len), key=len, reverse=True)
    if not ordered:
        return None
    return re.compile("(" + "|".join(re.escape(k) for k in ordered) + ")", re.IGNORECASE)


def _split_occurrences(payload, kws, joiner, min_len=3):
    """对 payload 中所有命中关键字做中点拆分（单遍，不重复匹配插入内容）。"""
    pat = _kw_pattern(kws, min_len)
    if pat is None:
        return None
    def _repl(m):
        g = m.group(0)
        mid = max(1, len(g) // 2)
        return g[:mid] + joiner + g[mid:]
    out = pat.sub(_repl, payload)
    return out if out != payload else None


def t_comment_split_all(payload, scenario):
    """UN/**/ION/**/SEL/**/ECT — 所有关键字注释拆分（深度，仅 sqli）。"""
    if scenario != "sqli":
        return None
    return _split_occurrences(payload, SQL_KEYWORDS, "/**/")


def t_version_comment_all(payload, scenario):
    """/*!50000UNION*//*!50000SELECT*/ — 所有关键字版本注释包裹。"""
    if scenario != "sqli":
        return None
    pat = _kw_pattern(SQL_KEYWORDS)
    if pat is None:
        return None
    out = pat.sub(lambda m: "/*!50000%s*/" % m.group(0), payload)
    return out if out != payload else None


def t_double_write_all(payload, scenario):
    """UNIunionONSELselectECT — 所有关键字双重写。"""
    if scenario != "sqli":
        return None
    pat = _kw_pattern(SQL_KEYWORDS)
    if pat is None:
        return None
    out = pat.sub(lambda m: m.group(0) + m.group(0).lower(), payload)
    return out if out != payload else None


def t_quote_split_all(payload, scenario):
    """UN'I''ON' SEL'ECT' — 所有关键字引号拆分。"""
    if scenario == "sqli":
        return _split_occurrences(payload, SQL_KEYWORDS, "'")
    if scenario == "cmdi":
        return _split_occurrences(payload, CMDI_COMMANDS, "'", min_len=2)
    return None


def t_blank_matrix(payload, scenario):
    """空格 → %0a/%09/%0b/%a0 轮换分隔符矩阵（深度 whitespace）。"""
    if scenario != "sqli" or " " not in payload:
        return None
    seps = ["%0a", "%09", "%0b", "%a0", "%0c"]
    out, i = [], 0
    for ch in payload:
        if ch == " ":
            out.append(seps[i % len(seps)])
            i += 1
        else:
            out.append(ch)
    return "".join(out) if out != payload else None


def t_compose_version_quote(payload, scenario):
    """/*!50000UN'ION*/ — 版本注释 × 引号拆分组合（配方 stack 示例）。"""
    if scenario != "sqli":
        return None
    kw, idx = _find_keyword(payload, ["UNION", "SELECT", "FROM", "WHERE"], case_insensitive=True)
    if kw is None or len(kw) < 4:
        return None
    mid = max(1, len(kw) // 2)
    return payload[:idx] + "/*!50000%s*/" % (kw[:mid] + "'" + kw[mid:]) + payload[idx + len(kw):]


def t_compose_double_quote(payload, scenario):
    """UNIunion'ON' — 双写 × 引号拆分组合。"""
    if scenario != "sqli":
        return None
    kw, idx = _find_keyword(payload, ["UNION", "SELECT", "FROM"], case_insensitive=True)
    if kw is None or len(kw) < 4:
        return None
    mid = max(1, len(kw) // 2)
    first, rest = kw[:mid], kw[mid:]
    return payload[:idx] + first + first.lower() + "'" + rest + payload[idx + len(kw):]


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
    {"id": "tag_case",          "layer": "lexical",   "scenarios": ["xss"],           "fn": t_tag_case},
    # 组合派生（多层/全关键字）
    {"id": "comment_split_all", "layer": "lexical",   "scenarios": ["sqli", "xss"],   "fn": t_comment_split_all},
    {"id": "version_comment_all", "layer": "lexical", "scenarios": ["sqli"],          "fn": t_version_comment_all},
    {"id": "double_write_all",  "layer": "lexical",   "scenarios": ["sqli"],          "fn": t_double_write_all},
    {"id": "quote_split_all",   "layer": "lexical",   "scenarios": ["sqli", "cmdi"],  "fn": t_quote_split_all},
    {"id": "blank_matrix",      "layer": "lexical",   "scenarios": ["sqli"],          "fn": t_blank_matrix},
    {"id": "compose_version_quote", "layer": "lexical", "scenarios": ["sqli"],        "fn": t_compose_version_quote},
    {"id": "compose_double_quote",  "layer": "lexical", "scenarios": ["sqli"],        "fn": t_compose_double_quote},
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


def derive(seeds, max_depth=3, max_variants=None):
    """种子列表 → 派生变体列表（去重）。

    迭代链式组合（深度 max_depth）：单变换 → 逐层叠加，注释累积到 mechanism。
    用"全关键字/组合"变换可一次性派生出多层矩阵攻击，而非单技法换皮。
    """
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
        # 迭代链式组合：基于前一深度变体再叠加变换（允许同变换作用于不同位置）
        if max_depth >= 2:
            frontier = variants[:40]
            for _ in range(2, max_depth + 1):
                nxt = []
                for v1 in frontier:
                    for t2 in TRANSFORMS:
                        if scenario not in t2["scenarios"]:
                            continue
                        v2 = apply_transform(t2["id"], v1["payload"]["raw"], scenario)
                        if not v2 or any(x["payload"]["raw"] == v2 for x in variants):
                            continue
                        chained = _variant_record(v1, v2, t2["id"], t2["layer"])
                        variants.append(chained)
                        nxt.append(chained)
                frontier = nxt[:40]
                if not frontier:
                    break
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
