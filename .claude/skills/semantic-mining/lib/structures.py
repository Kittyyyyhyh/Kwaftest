"""攻击结构分类与覆盖信号 — 新颖性的数据基础。

"治本"机制：样本收敛的根因是生成没有"结构新颖性"信号。
本模块把每条样本按【攻击语句结构】分类，产出结构覆盖报告，
让生成者（AI）每轮先读"哪些结构试烂了、哪些零通过"，再针对性设计。

用法:
  from lib import structures
  coverage = structures.coverage_report(samples, "sqli")
  gaps = structures.novelty_gaps(coverage)   # 零通过/低覆盖结构 → 设计目标
"""
import collections


def sqli_struct(raw: str) -> str:
    r = raw.upper()
    if "GET_LOCK" in r or "IS_FREE_LOCK" in r or "RELEASE_LOCK" in r:
        return "锁函数盲注"
    if "SLEEP" in r or "BENCHMARK" in r:
        return "时间盲注"
    if any(x in r for x in ("EXTRACTVALUE", "UPDATEXML", "GTID", "ST_X", "POINT(", "GEOMETRYCOLLECTION")):
        return "报错/几何注入"
    if "PREPARE" in r or "EXECUTE" in r:
        return "预处理语句"
    if ";" in r:
        return "堆叠查询"
    if "TABLE " in r or "VALUES" in r or "HANDLER" in r:
        return "TABLE/VALUES/HANDLER"
    if "WITH " in r:
        return "CTE"
    if "EXCEPT" in r or "INTERSECT" in r:
        return "集合运算"
    if "UNION" in r:
        return "UNION联合"
    if "REGEXP" in r or "RLIKE" in r:
        return "REGEXP盲注"
    if any(x in r for x in ("GREATEST", "CASE", "ELT", "FIELD", "<=>", "BIT_COUNT", "<<", ">>")):
        return "函数布尔盲注"
    if any(x in r for x in ("@@", "UUID", "ROW_COUNT", "FOUND_ROWS")):
        return "系统/状态函数"
    if "JSON" in r:
        return "JSON函数"
    if any(x in r for x in ("SUBSTRING", "SUBSTR", "MID(")):
        return "字符函数盲注"
    if "CAST" in r or "CONVERT" in r:
        return "类型转换"
    if "LIKE" in r:
        return "LIKE盲注"
    return "基础/子查询"


def cmdi_struct(raw: str) -> str:
    r = raw
    if "curl" in r or "wget" in r or "nslookup" in r or "dig" in r or "/dev/tcp" in r:
        return "OOB外带"
    if "nc " in r or "netcat" in r:
        return "反弹shell"
    if "perl" in r or "python" in r or "node" in r or "php " in r or "awk" in r or "sed " in r or "ruby" in r:
        return "解释器"
    if "<(" in r:
        return "进程替换"
    if "<<<" in r or "<<" in r:
        return "here-string/heredoc"
    if "$(" in r:
        return "命令替换"
    if "base64" in r or "xxd" in r or "hex" in r:
        return "编码喂入"
    if "$((16#" in r or "$((1" in r:
        return "算术构造"
    if "${PATH" in r or "IFS" in r or "$@" in r:
        return "环境变量/空参"
    if "\\" in r:
        return "反斜杠拆分"
    if "'" in r:
        return "引号拆分"
    if "?" in r:
        return "glob通配"
    if "whoami" in r:
        return "whoami"
    if "cat " in r or "/etc/" in r:
        return "读文件"
    return "基础/其他"


def classify(payload, scenario):
    return sqli_struct(payload) if scenario == "sqli" else cmdi_struct(payload)


def coverage_report(samples, scenario):
    """返回 {结构: {total, passed, rate}}。"""
    cov = collections.defaultdict(lambda: {"total": 0, "passed": 0})
    for s in samples:
        if s["scenario"] != scenario:
            continue
        st = classify(s["payload"]["raw"], scenario)
        cov[st]["total"] += 1
        if s["status"] in ("passed", "verifying"):
            cov[st]["passed"] += 1
    for st, d in cov.items():
        d["rate"] = round(d["passed"] / d["total"], 2) if d["total"] else 0
    return dict(cov)


def novelty_gaps(coverage, min_total=5):
    """返回设计目标：零通过(≥min_total 测试仍 0 过) + 低覆盖(<min_total 未充分测) + 高熵(boundary)。"""
    zero = [s for s, d in coverage.items() if d["total"] >= min_total and d["passed"] == 0]
    low = [s for s, d in coverage.items() if d["total"] < min_total]
    boundary = sorted(
        (s for s, d in coverage.items() if 0 < d["rate"] < 0.5),
        key=lambda s: -coverage[s]["rate"] * (1 - coverage[s]["rate"]))
    return {"zero_pass": zero, "low_coverage": low, "boundary": boundary}
