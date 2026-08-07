"""
executor_schema.py — semantic-mining Skill 执行层的单一格式来源。

本文件定义了 executor.py 输入/输出、samples/results/*.jsonl、
logs/probe_log.jsonl 等所有执行相关文件的字段名、枚举值和校验规则。

SKILL.md 和 executor.py 均引用此文件，不各自定义格式，避免漂移。
"""

from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════
# 运输模式
# ═══════════════════════════════════════════════════════════════

TRANSPORT_DIRECT = "direct"    # GET，payload 作为 URL 查询参数
TRANSPORT_HEADER = "header"    # GET，payload 作为自定义 HTTP 头
TRANSPORT_API = "api"          # POST JSON 到 /api/attack.php（WAF 白名单端点）
TRANSPORT_MULTIPART = "multipart"  # POST multipart/form-data（Upload 场景）
VALID_TRANSPORTS = {TRANSPORT_DIRECT, TRANSPORT_HEADER, TRANSPORT_API, TRANSPORT_MULTIPART}

# ═══════════════════════════════════════════════════════════════
# WAF 注意力级别
# ═══════════════════════════════════════════════════════════════

ATTENTION_LOW = "low"          # WAF 放行（200，无拦截特征）
ATTENTION_HIGH = "high"        # WAF 拦截（403 或 WAF_SCORE >= 阈值）
ATTENTION_UNKNOWN = "?"        # 未探测 / 网络错误
VALID_ATTENTIONS = {ATTENTION_LOW, ATTENTION_HIGH, ATTENTION_UNKNOWN}

# ═══════════════════════════════════════════════════════════════
# 结果分类（executor 机械判定，不做语义判断）
# ═══════════════════════════════════════════════════════════════

CLASS_DATA_EXTRACTION = "data_extraction"       # 200 + 新 flag 出现在响应中（基线外）
CLASS_WAF_BLOCKED = "waf_blocked"               # 403 或 WAF_SCORE >= 5
CLASS_NO_EFFECT = "no_effect"                   # 200 但无新 flag，无 payload 反射
CLASS_FALSE_POSITIVE = "false_positive"          # flag 命中但全在基线中（页面模板）
CLASS_XSS_REFLECTED = "xss_reflected"            # XSS: payload 未转义出现在响应中
CLASS_XSS_BLOCKED_OR_ESCAPED = "xss_blocked_or_escaped"  # XSS: payload 未出现或已转义
CLASS_BLIND_DIFF = "blind_diff"                  # SQLi L2: 行排序变化（布尔盲注）
CLASS_NETWORK_ERROR = "network_error"            # 连接失败 / 超时
CLASS_HTTP_ERROR = "http_error"                  # 非 200/403 状态码

VALID_CLASSIFICATIONS = {
    CLASS_DATA_EXTRACTION,
    CLASS_WAF_BLOCKED,
    CLASS_NO_EFFECT,
    CLASS_FALSE_POSITIVE,
    CLASS_XSS_REFLECTED,
    CLASS_XSS_BLOCKED_OR_ESCAPED,
    CLASS_BLIND_DIFF,
    CLASS_NETWORK_ERROR,
    CLASS_HTTP_ERROR,
}

# ═══════════════════════════════════════════════════════════════
# 探针输入格式（executor.py --input）
# ═══════════════════════════════════════════════════════════════

PROBE_INPUT_FIELDS = {
    "id": str,          # 探针唯一标识（如 "s1"）
    "payload": str,     # 攻击载荷（原始字符串，executor 负责 URL 编码）
    "category": str,    # 探针类别（如 "separator_variants"）
    "dimension": str,   # 探测维度（如 "separator"）
    "variant": str,     # 维度变体（如 "|"）
}

# header transport 额外字段
PROBE_HEADER_FIELD = "header_name"  # 注入的目标 HTTP 头名（如 "User-Agent"）

# multipart transport 额外字段（可选，有默认值）
PROBE_FILENAME = "filename"        # 上传文件名（默认 "shell.php"）
PROBE_MIME_TYPE = "mime_type"      # Content-Type（默认 "application/octet-stream"）
PROBE_FILE_CONTENT = "file_content"  # 文件内容（默认使用 payload）

# ═══════════════════════════════════════════════════════════════
# 结果输出格式（executor.py --output → samples/results/<run_id>.jsonl）
# ═══════════════════════════════════════════════════════════════

RESULT_OUTPUT_FIELDS = [
    # 来自输入探针
    "id",                # str
    "payload",           # str
    "category",          # str
    "dimension",         # str
    "variant",           # str
    # 运行元数据
    "run_id",            # str, 如 "cmdi_r1_20260731_100000"
    "round",             # int
    "step",              # int (1-4)
    "scenario",          # str: cmdi|sqli|upload|xss|log4j2
    "transport",         # str: direct|header|api|multipart
    # HTTP 响应
    "url",               # str, 实际请求的完整 URL
    "http_status",       # int
    "flag_hit",          # bool
    "flag_value",        # str|null
    "baseline_flag",     # bool — 该 flag 是否在基线中
    "waf_attention",     # str: low|high|?
    "classification",    # str (见 VALID_CLASSIFICATIONS)
    "response_snippet",  # str, 响应体前 N 字符
    "response_size",     # int, 响应体字节数
    "response_time_ms",  # int
    # WAF 响应头（从 HTTP 头或 API JSON 提取）
    "waf_blocked",       # bool, X-WAF-Blocked 头
    "waf_score_total",   # int|null
    "waf_score_sqli",    # int|null
    "waf_score_xss",     # int|null
    "waf_score_rce",     # int|null
    "waf_score_lfi",     # int|null
    "waf_rule_id",       # str|null, 触发的规则 ID
    # 错误
    "error",             # str|null
    # 时间戳
    "timestamp",         # str, ISO 8601
]

# ═══════════════════════════════════════════════════════════════
# 质量评分字段（AI 在第 3 步填写，写入 samples/batches/<run_id>.jsonl）
# ═══════════════════════════════════════════════════════════════

QUALITY_EFFECTIVENESS = {"S", "A", "B", "F"}
QUALITY_HARMFULNESS = {"L1", "L2", "L3", "L4", "L5"}
QUALITY_INSIGHT = {"S", "A", "B", "C", "F"}
QUALITY_USABILITY = {"S", "A", "B", "C", "F"}

BATCH_FIELDS = [
    "run_id", "round", "scenario", "payload", "category",
    "dimensions", "differential_primitive", "generation_reason",
    "quality_scores",  # {"effectiveness": "S", "harmfulness": "L4", "insight": "A", "usability": "S"}
    "overall_quality",  # "high" | "boundary_marker"
]

# ═══════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════

def now_iso() -> str:
    """返回当前 UTC ISO 8601 时间戳字符串。"""
    return datetime.now(timezone.utc).isoformat()


def validate_probe(probe: dict) -> List[str]:
    """校验单条探针输入，返回错误列表（空列表 = 有效）。"""
    errors = []
    for field, expected_type in PROBE_INPUT_FIELDS.items():
        if field not in probe:
            errors.append(f"缺少必需字段: {field}")
        elif not isinstance(probe[field], expected_type):
            errors.append(f"字段 {field} 类型错误: 期望 {expected_type.__name__}, 实际 {type(probe[field]).__name__}")
    if not probe.get("payload"):
        errors.append("payload 不能为空")
    return errors


def validate_result(result: dict) -> List[str]:
    """校验单条结果输出，返回错误列表（空列表 = 有效）。"""
    errors = []
    for field in ["id", "http_status", "classification", "waf_attention"]:
        if field not in result:
            errors.append(f"结果缺少必需字段: {field}")
    if result.get("classification") and result["classification"] not in VALID_CLASSIFICATIONS:
        errors.append(f"无效 classification: {result['classification']}")
    if result.get("waf_attention") and result["waf_attention"] not in VALID_ATTENTIONS:
        errors.append(f"无效 waf_attention: {result['waf_attention']}")
    return errors


def build_result(
    probe: dict,
    run_id: str,
    round_num: int,
    step: int,
    scenario: str,
    transport: str,
    url: str,
    http_status: int,
    classification: str,
    waf_attention: str,
    flag_hit: bool = False,
    flag_value: Optional[str] = None,
    baseline_flag: bool = False,
    response_snippet: str = "",
    response_size: int = 0,
    response_time_ms: int = 0,
    waf_blocked: bool = False,
    waf_score_total: Optional[int] = None,
    waf_score_sqli: Optional[int] = None,
    waf_score_xss: Optional[int] = None,
    waf_score_rce: Optional[int] = None,
    waf_score_lfi: Optional[int] = None,
    waf_rule_id: Optional[str] = None,
    error: Optional[str] = None,
) -> dict:
    """构造符合规范的结果 dict。"""
    return {
        "id": probe.get("id", ""),
        "payload": probe.get("payload", ""),
        "category": probe.get("category", ""),
        "dimension": probe.get("dimension", ""),
        "variant": probe.get("variant", ""),
        "run_id": run_id,
        "round": round_num,
        "step": step,
        "scenario": scenario,
        "transport": transport,
        "url": url,
        "http_status": http_status,
        "flag_hit": flag_hit,
        "flag_value": flag_value,
        "baseline_flag": baseline_flag,
        "waf_attention": waf_attention,
        "classification": classification,
        "response_snippet": response_snippet[:300],
        "response_size": response_size,
        "response_time_ms": response_time_ms,
        "waf_blocked": waf_blocked,
        "waf_score_total": waf_score_total,
        "waf_score_sqli": waf_score_sqli,
        "waf_score_xss": waf_score_xss,
        "waf_score_rce": waf_score_rce,
        "waf_score_lfi": waf_score_lfi,
        "waf_rule_id": waf_rule_id,
        "error": error,
        "timestamp": now_iso(),
    }
