#!/usr/bin/env python3
"""
目标环境发现脚本 — 探测 WAF/靶场，生成或验证 profile.json。

用法:
  # 交互式发现（每步提示确认）
  python3 discovery.py --url http://new-target.com:8090

  # 全自动（不提示）
  python3 discovery.py --url http://new-target.com:8090 --auto

  # 仅验证现有 profile
  python3 discovery.py --validate

  # 指定输出路径
  python3 discovery.py --url http://new-target.com:8090 --output samples/targets/new_profile.json

设计原则:
  - 零外部依赖，纯 Python 3 标准库
  - 探测结果写入 stdout，AI/用户可检查
  - 不确定的选项（如 flag 格式）在交互模式下提示确认
  - 所有 HTTP 请求使用 urllib（与 executor.py 一致）
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── 默认值 ────────────────────────────────────────────

DEFAULT_PROFILE_PATH = "samples/targets/profile.json"
DEFAULT_TIMEOUT = 10

# 已知的 flag 模式（按常见程度排序，用于自动发现）
KNOWN_FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"ctf\{[^}]+\}",
]

# 已知的 WAF 特征（响应体关键词 → WAF 身份）
WAF_FINGERPRINTS = {
    "ModSecurity": "modsecurity",
    "CRS": "owasp_crs",
    "Cloudflare": "cloudflare",
    "AWS WAF": "aws_waf",
    "Azure WAF": "azure_waf",
    "Akamai": "akamai",
}

# 常见场景名和对应的 URL 路径候选
SCENARIO_CANDIDATES = {
    "cmdi": ["cmdi", "cmd", "command", "rce", "exec"],
    "sqli": ["sqli", "sql", "sqli-labs", "sql-injection"],
    "upload": ["upload", "file-upload", "file_upload"],
    "xss": ["xss", "reflected", "stored"],
    "log4j2": ["log4j", "log4j2", "log4shell"],
}


# ═══════════════════════════════════════════════════════════════
# HTTP 工具
# ═══════════════════════════════════════════════════════════════

def http_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """GET 请求，返回 {status, headers, body, error}。"""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "headers": dict(resp.headers), "body": body, "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "headers": dict(e.headers) if hasattr(e, "headers") else {}, "body": body, "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


# ═══════════════════════════════════════════════════════════════
# 探测步骤
# ═══════════════════════════════════════════════════════════════

def step_connectivity(url: str) -> Dict[str, Any]:
    """步骤 1: 连通性检查。"""
    print(f"\n[1/6] 连通性检查: {url}")
    resp = http_get(url)
    if resp["error"]:
        print(f"  [ERROR] 不可达: {resp['error']}")
        return {"reachable": False, "error": resp["error"]}
    print(f"  [OK] HTTP {resp['status']}, {len(resp['body'])} bytes")
    return {"reachable": True, "status": resp["status"], "headers": resp["headers"]}


def step_url_structure(url_prefix: str) -> Dict[str, Any]:
    """步骤 2: URL 结构发现——探测场景路径和页面模式。"""
    print(f"\n[2/6] URL 结构发现")

    url_path_map = {}
    levels_found = set()
    page_pattern = None

    for scenario, candidates in SCENARIO_CANDIDATES.items():
        for candidate in candidates:
            # 尝试 level1.php 和 level2.php
            for level in [1, 2]:
                test_url = f"{url_prefix.rstrip('/')}/{candidate}/level{level}.php"
                resp = http_get(test_url)
                if resp["status"] == 200 and not resp["error"]:
                    if scenario not in url_path_map:
                        url_path_map[scenario] = candidate
                        levels_found.add(level)
                        page_pattern = "level{level}.php"
                        print(f"  [OK] {scenario} → /{candidate}/ (L{level} 可达)")
                    else:
                        levels_found.add(level)

            # 也尝试无 PHP 后缀的模式
            if scenario not in url_path_map:
                for level in [1, 2]:
                    test_url = f"{url_prefix.rstrip('/')}/{candidate}/{level}"
                    resp = http_get(test_url)
                    if resp["status"] == 200 and not resp["error"]:
                        url_path_map[scenario] = candidate
                        levels_found.add(level)
                        page_pattern = "{level}"
                        print(f"  [OK] {scenario} → /{candidate}/{level} (无后缀)")

            if scenario in url_path_map:
                break  # 找到就跳下一个场景

    if not url_path_map:
        print("  [WARN] 未发现任何场景页面——URL 结构可能不同于预期模式")
        print("  手动指定: --url-prefix + 场景路径映射")

    levels = sorted(levels_found) if levels_found else [1]
    return {
        "url_path_map": url_path_map,
        "levels": levels,
        "page_pattern": page_pattern or "level{level}.php",
    }


def step_params(url_prefix: str, url_path_map: Dict[str, str], levels: List[int]) -> Dict[str, Any]:
    """步骤 3: 参数名发现——解析页面 HTML 中的 <form> 和 <input>。"""
    print(f"\n[3/6] 参数发现")

    params = {}
    for scenario, path in url_path_map.items():
        params[scenario] = {}
        for level in levels:
            url = f"{url_prefix.rstrip('/')}/{path}/level{level}.php"
            resp = http_get(url)
            if resp["status"] != 200:
                continue

            body = resp["body"]

            # 检测 HTTP 方法
            method = "POST" if '<form method="POST"' in body or '<form method="post"' in body else "GET"
            enctype = None
            if 'multipart/form-data' in body:
                enctype = "multipart"
            elif method == "POST":
                enctype = "form"

            # 提取 <input> 的 name 属性
            input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            # 排除 hidden/submit/button 类型
            hidden_types = re.findall(
                r'<input[^>]+type=["\'](hidden|submit|button)["\'][^>]+name=["\']([^"\']+)["\']',
                body, re.IGNORECASE
            )
            hidden_names = {m[1] for m in hidden_types}

            visible_inputs = [n for n in input_names if n not in hidden_names]

            if visible_inputs:
                name = visible_inputs[0]
                params[scenario][f"level{level}"] = {"method": method, "name": name}
                if enctype:
                    params[scenario][f"level{level}"]["enctype"] = enctype
                print(f"  [OK] {scenario} L{level}: {method} param='{name}'" + (f" enctype={enctype}" if enctype else ""))
            else:
                # 无可见 input → 可能是 header 注入或其他
                params[scenario][f"level{level}"] = {"method": method, "name": None}
                if scenario == "log4j2" and level == 2:
                    params[scenario][f"level{level}"]["injection"] = "header"
                    params[scenario][f"level{level}"]["header_names"] = ["User-Agent", "X-Forwarded-For"]
                print(f"  [WARN] {scenario} L{level}: 无可见表单参数")

    return {"params": params}


def step_flag_format(url_prefix: str, url_path_map: Dict[str, str], levels: List[int], interactive: bool) -> Dict[str, Any]:
    """步骤 4: Flag 格式发现。"""
    print(f"\n[4/6] Flag 格式发现")

    # 从第一个可用的场景页面探测 flag 格式
    found_flags = {}
    for scenario, path in url_path_map.items():
        for level in levels:
            url = f"{url_prefix.rstrip('/')}/{path}/level{level}.php"
            resp = http_get(url)
            if resp["status"] != 200:
                continue
            for pattern in KNOWN_FLAG_PATTERNS:
                matches = re.findall(pattern, resp["body"])
                if matches:
                    if pattern not in found_flags:
                        found_flags[pattern] = set()
                    found_flags[pattern].update(matches)
            if found_flags:
                break
        if found_flags:
            break

    if found_flags:
        for pattern, values in found_flags.items():
            print(f"  发现模式: {pattern} — 匹配 {len(values)} 个值")

        best_pattern = max(found_flags.keys(), key=lambda p: len(found_flags[p]))
        return {
            "pattern": best_pattern,
            "mode": "regex",
            "baseline_strategy": "dedup",
        }

    print("  [WARN] 未发现已知 flag 模式")
    if interactive:
        user_pattern = input("  请输入 flag 正则表达式 (留空使用默认 flag\\{[^}]+\\}): ").strip()
        if user_pattern:
            return {"pattern": user_pattern, "mode": "regex", "baseline_strategy": "dedup"}

    return {
        "pattern": r"flag\{[^}]+\}",
        "mode": "regex",
        "baseline_strategy": "dedup",
    }


def step_waf_detect(url_prefix: str, url_path_map: Dict[str, str]) -> Dict[str, Any]:
    """步骤 5: WAF 检测——发送恶意 payload 观察响应。"""
    print(f"\n[5/6] WAF 检测")

    # 找到第一个有 GET 参数的场景
    test_scenario = None
    test_path = None
    for scenario in ["cmdi", "sqli", "xss"]:
        if scenario in url_path_map:
            test_scenario = scenario
            test_path = url_path_map[scenario]
            break

    if not test_scenario:
        print("  [WARN] 无可用场景进行 WAF 检测")
        return {"block_signals": {"http_status": [403]}, "identity": "unknown"}

    # 发送一个已知的恶意 payload
    test_url = f"{url_prefix.rstrip('/')}/{test_path}/level1.php?cmd=\$(cat%20/etc/passwd)"
    print(f"  探测: {test_url[:80]}...")
    resp = http_get(test_url)

    block_signals = {
        "http_status": [403],
        "response_headers": {},
        "response_body_patterns": [],
    }
    identity = "unknown"

    # 检测 HTTP 状态码
    if resp["status"] == 403:
        block_signals["http_status"] = [403]
        print(f"  [OK] 拦截信号: HTTP 403")

    # 检测 WAF 响应头
    for header_name in ["X-WAF-Blocked", "WAF_BLOCKED", "X-CDN-Blocked"]:
        if header_name in resp["headers"]:
            block_signals["response_headers"][header_name] = resp["headers"][header_name]
            print(f"  [OK] WAF 响应头: {header_name}={resp['headers'][header_name]}")

    # 检测 WAF 评分头
    score_headers_found = []
    for header_name in resp["headers"]:
        if "score" in header_name.lower() or "waf" in header_name.lower():
            score_headers_found.append(header_name)
    if score_headers_found:
        print(f"  [OK] 评分类响应头: {', '.join(score_headers_found)}")

    # 识别 WAF 身份（从响应体特征）
    for keyword, waf_id in WAF_FINGERPRINTS.items():
        if keyword.lower() in resp["body"].lower():
            identity = waf_id
            block_signals["response_body_patterns"].append(keyword)
            print(f"  [OK] WAF 身份: {waf_id} (响应体含 '{keyword}')")
            break

    # 提取规则 ID 模式
    rule_ids = re.findall(r'rule-id[\"\'>]+([0-9]+)', resp["body"])
    if rule_ids:
        print(f"  [OK] 规则 ID 模式: {len(rule_ids)} 条规则触发 ({', '.join(rule_ids[:5])}...)")

    return {
        "block_signals": block_signals,
        "score_headers": score_headers_found,
        "rule_id_pattern": "rule-id[\"'>]+([0-9]+)" if rule_ids else None,
        "identity": identity,
    }


# ═══════════════════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════════════════

def discover(url: str, output_path: str, auto: bool) -> Dict[str, Any]:
    """运行完整发现流程，返回 profile dict。"""
    print("=" * 60)
    print(f"目标发现: {url}")
    print("=" * 60)

    # 1. 连通性
    conn = step_connectivity(url)
    if not conn["reachable"]:
        print(f"\n[ERROR] 目标不可达，终止。")
        sys.exit(1)

    # 2. URL 结构
    url_info = step_url_structure(url)
    if not url_info["url_path_map"]:
        if not auto:
            print("\n自动发现未找到场景页面。请手动提供 URL 路径映射。")
            print("示例: samples/targets/profile.json → target.url_path_map")
        sys.exit(1)

    # 3. 参数名
    param_info = step_params(url, url_info["url_path_map"], url_info["levels"])

    # 4. Flag 格式
    flag_info = step_flag_format(url, url_info["url_path_map"], url_info["levels"], not auto)

    # 5. WAF 检测
    waf_info = step_waf_detect(url, url_info["url_path_map"])

    # 6. 组装 profile
    profile = {
        "_meta": {
            "name": f"自动发现的靶场 ({url})",
            "description": "",
            "version": "1",
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "discovery_method": "auto",
        },
        "target": {
            "url_prefix": url.rstrip("/"),
            "url_path_map": url_info["url_path_map"],
            "url_page_pattern": url_info["page_pattern"],
            "levels": url_info["levels"],
            "direct_url": None,
        },
        "params": param_info["params"],
        "success": flag_info,
        "waf": waf_info,
        "backend": {
            "shell": "posix_sh",
            "database": "mysql",
            "app_server": "php",
            "php_version": None,
        },
        "executor": {
            "encoding": "url_single",
            "timeout_ms": 10000,
            "retries": 2,
            "concurrency": 5,
            "python_cmd": "python3",
        },
    }

    # 写入
    if not output_path:
        output_path = DEFAULT_PROFILE_PATH
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)

    print(f"\n{'=' * 60}")
    print(f"Profile 已保存: {output_path}")
    print(f"发现场景: {list(url_info['url_path_map'].keys())}")
    print(f"WAF 身份: {waf_info['identity']}")
    if not auto:
        print(f"\n提示: 请检查 backend 段（shell/database/app_server）——这些无法自动发现。")
    return profile


def validate(profile_path: str) -> bool:
    """验证现有 profile 是否仍有效。"""
    print(f"验证 profile: {profile_path}")

    if not os.path.exists(profile_path):
        print(f"[ERROR] profile 文件不存在: {profile_path}")
        return False

    with open(profile_path, encoding="utf-8") as f:
        profile = json.load(f)

    url_prefix = profile.get("target", {}).get("url_prefix", "")
    if not url_prefix:
        print("[ERROR] target.url_prefix 缺失")
        return False

    print(f"目标: {url_prefix}")

    # 连通性检查
    conn = step_connectivity(url_prefix)
    if not conn["reachable"]:
        print("[FAIL] 目标不可达——profile 需要更新")
        return False

    # 检查每个场景是否仍可达
    all_ok = True
    url_path_map = profile.get("target", {}).get("url_path_map", {})
    page_pattern = profile.get("target", {}).get("url_page_pattern", "level{level}.php")

    for scenario, path in url_path_map.items():
        test_url = f"{url_prefix.rstrip('/')}/{path}/{page_pattern.replace('{level}', '1')}"
        resp = http_get(test_url)
        if resp["status"] == 200:
            print(f"  [OK] {scenario} → {test_url}")
        else:
            print(f"  [FAIL] {scenario} → {test_url} (HTTP {resp['status']})")
            all_ok = False

    if all_ok:
        print("[OK] 所有场景可达——profile 有效")
    return all_ok


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="目标环境发现脚本 — 探测 WAF/靶场，生成或验证 profile.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 discovery.py --url http://new-target.com:8090 --auto
  python3 discovery.py --url http://new-target.com:8090 --output my_profile.json
  python3 discovery.py --validate
        """,
    )

    parser.add_argument("--url", default=None,
                        help="目标 URL 前缀 (如 http://localhost:8090)")
    parser.add_argument("--auto", action="store_true",
                        help="全自动模式，不提示用户确认")
    parser.add_argument("--validate", action="store_true",
                        help="仅验证现有 profile.json，不修改")
    parser.add_argument("--output", default=DEFAULT_PROFILE_PATH,
                        help=f"输出 profile 路径 (默认: {DEFAULT_PROFILE_PATH})")
    parser.add_argument("--profile", default=DEFAULT_PROFILE_PATH,
                        help=f"验证时使用的 profile 路径 (默认: {DEFAULT_PROFILE_PATH})")

    args = parser.parse_args()

    if args.validate:
        ok = validate(args.profile)
        sys.exit(0 if ok else 1)
    elif args.url:
        discover(args.url, args.output, args.auto)
    else:
        parser.print_help()
        print("\n[ERROR] 需要 --url (发现模式) 或 --validate (验证模式)")
        sys.exit(1)


if __name__ == "__main__":
    main()
