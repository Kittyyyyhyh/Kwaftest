#!/usr/bin/env python3
"""
对照探针 — 用无害对照隔离技法/目标, O(T+G) 替代 O(T×G)

阶段A: 每个技法 × 无害对照目标(id) → 测技法本身是否被拦
阶段B: 安全技法(;) × 每个目标 → 测目标本身是否被拦
阶段C: 安全技法 × 安全目标 → 填满矩阵(只跑有意义的格子)
"""
import sys,io,os,json,argparse,urllib.parse,requests,subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.transport import check_success
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(BASE, "logs", "probe_cache.json")

# 对照基准 — 已验证能绕过WAF的技法和目标
CONTROL_TECHNIQUE = "semi"      # ; 已验证绕过
CONTROL_TARGET = "id"           # id 已验证绕过


def _send(scenario, payload, tgt, base_url):
    """发送一次请求, 返回 BLOCKED/FLAG/PASSED"""
    pre = tgt.get("pre_setup", {})
    if pre.get("action") == "file_delete":
        subprocess.run(["docker","exec","waf-app","rm","-f",pre["path"]], capture_output=True, timeout=5)
    elif pre.get("action") == "file_create":
        subprocess.run(["docker","exec","waf-app","sh","-c",
                        f"echo '{pre.get('content','x')}' > {pre['path']}"], capture_output=True, timeout=5)

    level = tgt.get("level", 1)
    url_param = tgt.get("url_param", "cmd" if scenario == "cmdi" else "id")
    encoded = urllib.parse.quote(payload, safe="")
    try:
        resp = requests.get(f"{base_url}/{scenario}/level{level}.php?{url_param}={encoded}",
                            timeout=5, allow_redirects=False)
        if resp.status_code == 403:
            return "BLOCKED"
        _, ok = check_success(tgt.get("success_on", {}), resp.text)
        return "FLAG" if ok else "PASSED"
    except:
        return "ERROR"


def run(scenario: str, cache_path: str = CACHE, base_url: str = "http://localhost:8090"):
    techs = json.load(open(os.path.join(BASE, "samples","techniques",f"{scenario}.json"), encoding="utf-8"))
    targets = json.load(open(os.path.join(BASE, "samples","targets",f"{scenario}.json"), encoding="utf-8"))
    tg_map = {t["id"]: t for t in targets}
    control_tgt = tg_map.get(CONTROL_TARGET, targets[-1])
    control_tech = next((t for t in techs if t["id"] == CONTROL_TECHNIQUE), techs[0])

    total_cells = len(techs) * len(targets)
    probes_run = 0

    # ====== 阶段A: 技法对照 (每个技法 × 无害目标id) ======
    print(f"阶段A: 技法对照 (×{CONTROL_TARGET})")
    blocked_techs = set()
    for tech in techs:
        payload = tech["template"].replace("{PAYLOAD}", control_tgt["payload"])
        result = _send(scenario, payload, control_tgt, base_url)
        probes_run += 1
        icon = "[X]" if result == "BLOCKED" else "[O]"
        if result == "BLOCKED":
            blocked_techs.add(tech["id"])
        print(f"  {icon} {tech['name']:<6} → {result}")

    # ====== 阶段B: 目标对照 (安全技法; × 每个目标) ======
    print(f"\n阶段B: 目标对照 (×{control_tech['name']})")
    blocked_targets = set()
    for tgt in targets:
        payload = control_tech["template"].replace("{PAYLOAD}", tgt["payload"])
        result = _send(scenario, payload, tgt, base_url)
        probes_run += 1
        icon = "[X]" if result == "BLOCKED" else "[O]"
        if result == "BLOCKED":
            blocked_targets.add(tgt["id"])
        print(f"  {icon} {tgt['id']:<14} → {result}")

    # ====== 阶段C: 安全技法 × 安全目标 ======
    safe_techs = [t for t in techs if t["id"] not in blocked_techs]
    safe_targets = [t for t in targets if t["id"] not in blocked_targets]
    remaining = len(safe_techs) * len(safe_targets)

    print(f"\n阶段C: 安全矩阵 ({len(safe_techs)}×{len(safe_targets)}={remaining}格)")
    probes = {}
    for tech in safe_techs:
        probes[tech["id"]] = {}
        for tgt in safe_targets:
            payload = tech["template"].replace("{PAYLOAD}", tgt["payload"])
            result = _send(scenario, payload, tgt, base_url)
            probes_run += 1
            probes[tech["id"]][tgt["id"]] = result
            if probes_run % 10 == 0:
                print(f"  [{probes_run}/{total_cells}]", flush=True)

    # 被拦的技法/目标全部标为BLOCKED
    for tech in techs:
        if tech["id"] not in probes:
            probes[tech["id"]] = {t["id"]: "BLOCKED" for t in targets}

    for tech in techs:
        for tgt in targets:
            if tgt["id"] not in probes[tech["id"]]:
                probes[tech["id"]][tgt["id"]] = "BLOCKED"

    # 保存缓存
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    json.dump(probes, open(cache_path, "w", encoding="utf-8"), indent=2)

    # 统计
    saved = total_cells - probes_run
    print(f"\n  探针: {probes_run}/{total_cells} 次 (跳过 {saved} 次注定被拦的, 省 {round(saved/total_cells*100) if total_cells else 0}%)")
    print(f"  删技法: {blocked_techs or '无'}")
    print(f"  删目标: {blocked_targets or '无'}")

    return probes


def main():
    parser = argparse.ArgumentParser(description="对照探针")
    parser.add_argument("--scenario", default="cmdi")
    parser.add_argument("--cache", default=CACHE)
    parser.add_argument("--base-url", default="http://localhost:8090")
    args = parser.parse_args()
    run(args.scenario, args.cache, args.base_url)


if __name__ == "__main__":
    main()
