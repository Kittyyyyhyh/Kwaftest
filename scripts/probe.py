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

# 对照基准 — 每类两个，互相验证
CONTROL_TECHS = ["semi", "pipe"]          # ; 和 | 已验证绕过
CONTROL_TARGETS = ["id", "P2-db"]         # id(命令) 和 P2-db(文件) 已验证绕过


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
    ctrl_tgts = [tg_map.get(c, targets[-1]) for c in CONTROL_TARGETS]
    ctrl_techs_list = [next((t for t in techs if t["id"] == c), techs[0]) for c in CONTROL_TECHS]

    total_cells = len(techs) * len(targets)
    probes_run = 0

    # ====== 阶段A: 技法对照 (双目标验证) ======
    print(f"阶段A: 技法对照 (×{CONTROL_TARGETS[0]} + ×{CONTROL_TARGETS[1]})")
    tech_results = {}
    blocked_techs = set()
    for tech in techs:
        results = []
        for ctrl_tgt in ctrl_tgts:
            p = tech["template"].replace("{PAYLOAD}", ctrl_tgt["payload"])
            r = _send(scenario, p, ctrl_tgt, base_url)
            probes_run += 1
            results.append(r)
        tech_results[tech["id"]] = results
        # 两个对照都拦 → 确定是技法被识破
        if results[0] == "BLOCKED" and results[1] == "BLOCKED":
            blocked_techs.add(tech["id"])
            icon = "[X]"
        elif results[0] == "BLOCKED" or results[1] == "BLOCKED":
            icon = "[?]"  # 不一致，保留但标记
        else:
            icon = "[O]"
        print(f"  {icon} {tech['name']:<6} → {results[0]:<8} {results[1]:<8}")

    # ====== 阶段B: 目标对照 (双技法验证) ======
    print(f"\n阶段B: 目标对照 (×{CONTROL_TECHS[0]} + ×{CONTROL_TECHS[1]})")
    blocked_targets = set()
    for tgt in targets:
        results = []
        for ctrl_tech in ctrl_techs_list:
            p = ctrl_tech["template"].replace("{PAYLOAD}", tgt["payload"])
            r = _send(scenario, p, tgt, base_url)
            probes_run += 1
            results.append(r)
        # 两个技法都拦 → 确定是目标被保护
        if results[0] == "BLOCKED" and results[1] == "BLOCKED":
            blocked_targets.add(tgt["id"])
            icon = "[X]"
        elif results[0] == "BLOCKED" or results[1] == "BLOCKED":
            icon = "[?]"
        else:
            icon = "[O]"
        print(f"  {icon} {tgt['id']:<14} → {results[0]:<8} {results[1]:<8}")

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
