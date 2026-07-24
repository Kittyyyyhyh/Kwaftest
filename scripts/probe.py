#!/usr/bin/env python3
"""
对照探针 — 换WAF时自动发现无害对照, 之后O(T+G)剪枝

冷启动(无缓存): 跑全矩阵 → 自动发现对照 → 缓存
热启动(有缓存): 读对照 → O(T+G) → 剪枝
"""
import sys,io,os,json,argparse,urllib.parse,requests,subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.transport import check_success
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(BASE, "logs", "probe_cache.json")
CTRL_CACHE = os.path.join(BASE, "logs", "probe_controls.json")


def _send(scenario, payload, tgt, base_url):
    pre = tgt.get("pre_setup", {})
    if pre.get("action") == "file_delete":
        subprocess.run(["docker","exec","waf-app","rm","-f",pre["path"]], capture_output=True, timeout=5)
    elif pre.get("action") == "file_create":
        subprocess.run(["docker","exec","waf-app","sh","-c",
                        f"echo '{pre.get('content','x')}' > {pre['path']}"], capture_output=True, timeout=5)
    level = tgt.get("level", 1)
    uparam = tgt.get("url_param", "cmd" if scenario == "cmdi" else "id")
    try:
        resp = requests.get(f"{base_url}/{scenario}/level{level}.php?{uparam}={urllib.parse.quote(payload,safe='')}",
                            timeout=5, allow_redirects=False)
        if resp.status_code == 403: return "BLOCKED"
        _, ok = check_success(tgt.get("success_on", {}), resp.text)
        return "FLAG" if ok else "PASSED"
    except:
        return "ERROR"


def _discover_controls(probes):
    """从全矩阵结果自动发现两个最无害的技法和目标（被拦最少）"""
    techs = list(probes.keys())
    targets = list(probes[techs[0]].keys())
    # 选FLAG最多的(真正能绕过的)做对照, 不选只PASSED不FLAG的
    tech_flag = {t: sum(1 for g in targets if probes[t].get(g)=="FLAG") for t in techs}
    tgt_flag = {g: sum(1 for t in techs if probes[t].get(g)=="FLAG") for g in targets}
    ctrl_techs = sorted(tech_flag, key=tech_flag.get, reverse=True)[:2]
    ctrl_tgts = sorted(tgt_flag, key=tgt_flag.get, reverse=True)[:2]
    c = {"techniques": ctrl_techs, "targets": ctrl_tgts}
    json.dump(c, open(CTRL_CACHE,"w",encoding="utf-8"), indent=2)
    return ctrl_techs, ctrl_tgts


def _probe_full(techs, targets, scenario, base_url):
    """冷启动: 全矩阵"""
    probes = {}
    total = len(techs)*len(targets)
    done = 0
    for tech in techs:
        probes[tech["id"]] = {}
        for tgt in targets:
            p = tech["template"].replace("{PAYLOAD}", tgt["payload"])
            probes[tech["id"]][tgt["id"]] = _send(scenario, p, tgt, base_url)
            done += 1
            if done % 10 == 0: print(f"  [{done}/{total}]", flush=True)
    return probes


def _probe_controlled(techs, targets, ctrl_tech_ids, ctrl_tgt_ids, scenario, base_url):
    """热启动: 对照探针 O(T+G+剩余)"""
    tg_map = {t["id"]:t for t in targets}
    ctrl_tgts = [tg_map[c] for c in ctrl_tgt_ids]
    ctrl_techs = [next(t for t in techs if t["id"]==c) for c in ctrl_tech_ids]
    total = len(techs)*len(targets)
    probes_run = 0

    # 阶段A: 技法对照
    print(f"阶段A: 技法对照 (×{ctrl_tgt_ids[0]} + ×{ctrl_tgt_ids[1]})")
    blocked_techs = set()
    for tech in techs:
        rs = [_send(scenario, tech["template"].replace("{PAYLOAD}",c["payload"]),c,base_url) for c in ctrl_tgts]
        probes_run += 2
        if rs[0]=="BLOCKED" and rs[1]=="BLOCKED":
            blocked_techs.add(tech["id"]); icon="[X]"
        elif rs[0]=="BLOCKED" or rs[1]=="BLOCKED": icon="[?]"
        else: icon="[O]"
        print(f"  {icon} {tech['name']:<6} → {rs[0]:<8} {rs[1]:<8}")

    # 阶段B: 目标对照
    print(f"\n阶段B: 目标对照 (×{ctrl_tech_ids[0]} + ×{ctrl_tech_ids[1]})")
    blocked_targets = set()
    for tgt in targets:
        rs = [_send(scenario, c["template"].replace("{PAYLOAD}",tgt["payload"]),tgt,base_url) for c in ctrl_techs]
        probes_run += 2
        if rs[0]=="BLOCKED" and rs[1]=="BLOCKED":
            blocked_targets.add(tgt["id"]); icon="[X]"
        elif rs[0]=="BLOCKED" or rs[1]=="BLOCKED": icon="[?]"
        else: icon="[O]"
        print(f"  {icon} {tgt['id']:<14} → {rs[0]:<8} {rs[1]:<8}")

    # 阶段C: 安全矩阵
    safe_techs = [t for t in techs if t["id"] not in blocked_techs]
    safe_targets = [t for t in targets if t["id"] not in blocked_targets]
    remaining = len(safe_techs)*len(safe_targets)
    print(f"\n阶段C: 安全矩阵 ({len(safe_techs)}×{len(safe_targets)}={remaining}格)")
    probes = {}
    for tech in safe_techs:
        probes[tech["id"]] = {}
        for tgt in safe_targets:
            p = tech["template"].replace("{PAYLOAD}", tgt["payload"])
            probes[tech["id"]][tgt["id"]] = _send(scenario, p, tgt, base_url)
            probes_run += 1
            if probes_run % 10 == 0: print(f"  [{probes_run}/{total}]", flush=True)

    # 被拦的填BLOCKED
    for tech in techs:
        if tech["id"] not in probes:
            probes[tech["id"]] = {t["id"]:"BLOCKED" for t in targets}
        for tgt in targets:
            if tgt["id"] not in probes[tech["id"]]:
                probes[tech["id"]][tgt["id"]] = "BLOCKED"

    saved = total - probes_run
    print(f"\n  探针: {probes_run}/{total} (省 {saved}, {round(saved/total*100) if total else 0}%)")
    print(f"  删技法: {blocked_techs or '无'}")
    print(f"  删目标: {blocked_targets or '无'}")
    return probes


def run(scenario, cache_path=CACHE, base_url="http://localhost:8090"):
    techs = json.load(open(os.path.join(BASE,"samples","techniques",f"{scenario}.json"), encoding="utf-8"))
    targets = json.load(open(os.path.join(BASE,"samples","targets",f"{scenario}.json"), encoding="utf-8"))

    ctrl_tech_ids, ctrl_tgt_ids = [], []
    if os.path.exists(CTRL_CACHE):
        c = json.load(open(CTRL_CACHE, encoding="utf-8"))
        ctrl_tech_ids, ctrl_tgt_ids = c.get("techniques",[]), c.get("targets",[])

    if ctrl_tech_ids and ctrl_tgt_ids:
        print(f"[热启动] 对照: 技法={ctrl_tech_ids} 目标={ctrl_tgt_ids}")
        probes = _probe_controlled(techs, targets, ctrl_tech_ids, ctrl_tgt_ids, scenario, base_url)
    else:
        print("[冷启动] 无缓存, 跑全矩阵自动发现对照...")
        probes = _probe_full(techs, targets, scenario, base_url)
        ctrl_tech_ids, ctrl_tgt_ids = _discover_controls(probes)
        print(f"自动发现对照: 技法={ctrl_tech_ids} 目标={ctrl_tgt_ids}")
        print(f"下次将用对照探针, 省去全矩阵")

    json.dump(probes, open(cache_path,"w",encoding="utf-8"), indent=2)
    return probes


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="cmdi")
    p.add_argument("--cache", default=CACHE)
    p.add_argument("--base-url", default="http://localhost:8090")
    p.add_argument("--reset", action="store_true", help="清除对照缓存, 强制冷启动")
    args = p.parse_args()
    if args.reset and os.path.exists(CTRL_CACHE):
        os.remove(CTRL_CACHE); print("已清除对照缓存")
    run(args.scenario, args.cache, args.base_url)


if __name__ == "__main__":
    main()
