#!/usr/bin/env python3
"""探针 — 技法×目标全矩阵探测(无编码,秒级)"""
import sys,io,os,json,argparse,urllib.parse,requests,subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.transport import check_success
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(BASE, "logs", "probe_cache.json")


def _send(scenario, payload, tgt, base_url):
    pre = tgt.get("pre_setup", {})
    if pre.get("action") == "file_delete":
        subprocess.run(["docker","exec","waf-app","rm","-f",pre["path"]], capture_output=True, timeout=5)
    elif pre.get("action") == "file_create":
        subprocess.run(["docker","exec","waf-app","sh","-c",
                        f"echo '{pre.get('content','x')}' > {pre['path']}"], capture_output=True, timeout=5)
    uparam = tgt.get("url_param", "cmd" if scenario == "cmdi" else "id")
    try:
        resp = requests.get(f"{base_url}/{scenario}/level{tgt.get('level',1)}.php?{uparam}={urllib.parse.quote(payload,safe='')}",
                            timeout=5, allow_redirects=False)
        if resp.status_code == 403: return "BLOCKED"
        _, ok = check_success(tgt.get("success_on", {}), resp.text)
        return "FLAG" if ok else "PASSED"
    except:
        return "ERROR"


def run(scenario, cache_path=CACHE, base_url="http://localhost:8090"):
    techs = json.load(open(os.path.join(BASE,"samples","techniques",f"{scenario}.json"), encoding="utf-8"))
    targets = json.load(open(os.path.join(BASE,"samples","targets",f"{scenario}.json"), encoding="utf-8"))
    total = len(techs) * len(targets)
    probes = {t["id"]: {} for t in techs}
    done = 0

    for tech in techs:
        for tgt in targets:
            p = tech["template"].replace("{PAYLOAD}", tgt["payload"])
            probes[tech["id"]][tgt["id"]] = _send(scenario, p, tgt, base_url)
            done += 1
            if done % 15 == 0: print(f"  [{done}/{total}]", flush=True)

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    json.dump(probes, open(cache_path,"w",encoding="utf-8"), indent=2)

    # 打印矩阵
    print(f"\n  {'':>3}", end="")
    for t in targets: print(f"{t['id']:<14}", end="")
    print(f"\n  {'':>3}{'-'*(14*len(targets))}")
    for tech in techs:
        print(f"  {tech['name']:<3}", end="")
        for tgt in targets:
            print(f"{probes[tech['id']][tgt['id']]:<14}", end="")
        print()

    return probes


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="cmdi")
    p.add_argument("--cache", default=CACHE)
    p.add_argument("--base-url", default="http://localhost:8090")
    args = p.parse_args()
    run(args.scenario, args.cache, args.base_url)


if __name__ == "__main__":
    main()
