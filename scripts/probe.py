#!/usr/bin/env python3
"""探针 — 技法×目标全矩阵探测(无编码,秒级). 输出缓存供剪枝使用."""
import sys,io,os,json,argparse,urllib.parse,requests,re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.transport import verify_attack
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(BASE, "logs", "probe_cache.json")


def run(scenario: str, cache_path: str = CACHE, base_url: str = "http://localhost:8090"):
    techs_file = os.path.join(BASE, "samples", "techniques", f"{scenario}.json")
    targets_file = os.path.join(BASE, "samples", "targets", f"{scenario}.json")

    if not os.path.exists(techs_file) or not os.path.exists(targets_file):
        print(f"ERROR: techniques/targets not found for {scenario}")
        return None

    techs = json.load(open(techs_file, encoding="utf-8"))
    targets = json.load(open(targets_file, encoding="utf-8"))

    probes = {}
    total = len(techs) * len(targets)
    done = 0

    for tech in techs:
        probes[tech["id"]] = {}
        for tgt in targets:
            cmd = tgt.get("cmd", "cat")
            path = tgt.get("path", "")
            if path:
                payload = tech["template"].replace("{CMD}", cmd).replace("{TARGET}", path)
            else:
                payload = tech["template"].replace("{CMD}", tgt["cmd"]).replace(" {TARGET}", "")

            url_param = tgt.get("url_param", "cmd" if scenario == "cmdi" else "id")
            level = tgt.get("level", 1)
            encoded = urllib.parse.quote(payload, safe="")

            # 前置处理: side_effect需要先准备文件状态
            pre_setup = tgt.get("verify", {}).get("pre_setup", {})
            if pre_setup:
                try:
                    import subprocess
                    if pre_setup.get("action") == "file_delete":
                        subprocess.run(["docker", "exec", "waf-app", "rm", "-f", pre_setup["path"]], capture_output=True, timeout=5)
                    elif pre_setup.get("action") == "file_create":
                        c = pre_setup.get("content", "")
                        subprocess.run(["docker", "exec", "waf-app", "sh", "-c", f"echo '{c}' > {pre_setup['path']}"], capture_output=True, timeout=5)
                except Exception:
                    pass

            try:
                resp = requests.get(f"{base_url}/{scenario}/level{level}.php?{url_param}={encoded}",
                                    timeout=5, allow_redirects=False)
                verify_config = tgt.get("verify", {})
                _, verified = verify_attack(verify_config, resp.text)
                if resp.status_code == 403:
                    probes[tech["id"]][tgt["id"]] = "BLOCKED"
                elif verified:
                    probes[tech["id"]][tgt["id"]] = "FLAG"
                else:
                    probes[tech["id"]][tgt["id"]] = "PASSED"
            except Exception as e:
                probes[tech["id"]][tgt["id"]] = f"ERROR:{e}"

            done += 1
            if done % 10 == 0:
                print(f"  [{done}/{total}]", flush=True)

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    json.dump(probes, open(cache_path, "w", encoding="utf-8"), indent=2)

    # 打印矩阵
    print(f"\n  {'':>3}", end="")
    for t in targets:
        print(f"{t['id']:<14}", end="")
    print(f"\n  {'':>3}{'-' * (14 * len(targets))}")
    for tech in techs:
        print(f"  {tech['name']:<3}", end="")
        for tgt in targets:
            r = probes[tech["id"]][tgt["id"]]
            print(f"{r:<14}", end="")
        print()

    return probes


def main():
    parser = argparse.ArgumentParser(description="探针矩阵探测")
    parser.add_argument("--scenario", default="cmdi")
    parser.add_argument("--cache", default=CACHE)
    parser.add_argument("--base-url", default="http://localhost:8090")
    args = parser.parse_args()
    run(args.scenario, args.cache, args.base_url)


if __name__ == "__main__":
    main()
