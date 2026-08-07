"""远程执行器 — 批量探针 → 远程腾讯云 WAF → TestEvent 流。

remote（默认）: IP + Host 头。判定纯二元——请求是否被 WAF 拦：
  - blocked     : 403 或 响应头 X-WAF-UUID 存在 或 body 命中拦截页特征
  - rate_limited: 429 或限流特征（与规则拦截区分）
  - passed      : 其余可达响应（200/404/500 均说明请求已穿过 WAF 到达源站）
  - ambiguous   : 网络错误 / 重试耗尽

输入 probes = SampleRecord 列表（含 sample_id / payload / context.placements）。
输出 tests = TestEvent 列表（schema.build_test）。

礼貌性：PacedPool 限速（并发 2-3，间隔 300ms+jitter），200/403 不重试。
"""
import argparse
import http.client
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import schema  # noqa: E402
from lib import util  # noqa: E402

DEFAULT_PROFILE = "targets/profile.json"


def _http_request(url, method, headers, body, timeout):
    """直接 http.client 请求。

    相比 urllib：不走系统代理；头值支持原始 UTF-8 字节（无点 ı 等非 ASCII
    可放进 UA/Referer 头）；403 等状态码正常返回不抛异常。
    返回 (status, headers_dict, body_text)。
    """
    p = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in headers.items():
            if isinstance(v, str):
                try:
                    conn.putheader(k, v)  # 纯 ASCII 正常
                except UnicodeEncodeError:
                    conn.putheader(k, v.encode("utf-8"))  # 非 ASCII 用原始 UTF-8 字节
            else:
                conn.putheader(k, v)
        conn.endheaders()
        if body:
            conn.send(body if isinstance(body, bytes) else body.encode("utf-8"))
        resp = conn.getresponse()
        status = resp.status
        resp_headers = dict(resp.getheaders())
        resp_body = resp.read().decode("utf-8", "replace")
        conn.close()
        return status, resp_headers, resp_body
    except Exception:
        conn.close()
        raise


# ── 目标/profile 解析 ──────────────────────────────────────────

def load_profile(path=DEFAULT_PROFILE) -> dict:
    return util.load_json(str(Path(__file__).resolve().parent.parent / path), {})


def get_target(profile, target_name=None) -> dict:
    t = profile.get("target", {})
    if target_name and profile.get("targets", {}).get(target_name):
        t = profile["targets"][target_name]
    return t


# ── 请求构造 ──────────────────────────────────────────────────

def build_request(payload, placement, target, param_name):
    """返回 (url, method, headers, body)。"""
    tpl = target["placements"][placement]
    url = tpl["url"].replace("{ip}", target["ip"])
    url = url.replace("{host}", target.get("host", ""))
    url = url.replace("{param}", param_name)
    q = tpl.get("quote", "url")
    if q == "url":
        encoded = urllib.parse.quote(payload, safe="")
    elif q == "form":
        encoded = urllib.parse.quote_plus(payload, safe="")
    else:
        encoded = payload
    url = url.replace("{payload}", encoded)

    headers = {"User-Agent": "semantic-mining-v2/1.0"}
    if target.get("host"):
        headers["Host"] = target["host"]
    body = None
    if tpl.get("header"):
        hname, _, hval = tpl["header"].partition(":")
        headers[hname.strip()] = hval.strip().replace("{payload}", payload)
    if tpl.get("body"):
        body = tpl["body"].replace("{param}", param_name).replace("{payload}", encoded)
        headers["Content-Type"] = tpl.get("ctype", "application/x-www-form-urlencoded")
    return url, tpl.get("method", "GET"), headers, body


# ── 拦截信号与判定 ────────────────────────────────────────────

def detect_block_signals(headers, body, block_signals, tracking_headers=None):
    sig = {"present": False, "x_waf_uuid": None, "body_hits": [], "body_uuid": None}
    # 追踪字段（X-WAF-UUID 出现于所有响应，非拦截信号；仅记录用于检测 WAF 升级）
    for th in tracking_headers or []:
        for k, v in (headers or {}).items():
            if k.lower() == th.lower() and v and not sig["x_waf_uuid"]:
                sig["x_waf_uuid"] = v
    # 配置的拦截响应头
    for hname, hpat in (block_signals or {}).get("response_headers", {}).items():
        for k, v in (headers or {}).items():
            if k.lower() == hname.lower() and re.search(hpat, v):
                sig["present"] = True
    for pat in (block_signals or {}).get("body_patterns", []):
        if pat in (body or ""):
            sig["present"] = True
            sig["body_hits"].append(pat)
    m = re.search((block_signals or {}).get("body_uuid_pattern", ""), body or "")
    if m:
        sig["body_uuid"] = m.group(1)
    return sig


def classify_remote(status, headers, body, block_signals, rate_signals):
    if status == 0:
        return "ambiguous"  # 网络错误
    if status in (rate_signals or {}).get("http_status", []) or any(
            p in (body or "") for p in (rate_signals or {}).get("body_patterns", [])):
        return "rate_limited"
    if status in (block_signals or {}).get("http_status", []) or detect_block_signals(headers, body, block_signals)["present"]:
        return "blocked"
    return "passed"


# ── 单条执行 ──────────────────────────────────────────────────

def execute_one(probe, *, target, block_signals, rate_signals, timeout=10, retries=2,
                run_id="run_x", round_num=1, param_name="q", tracking_headers=None):
    payload = probe.get("payload", {}).get("raw", probe.get("payload", ""))
    if isinstance(probe.get("payload"), dict):
        payload = probe["payload"].get("raw", "")
    placement = probe.get("placement") or (probe.get("context", {}).get("placements") or
                                           [target.get("default_placement", "query")])[0]
    sample_id = probe.get("sample_id") or schema.sample_id_of(payload, "direct", placement, [])
    url, method, headers, body = build_request(payload, placement, target, param_name)

    start = time.monotonic()
    status, resp_headers, resp_body, error = 0, {}, "", None
    for attempt in range(1 + max(0, int(retries))):
        try:
            status, resp_headers, resp_body = _http_request(url, method, headers, body, timeout)
            error = None
            break
        except Exception as e:  # noqa: BLE001 网络层错误
            status = 0
            error = repr(e)
            time.sleep(0.5 * (attempt + 1))

    decision = classify_remote(status, resp_headers, resp_body, block_signals, rate_signals)
    sig = detect_block_signals(resp_headers, resp_body, block_signals, tracking_headers)
    latency_ms = int((time.monotonic() - start) * 1000)
    result = {
        "http_status": status,
        "waf_decision": decision,
        "block_signals": {"x_waf_uuid": sig.get("x_waf_uuid"),
                          "body_hits": sig.get("body_hits", []),
                          "body_uuid": sig.get("body_uuid")},
        "latency_ms": latency_ms,
        "error": error,
    }
    test = schema.build_test(
        sample_id=sample_id, run_id=run_id, round_num=round_num,
        target={"name": target.get("name"), "ip": target.get("ip"),
                "host": target.get("host"), "placement": placement},
        result=result)
    return test


# ── 批量执行 ──────────────────────────────────────────────────

def execute_remote_batch(probes, target, block_signals, rate_signals, *,
                         concurrency=3, min_interval_ms=300, jitter_ms=150,
                         timeout=10, retries=2, run_id=None, round_num=1,
                         dry_run=False, limit=None, param_name="q",
                         tracking_headers=None):
    run_id = run_id or "run_" + util.sha1_id(util.now_iso())
    items = list(probes)
    if limit:
        items = items[:limit]
    if dry_run:
        return [], {"total": len(items), "dry_run": True}
    pool = util.PacedPool(concurrency, min_interval_ms, jitter_ms)
    tests = pool.map(lambda p: execute_one(
        p, target=target, block_signals=block_signals, rate_signals=rate_signals,
        timeout=timeout, retries=retries, run_id=run_id, round_num=round_num,
        param_name=param_name, tracking_headers=tracking_headers), items)
    pool.shutdown()
    stats = {"total": len(tests), "passed": 0, "blocked": 0,
             "rate_limited": 0, "ambiguous": 0}
    for t in tests:
        d = t["result"]["waf_decision"]
        if d in stats:
            stats[d] += 1
    return tests, stats


# ── 自检（M2 验证用）──────────────────────────────────────────

def selfcheck(target, block_signals, rate_signals, timeout=10, retries=1, param_name="q",
              tracking_headers=None):
    """两条已知探针：良性应 passed，恶意应 blocked。"""
    benign = {"sample_id": "selfcheck-benign", "payload": {"raw": "hello"}}
    malicious = {"sample_id": "selfcheck-xss", "payload": {"raw": "<script>alert(1)</script>"},
                 "context": {"placements": ["query"]}}
    print("== selfcheck: benign 'hello' ==")
    r1 = execute_one(benign, target=target, block_signals=block_signals,
                     rate_signals=rate_signals, timeout=timeout, retries=retries,
                     run_id="selfcheck", param_name=param_name, tracking_headers=tracking_headers)
    print("   status=%s decision=%s" % (r1["result"]["http_status"], r1["result"]["waf_decision"]))
    print("== selfcheck: malicious '<script>alert(1)</script>' ==")
    r2 = execute_one(malicious, target=target, block_signals=block_signals,
                     rate_signals=rate_signals, timeout=timeout, retries=retries,
                     run_id="selfcheck", param_name=param_name, tracking_headers=tracking_headers)
    print("   status=%s decision=%s x_waf_uuid=%s" % (
        r2["result"]["http_status"], r2["result"]["waf_decision"],
        r2["result"]["block_signals"].get("x_waf_uuid")))
    ok1 = r1["result"]["waf_decision"] == "passed"
    ok2 = r2["result"]["waf_decision"] == "blocked"
    print("RESULT:", "PASS" if (ok1 and ok2) else "FAIL", "(benign=passed:%s, malicious=blocked:%s)" % (ok1, ok2))
    return ok1 and ok2


# ── CLI ───────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="semantic-mining v2 远程执行器")
    ap.add_argument("--input", help="探针 JSONL（SampleRecord 列表）")
    ap.add_argument("--output", default="corpus/tests.jsonl", help="TestEvent JSONL 输出")
    ap.add_argument("--profile", default=DEFAULT_PROFILE)
    ap.add_argument("--target", default=None)
    ap.add_argument("--scenario", default="sqli", choices=schema.SCENARIOS)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--concurrency", type=int, default=None)
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()

    profile = load_profile(args.profile)
    target = get_target(profile, args.target)
    block_signals = profile.get("block_signals", {})
    rate_signals = profile.get("rate_limit_signals", {})
    tracking_headers = profile.get("tracking_headers")
    ex = profile.get("executor", {})
    param_name = target.get("params", {}).get(args.scenario, "q")

    if args.selfcheck:
        sys.exit(0 if selfcheck(target, block_signals, rate_signals,
                                timeout=ex.get("timeout_ms", 10000) / 1000.0,
                                tracking_headers=tracking_headers) else 1)

    probes = util.read_jsonl(args.input)
    tests, stats = execute_remote_batch(
        probes, target, block_signals, rate_signals,
        concurrency=args.concurrency or ex.get("concurrency", 3),
        min_interval_ms=ex.get("min_interval_ms", 300), jitter_ms=ex.get("jitter_ms", 150),
        timeout=ex.get("timeout_ms", 10000) / 1000.0, retries=ex.get("retries", 2),
        run_id=args.run_id, round_num=args.round, dry_run=args.dry_run,
        limit=args.limit, param_name=param_name, tracking_headers=tracking_headers)
    if not args.dry_run:
        util.append_jsonl(args.output, tests)
    print("stats:", json.dumps(stats, ensure_ascii=False))
    if tests:
        print("sample:", json.dumps(tests[0], ensure_ascii=False)[:300])


if __name__ == "__main__":
    main()
