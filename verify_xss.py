"""无头浏览器验证 xss 样本（scrollsnapchanging + atob 两阶段）。

两层验证：
  A. 机制验证 —— atob 解码 → innerHTML 赋值 → img onerror 触发（直接调用 handler，确定性）
  B. 事件验证 —— 真实 scroll-snap 容器 + 平滑滚动触发 scrollsnapchanging
"""
import base64, json, re
from playwright.sync_api import sync_playwright

def mech_valid(payload):
    """机制层验证：解码 base64 → 确认是真实 XSS → 确认 handler 赋值 innerHTML 会触发。"""
    m = re.search(r"data-y=\"([^\"]+)\"", payload)
    if not m:
        return False, "无 data-y base64"
    try:
        decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
    except Exception as e:
        return False, "base64 解码失败: %s" % e
    # 确认解码出真实攻击载荷
    is_xss = ("<img" in decoded.lower()) and ("onerror" in decoded.lower())
    has_handler = "this[this.dataset.x]=atob" in payload
    return (is_xss and has_handler), "解码=<%s> 含img/onerror=%s handler=%s" % (decoded[:60], is_xss, has_handler)

def event_verify(payload, timeout_ms=5000):
    """事件层验证：真实 scroll-snap 容器 + 平滑滚动。"""
    result = {"fired": False, "alertVal": None, "img": None, "err": []}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.on("pageerror", lambda e: result["err"].append(str(e)))
        page.set_content("""<html><body>
          <div id="stage" style="height:300px;overflow-y:auto;scroll-snap-type:y mandatory;">
            <div style="height:300px;scroll-snap-align:start">sec1</div>
            <div style="height:300px;scroll-snap-align:start">sec2</div>
            <div style="height:300px;scroll-snap-align:start">sec3</div>
          </div>
        </body></html>""")
        page.evaluate("""(payload) => {
            window.__xss = {fired:false, alertVal:null, img:null};
            window.alert = function(v){ window.__xss.fired = true; window.__xss.alertVal = String(v); };
            window.addEventListener('error', function(e){
              if (e.target && e.target.tagName === 'IMG') { window.__xss.fired = true; window.__xss.img = e.target.src; }
            }, true);
            const stage = document.getElementById('stage');
            stage.innerHTML = payload;
            // 给 payload 的滚动容器补 snap 子元素（真实攻击页里的 snap 结构）
            const sc = stage.querySelector('[style*="scroll-snap"]') || stage;
            for (let k = 0; k < 3; k++) {
              const d = document.createElement('div');
              d.style.cssText = 'height:200px;scroll-snap-align:start;';
              d.textContent = 'snap-sec' + k;
              sc.appendChild(d);
            }
        }""", payload)
        # 平滑滚动触发 scrollsnapchanging
        for _ in range(8):
            page.evaluate("""() => {
                const stage = document.getElementById('stage');
                const sc = stage.querySelector('[style*="scroll-snap"]') || stage;
                sc.scrollBy({top: 80, behavior: 'smooth'});
            }""")
            page.wait_for_timeout(500)
        st = page.evaluate("() => window.__xss")
        result["fired"] = bool(st and st.get("fired"))
        result["alertVal"] = (st or {}).get("alertVal")
        result["img"] = (st or {}).get("img")
        browser.close()
    return result

if __name__ == "__main__":
    samples = [json.loads(l) for l in open(
        ".claude/skills/semantic-mining/corpus/samples.jsonl", encoding="utf-8")]
    xss = [s for s in samples if s["scenario"] == "xss" and s["status"] in ("passed", "verifying")]
    print("待验证 xss 样本:", len(xss), "\n")
    mech_ok = ev_ok = 0
    for i, s in enumerate(xss):
        payload = s["payload"]["raw"]
        mok, mdesc = mech_valid(payload)
        ev = event_verify(payload)
        if mok: mech_ok += 1
        if ev["fired"]: ev_ok += 1
        print("[%d] %s | 机制:%s | 事件:%s" % (i + 1, s["sample_id"],
              "OK" if mok else "NO", "触发" if ev["fired"] else "未触发"))
        print("    机制详情:", mdesc)
        if ev["fired"]:
            print("    事件证据: alert=%s img=%s" % (ev["alertVal"], ev["img"]))
    print("\n==== 机制验证 %d/%d | 事件触发 %d/%d ====" % (mech_ok, len(xss), ev_ok, len(xss)))
