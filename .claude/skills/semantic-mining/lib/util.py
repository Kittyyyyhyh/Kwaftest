"""纯 stdlib 工具：时间 / 哈希 / JSONL 读写 / 限速线程池。"""
import hashlib
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def now_iso() -> str:
    """UTC ISO 8601，带毫秒。"""
    ms = int(time.time() * 1000) % 1000
    return "%s.%03dZ" % (time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), ms)


def sha1_id(*parts) -> str:
    """确定性内容哈希（用于样本去重）。"""
    h = hashlib.sha1()
    for p in parts:
        h.update(str(p).encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()[:10]


def read_jsonl(path) -> list:
    """读取 JSONL，跳过损坏行。文件不存在返回 []。"""
    if not Path(path).exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def append_jsonl(path, records) -> None:
    """追加写入 JSONL（一行一条）。records 可迭代。"""
    with open(path, "a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def write_jsonl(path, records) -> None:
    """整体覆写 JSONL。"""
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def load_json(path, default=None):
    """读取 JSON 文件，失败返回 default。"""
    if not Path(path).exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, obj) -> None:
    """原子写 JSON（先写临时文件再替换）。"""
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    Path(tmp).replace(path)


class PacedPool:
    """带礼貌限速的线程池——对公网 WAF 保持低速。

    每请求执行前 sleep(min_interval + jitter)，并发受控。
    """

    def __init__(self, concurrency=3, min_interval_ms=300, jitter_ms=150):
        self.concurrency = max(1, min(int(concurrency), 16))
        self.min_interval = max(0, min_interval_ms) / 1000.0
        self.jitter = max(0, jitter_ms) / 1000.0
        self._lock = threading.Lock()
        self._last = 0.0
        self._executor = ThreadPoolExecutor(max_workers=self.concurrency)

    def _pace(self):
        with self._lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                time.sleep(wait + (random.random() * self.jitter))
            self._last = time.monotonic()

    def map(self, func, items):
        """顺序迭代，并发执行，保持 items 顺序的结果。"""
        futures = [self._executor.submit(self._wrapped, func, item) for item in items]
        return [f.result() for f in futures]

    def _wrapped(self, func, item):
        self._pace()
        return func(item)

    def shutdown(self):
        self._executor.shutdown(wait=True)
