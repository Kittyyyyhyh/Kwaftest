"""
JSONL 读写工具 + 进度追踪
"""
import json
import os
from typing import Iterator, Any, Optional


def read_jsonl(path: str) -> Iterator[dict]:
    """流式读取 JSONL 文件，每行返回一个 dict"""
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: str, obj: dict, append: bool = True):
    """追加一行 JSON 到文件"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = 'a' if append else 'w'
    with open(path, mode, encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False) + '\n')


def count_lines(path: str) -> int:
    """快速统计 JSONL 文件行数"""
    if not os.path.exists(path):
        return 0
    count = 0
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def load_json(path: str) -> Any:
    """加载 JSON 文件"""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(path: str, data: Any):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def format_duration(seconds: float) -> str:
    """格式化时长"""
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s"


def format_progress(current: int, total: int, elapsed: float,
                    blocked: int, flag: int, errors: int) -> str:
    """格式化进度条"""
    pct = current / total * 100 if total > 0 else 0
    rate = current / elapsed if elapsed > 0 else 0
    eta = (total - current) / rate if rate > 0 else 0

    bar_len = 20
    filled = int(bar_len * current / total) if total > 0 else 0
    bar = '█' * filled + '░' * (bar_len - filled)

    return (f"[{bar}] {current}/{total} ({pct:.1f}%) | "
            f"{rate:.1f} samples/s | ETA: {format_duration(eta)} | "
            f"🛡️{blocked} ✅{flag} ⚠️{errors}")
