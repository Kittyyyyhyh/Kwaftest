#!/usr/bin/env python3
"""
批量执行器 — 流式执行 JSONL 样本批次，支持续传和进度追踪

用法:
    python scripts/execute_batch.py samples/batches/batch_001.jsonl
    python scripts/execute_batch.py samples/batches/batch_001.jsonl --resume
    python scripts/execute_batch.py samples/batches/batch_001.jsonl --limit 10
    python scripts/execute_batch.py samples/batches/batch_001.jsonl --progress-every 20
"""
import sys
import io
import os
import json
import time
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.transport import execute_sample
from lib.utils import read_jsonl, write_jsonl, count_lines, format_duration, format_progress

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    except (AttributeError, OSError):
        pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def execute_batch(batch_path: str, output_path: str = None,
                  limit: int = 0, resume: bool = False,
                  progress_every: int = 50, max_retries: int = 3,
                  run_id: str = None):
    """流式执行批次文件"""
    if not run_id:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if not output_path:
        output_path = os.path.join(BASE_DIR, "samples", "results", f"{run_id}.jsonl")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # 读入全部样本（JSONL 文件不会太大，10K条 ~4MB）
    all_samples = list(read_jsonl(batch_path))
    if not all_samples:
        print("❌ 批次文件为空或不存在")
        return

    total = len(all_samples)

    # 续传：跳过已完成的
    completed_ids = set()
    if resume and os.path.exists(output_path):
        for r in read_jsonl(output_path):
            sid = r.get("sample_id", "")
            if sid and r.get("attack_successful") is not None:
                completed_ids.add(sid)

    pending = [s for s in all_samples if s.get("sample_id") not in completed_ids]
    skipped = total - len(pending)

    if limit > 0:
        pending = pending[:limit]

    print(f"🚀 执行批次: {os.path.basename(batch_path)}")
    print(f"   Run ID: {run_id}")
    print(f"   总样本: {total} | 已完成: {skipped} | 待执行: {len(pending)} | 限制: {limit or '无'}")
    print(f"   输出: {output_path}")
    print()

    # 执行
    start_time = time.time()
    blocked = 0
    flags = 0
    errors = 0
    success_samples = []

    for i, sample in enumerate(pending):
        t0 = time.time()

        try:
            result = execute_sample(sample, run_id)
        except Exception as e:
            result = {
                "sample_id": sample.get("sample_id", "?"),
                "scenario": sample.get("scenario", "?"),
                "level": sample.get("level", 0),
                "transport": sample.get("transport", "?"),
                "error_message": str(e),
                "attack_successful": False,
            }

        # 重试逻辑
        retries = sample.get("retries", 0)
        while result.get("error_message") and retries < max_retries:
            retries += 1
            sample["retries"] = retries
            time.sleep(1)  # 短暂等待后重试
            try:
                result = execute_sample(sample, run_id)
            except Exception:
                pass

        result["retry_count"] = retries
        result["execution_duration_ms"] = int((time.time() - t0) * 1000)

        # 统计
        if result.get("waf_blocked"):
            blocked += 1
        if result.get("flag_captured"):
            flags += 1
            if result.get("attack_successful"):
                success_samples.append(result)
        if result.get("error_message"):
            errors += 1

        # 写入结果
        write_jsonl(output_path, result)

        # 进度报告
        done = skipped + i + 1
        if (i + 1) % progress_every == 0 or (i + 1) == len(pending):
            elapsed = time.time() - start_time
            bar = format_progress(done, total, elapsed, blocked, flags, errors)
            # 打印最近一个成功绕过的样本
            last_success = ""
            if success_samples:
                last = success_samples[-1]
                last_success = f" | 最近: {last['scenario']}/L{last['level']} {last.get('flag_captured','')}"
            print(f"  {bar}{last_success}")

    # 汇总
    elapsed = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"  执行完成!")
    print(f"  耗时: {format_duration(elapsed)} | 速率: {len(pending)/elapsed:.1f} samples/s")
    print(f"  🛡️ 拦截: {blocked} | ✅ 拿flag: {flags} | ⚠️ 错误: {errors}")

    if success_samples:
        print(f"\n  🎯 WAF ON下成功绕过:")
        for s in success_samples:
            if s.get("waf_enabled"):
                print(f"    ✅ {s['scenario']}/L{s['level']}: {s.get('flag_captured','')} "
                      f"({'+'.join(s.get('encoding_ids',[])) or 'none'})")
    print(f"{'='*70}")


def main():
    parser = argparse.ArgumentParser(description="WAF批量执行器")
    parser.add_argument("batch", help="样本批次文件 (JSONL)")
    parser.add_argument("--output", default=None, help="结果输出路径")
    parser.add_argument("--limit", type=int, default=0, help="限制执行数量（调试用）")
    parser.add_argument("--resume", action="store_true", help="续传模式（跳过已完成）")
    parser.add_argument("--progress-every", type=int, default=50, help="进度报告间隔")
    parser.add_argument("--max-retries", type=int, default=3, help="最大重试次数")
    parser.add_argument("--run-id", default=None, help="运行批次ID")
    args = parser.parse_args()

    execute_batch(
        batch_path=args.batch,
        output_path=args.output,
        limit=args.limit,
        resume=args.resume,
        progress_every=args.progress_every,
        max_retries=args.max_retries,
        run_id=args.run_id,
    )


if __name__ == "__main__":
    main()
