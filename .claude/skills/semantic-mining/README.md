# semantic-mining Skill v2 — 语义挖掘（纯语义，远程腾讯云 WAF）

自主安全研究员 Skill：约束「场景 + 攻击目标 + 成功标志」，不限制攻击路径，泛化生成攻击用例并对远程腾讯云 WAF 实测。

## 快速开始

```bash
# 0. 连通性自检（发 2 条请求）
python3 lib/executor.py --selfcheck
#   良性 'hello' → passed；恶意 '<script>alert(1)</script>' → blocked

# 1. 一轮机械循环（AI 写探针 → 门禁 → 入库 → 派生 → 实测 → 学习）
python3 scripts/run_round.py --scenario sqli --input probes.jsonl --dry-run   # 先试跑
python3 scripts/run_round.py --scenario sqli --input probes.jsonl --name run_sqli_r1
```

## 目录结构

```
├── SKILL.md                     # 4 步循环（生成→执行→学习→再生成）
├── lib/                         # 核心（纯 stdlib，py3.8 兼容）
│   ├── schema.py                # 统一 schema（SampleRecord + TestEvent 双流）
│   ├── generator.py             # Layer2 模板派生引擎（transform_catalog）
│   ├── executor.py              # 远程执行器（IP+Host / 200=放行 / X-WAF-UUID）
│   ├── analysis.py              # 学习循环（维度统计/confirmed/dead/方向）
│   └── util.py                  # 限速 PacedPool / 哈希 / JSONL
├── knowledge/
│   ├── advanced_bypass.md       # 【核心】场景×绕过维度知识库（纯语义）
│   ├── confirmed_techniques.jsonl  # 学习回写：对当前 WAF 有效技法
│   └── evaluation_rubric.md     # 四维质量评分
├── corpus/
│   ├── samples.jsonl            # 样本库（平台读取这里）
│   └── tests.jsonl              # 测试事件流
├── targets/profile.json         # 远程目标单一事实来源
├── scripts/run_round.py         # 一轮机械循环入口
└── _legacy/                     # v1 遗留（本地 lab 时代）
```

## 远程目标判定

- `http://<WAF_TARGET_IP>` + `Host: <WAF_TARGET_HOST>`
- **200 = WAF 放行（绕过成功）；403 = 被拦**；429/限流特征 = rate_limited
- 拦截签名：403 + body 含 "您的请求已中断"/"腾讯云WAF"/请求UUID
- `X-WAF-UUID` 出现在所有响应（含良性）——是请求追踪 ID，用于检测 WAF 规则升级，非拦截信号

## 迁移到新环境

目录完全自包含（纯 stdlib，零外部依赖）。迁移 = 复制整个目录，改 `targets/profile.json` 的 `ip/host` 即可。

```bash
# 单独上传 git（可选）
cd .claude/skills/semantic-mining && git init && git add . && git commit -m "semantic-mining skill v2"
```

## 数据流

```
AI(Claude) 读 advanced_bypass.md + skill_state → 写探针(机制+理由)
  → run_round.py: 门禁 → 入库去重 → Layer2 模板派生 → 远程实测(并发3限速)
  → 学习回写 dimension_stats/confirmed/dead/pending → 摘要
  → AI 读摘要 → 四轴追加方向 → 询问用户 → 下一批
```
