# WAF 语义绕过测试 · AI 驱动样本构建

> 面向 WAF 语义引擎的能力验证：以 **AI 自主安全研究员 Skill** 为核心，约束「场景 + 攻击目标 + 成功标志」、不限制攻击路径，泛化生成高质量攻击用例并对真实云 WAF 远程实测，产出可复现的绕过样本库。

---

## 🎯 项目背景

WAF 正从传统规则引擎向语义引擎演进。在命令注入、SQL 注入、Log4j 反序列化等场景中，攻击命令形态松散，单纯依赖新增规则拦截会陷入被动；攻击者大量借助多层/嵌套编码对载荷变形绕过。

本项目在**确定场景、确定攻击目标、确定成功标志**的前提下，不限制攻击路径、仅约束生成方向，用 AI 泛化生成攻击测试用例，验证 WAF 语义引擎在**意图级语义识别**与**多样化编码解码还原**两方面的能力边界。

两条能力线：**语义绕过**（本 Skill 已落地）与**编码绕过**（规划中，作为语义的变形维度叠加）。

---

## 🧠 核心：semantic-mining Skill v2（语义挖掘）

自主安全研究员 Skill。核心是**生成 payload**——生成 → 远程实测 → 学习 → 聚焦有效维度，产出能真正绕过 WAF 的样本。

### 4 步循环

```
/semantic-mining <scenario> [--batches N] [--focus <direction_id>]
```

1. **生成**（AI 智力密集）：从知识库 144 原语 + 上一轮数据选方向，每条 payload 必须带「机制 + 理由」（WAF 看到 X，解析器做 Y → 为什么能绕）
2. **执行 + 学习**（机械）：入库去重 → Layer2 模板派生变体 → 远程实测 → 回写维度统计
3. **变强检查**（主动）：自动检测知识缺口（全拦 / 停滞 / KB 覆盖不足），主动申请联网检索扩充知识库
4. **汇报 + 询问**：每批输出摘要 + 推荐下一方向，永不默默停下

### 学习循环（数据驱动，不靠人设判断）

- 按原语聚合实测通过率，分档：**confirmed（≥60%）/ boundary / dead（=0%）**
- 熵优先选择下一方向（`info = p(1-p)`），有效维度被深挖、无效维度被剪枝
- **同义近义迭代**：对成功样本做同义替换派生新表达（`AND→&&`、`=→LIKE`、`FROM` 均 100% 确认）
- X-WAF-UUID 追踪，检测 WAF 规则升级并触发重基线

### 知识库

- `knowledge/advanced_bypass.md` — 5 场景 × 绕过维度（词法/语法/语义层，纯语义不碰编码）
- `knowledge/synonyms.json` — 机器可读同义词表（迭代引擎）
- `knowledge/confirmed_techniques.jsonl` — 学习回写：对当前 WAF 实测有效的技法
- `knowledge/evaluation_rubric.md` — 有效/危害/洞察/可用 四维质量评分

---

## 📦 样本平台（platform/）

维护与展示样本库的 CLI + Web 仪表盘，读写 skill 的 corpus：

```bash
# CLI
python3 platform/cli.py corpus list --scenario sqli --status passed   # 样本库查询
python3 platform/cli.py report                                        # 统计报表 (md/json)
python3 platform/cli.py test run --status pending --limit 20          # 远程批量实测
python3 platform/cli.py test status                                   # 状态总览
python3 platform/cli.py corpus export --scenario sqli --format md     # 导出

# Web 仪表盘 (Flask)
python3 platform/server.py --port 8787    # http://127.0.0.1:8787
```

仪表盘：总览指标 / 样本库筛选 / 样本详情（机制+测试历史） / 知识库浏览 / Skill 状态。

---

## 📊 样本成果（已确认样本集）

> 口径：样本库**只保留远程实测通过**（HTTP 200 = WAF 放行）的样本，已确认绕过率 100%。

| 指标 | 值 |
|---|---|
| 已确认样本 | **205**（唯一 payload 180） |
| 场景分布 | sqli 191 · cmdi 13 · log4j2 1 |
| 已确认技法 | 3（`AND→&&` / `=→LIKE` / `FROM` 同义替换，100%） |
| 实测环境 | 真实云 WAF（远程，200=放行 / 403=拦截） |

**有效技法示例（真实通过云 WAF）**：

| 技法 | 原语 | 示例 |
|------|------|------|
| 关键字双重写 | `gen:double_write` | `1 UNIONunion SELECT 1,2,3` |
| 引号拆分 | `gen:quote_split` | `1 UN'ION SELECT 1,2,3` |
| 版本注释 × 拆分 | `gen:version_comment` | `1 /*!50000UN'ION*/ SELECT 1,2,3` |
| 空白替换 × 拆分 | `gen:whitespace_sub` | `1%a0UN'ION SELECT 1,2,3` |
| CMDi glob | `cmdi:syntactic:glob` | `;/???/passwd` |
| Log4j2 非 JNDI lookup | `log4j2:lookup:info_disclosure` | `${bundle:application:spring.datasource.password}` |

**关键洞察**：

1. **SQLi 是主突破口**：同义替换类原语（词法层不触发关键字连续匹配）是云 WAF 的明确盲区；双写/引号拆分靠"打断连续匹配"有效。
2. **XSS 内容层全面被拦**：mXSS、JS 混淆、冷门标签事件全拦——云 WAF 对 XSS 语义层检测强。
3. **Log4j2 非 JNDI 突破**：`${jndi:...}` 各类混淆全拦，但 `${bundle:...}` ResourceBundle 信息泄露 lookup 通过——WAF 只盯 jndi/ldap 关键字，漏了真实攻击面。
4. **WAF 差异巨大**：本地 CRS PL4 上 100% 通过的技法在云 WAF 上可能 0%，必须逐个从零画边界。

---

## 🏗️ 本地靶场（辅助，用于攻击可行性验证）

语义 Skill 对远程云 WAF 实测；本地 Docker 靶场用于验证攻击本身是否成立（消除"被 WAF 拦 = 攻击无效"的歧义）。

- **架构**：浏览器 → WAF (ModSecurity CRS PL4 :8090) → App (PHP-Apache) → DB (MySQL)
- **场景**：SQLi / CMDi / 文件上传 / XSS / Log4j2，每场景 2 关
- **验证体系**：蜜标 (honeytoken) + 输出匹配 + side-effect 三层验证，攻击成功有明确 flag 标志

```bash
docker compose up -d
open http://localhost:8090/index.php
curl "http://localhost:8090/sqli/level1.php?id=1+UNION+SELECT+1,2,3"   # → 403
```

---

## 📁 项目结构

```
├── .claude/skills/semantic-mining/   # ★ 语义挖掘 Skill（自包含，可独立使用）
│   ├── SKILL.md                      #   4 步循环工作流
│   ├── lib/                          #   schema / 生成器 / 远程执行器 / 学习分析
│   ├── knowledge/                    #   知识库 + 已确认技法 + 同义词表
│   ├── corpus/                       #   样本库 samples.jsonl + 测试事件 tests.jsonl
│   ├── scripts/                      #   run_round.py 一轮机械循环
│   └── targets/                      #   目标环境配置
├── platform/                         # 样本平台（waf-cli + Flask 仪表盘）
│   ├── cli.py                        #   命令行入口
│   ├── server.py                     #   Flask 仪表盘
│   └── pflib/                        #   storage / runner / report
├── app/                              # 本地靶场 PHP 应用（SQLi/CMDi/Upload/XSS/Log4j2）
├── app-log4j/                        # Log4j2 实验应用
├── waf/                              # ModSecurity CRS PL4 配置
├── db/                               # MySQL 初始化
├── samples/                          # 目标定义 / 编码配方 / 归档
└── docker-compose.yml                # 本地靶场编排
```

---

## 🚀 快速开始

```bash
# 1. Skill 连通性自检（需配置自己的 WAF 目标）
cd .claude/skills/semantic-mining
python3 lib/executor.py --selfcheck

# 2. 一轮机械循环（AI 写探针 → 门禁 → 派生 → 实测 → 学习）
python3 scripts/run_round.py --scenario sqli --input probes.jsonl --dry-run
python3 scripts/run_round.py --scenario sqli --input probes.jsonl --name run_sqli_r1

# 3. 平台查看成果
python3 platform/cli.py report
python3 platform/server.py --port 8787    # http://127.0.0.1:8787
```

---

## 🔒 技术约束

- 所有测试活动均在**授权范围内**进行，遵守负责任披露（Responsible Disclosure）原则
- 靶场环境本地/隔离部署，不对未授权目标攻击
- 仅用于安全研究、教育目的和 WAF 能力提升
- 攻击样本仅针对本项目自有测试环境
