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

1. **生成**（AI 智力密集）：从知识库 **216 原语** + 上一轮数据选方向，每条 payload 必须带「机制 + 理由」（WAF 看到 X，解析器做 Y → 为什么能绕）
2. **执行 + 学习**（机械）：入库去重 → Layer2 模板派生变体 → 远程实测 → 回写维度统计
3. **变强检查**（主动）：自动检测知识缺口（全拦 / 停滞 / KB 覆盖不足），主动申请联网检索扩充知识库
4. **汇报 + 询问**：每批输出摘要 + 推荐下一方向，永不默默停下

### 学习循环（数据驱动，不靠人设判断）

- 按原语聚合实测通过率，分档：**confirmed（≥60%）/ boundary / dead（=0%）**
- 熵优先选择下一方向（`info = p(1-p)`），有效维度被深挖、无效维度被剪枝
- **同义近义迭代**：对成功样本做同义替换派生新表达（`AND→&&`、`=→LIKE`、`FROM`，实测通过率统计入库，不标 100%）
- **结构新颖性优先**：`lib/structures.py` 每轮输出结构覆盖报告，设计目标锁定零通过/低覆盖结构，禁止只深化已 confirmed
- **语句合成器**：`lib/composer.py` 从「语句骨架 × 语法部件」结构性生成全新语句（`GET_LOCK`/`TABLE`/`CTE`/`HANDLER`），解耦新颖性与手写种子
- **种子策展**：`curate_seeds.py` 把通过样本按结构类提炼进 `knowledge/seeds.jsonl`，进化种子库
- **CMDi 语法门禁**：远程源站不执行命令，`bash -n` 本地校验后再实测，剔除无效载荷
- X-WAF-UUID 追踪，检测 WAF 规则升级并触发重基线复验

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

## 🔬 研究发现（WAF 语义引擎能力边界）

> 研究结论来自对真实云 WAF 的**授权远程实测**。样本载荷库是本地运行积累成果，不入库——本仓库只沉淀方法与结论。

**语义引擎检测强、边界失手**：

1. **对"形态完整"攻击检测强**：SQLi 结构变换、XSS 标签/事件、Log4j2 全 JNDI 混淆家族（rmi/dns/iiop/哈希片段/无点ı/lower/嵌套）均被语义化覆盖。
2. **对"零脚本语法"gadget 失手**：DOM clobbering（`<img name=currentScript>`）等无任何脚本语法的向量未被识别——这是语义引擎对"无特征形态"的结构性盲区。
3. **词法拆分最通用**：关键字双写/引号拆分/反斜杠靠"打断关键字连续匹配"稳定突破，sqli 与 cmdi 双场景互验。
4. **Log4j2 检出单向**：JNDI 混淆全拦，但 `${bundle:}`/`${env:}` 等非 JNDI 信息泄露 lookup 全放行——信息泄露面是缺口。
5. **上传配置注入盲区**：`.htaccess`/`user.ini` 配置指令、扩展名、multipart `filename*` 解析器差异类向量未拦，可执行 PHP 内容则被严格拦截。

**代表性技法**（按场景，载荷库为本地成果）：

| 场景 | 代表技法 |
|------|---------|
| SQLi | CASE WHEN × REGEXP 布尔盲注 · 关键字双重写 · 引号拆分 |
| CMDi | 参数展开 `${PATH:0:1}` 拼路径 · ANSI-C 引号 · 逻辑链稀释 |
| XSS | DOM clobbering（gadget 型，无脚本语法） |
| Upload | 配置注入（.htaccess/.user.ini）· multipart 解析器差异 |
| Log4j2 | 非 JNDI lookup 信息泄露 |

**工程能力**（学习循环让 skill 持续变强）：

- 结构覆盖报告驱动"生成前锁定零通过/低覆盖结构"
- 语句合成器从「语句骨架 × 语法部件」结构性生成全新语句
- 通过样本按结构类策展进进化种子库
- WAF 规则升级检测（X-WAF-UUID 追踪）+ 基线复验

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
│   │   ├── composer.py               #     语句合成器（结构性生成新语句）
│   │   └── structures.py             #     攻击结构分类 / 覆盖报告 / 新颖性缺口
│   ├── knowledge/                    #   知识库(216原语) + 已确认技法（种子/样本库为本地运行成果，不入库）
│   ├── corpus/                       #   样本库 samples.jsonl + 测试事件 tests.jsonl
│   ├── scripts/                      #   run_round.py 一轮循环 / curate_seeds.py 种子策展
│   ├── rounds/                       #   各轮探针与结果记录
│   └── targets/                      #   目标环境配置
├── platform/                         # 样本平台（waf-cli + Flask 只读仪表盘）
│   ├── cli.py                        #   命令行入口
│   ├── server.py                     #   Flask 仪表盘（总览/样本库/详情/知识库/状态）
│   └── pflib/                        #   storage / report
├── app/                              # 本地靶场 PHP 应用（SQLi/CMDi/Upload/XSS/Log4j2）
├── app-log4j/                        # Log4j2 实验应用
├── waf/                              # ModSecurity CRS PL4 配置
├── db/                               # MySQL 初始化
├── samples/                          # 目标定义 / 归档（移除样本历史数据不入库）
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
