---
name: semantic-mining
description: 自主安全研究员（v2）。约束"场景+攻击目标+成功标志"，不限制攻击路径，泛化生成高质量攻击用例并远程实测腾讯云 WAF。核心是生成 payload——生成→实测→学习→聚焦有效维度，产出能真正绕过 WAF 的样本。
argument-hint: <scenario> [--batches N] [--focus <direction_id>]
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
---

# 语义挖掘 Skill v2

## 核心理念

**生成 payload 是唯一重心。** 约束「场景 + 攻击目标 + 成功标志」，不限制攻击路径，泛化生成攻击用例。

- 成功判定：远程腾讯云 WAF —— **HTTP 200 = WAF 放行（绕过成功），403 = 被拦**。源站纯静态无反射，成功标志就是"这个真实攻击通过了 WAF"。
- **有效性由实测决定，不由"高级标签"决定**。低级但有效 → 好；花哨但无效 → 没用。
- 学习循环用实测通过率让有效技法自己浮出水面：有效维度被深挖、无效维度被剪枝。

## 四条纪律（违反即低质）

1. **每个 payload 必须有机制 + 理由**：`mechanism.primitives`（对应知识库原语）+ `generation.reason`（写出"WAF 看到 X，解析器做 Y → 为什么能绕"）。机械门禁会拒绝缺失的探针。
2. **禁止无机制凑数**：仅大小写/末尾空格/重复参数这类"换皮不变质"的纯凑数不入库。
3. **只做语义层，不碰编码**：编码变形（URL/Base64/Hex/Unicode）归未来 encoding-bypass skill。
4. **区分场景但别被框死**：五场景各有生成方向（见下表），但场景内不限制攻击路径，跨场景手法自由移植。
5. **完整攻击优先于单技法变换**：默认产出"目标明确 + 多层组合"的完整攻击（从 `组合配方` 出发改造），不是 `SELECT 1,2,3` 式计数探针换皮。单技法探针只用于确认某个原语单独的有效性。
6. **结构新颖性优先（治本）**：每轮先读结构覆盖报告（`lib/structures.py` 的 `novelty_gaps`），设计目标 = 零通过/低覆盖/boundary 结构。**重复已 confirmed 结构 = 低质**。可用 `python3 -c "from lib import structures; ..."` 快速看当前哪些结构垄断、哪些是缺口。

## 场景生成方向

| 场景 | 注入面 | 攻击目标（绕 WAF 的哪类检测） | 生成方向起点 |
|------|--------|------------------------------|-------------|
| sqli | query `?id=` | UNION/盲注/报错注入 | 差异原语驱动：版本注释/空白替换/引号拆分/运算符替代/子查询 |
| xss | query `?q=` / path | script/事件处理器/协议注入 | 上下文逃逸 + mXSS + JS 函数混淆 |
| cmdi | query `?cmd=` | 命令执行/敏感文件读取 | 引号拆分/IFS/ANSI-C/glob/逻辑链稀释 |
| upload | multipart `file` | 恶意文件上传 | 扩展名/内容短标签/动态函数/配置注入 |
| log4j2 | header(UA/XFF)/body | ${jndi}/lookup 表达式 | lookup 混淆（lower/::-/env/嵌套） |

## 4 步循环

```
/semantic-mining <scenario> [--batches N] [--focus <direction_id>]
```

### Step 0 — 就绪（机械，~1 分钟）
1. 连通性自检：`python3 lib/executor.py --selfcheck` → 必须 PASS
2. 读记忆：`skill_state.json`（当前维度统计/confirmed/dead/pending）+ `knowledge/confirmed_techniques.jsonl`
3. 读知识库对应场景章节：`knowledge/advanced_bypass.md`（找没试过的原语）

### Step 1 — 生成（核心，AI 智力密集）
两层生成，产出 `probes.jsonl`：

**Layer1 — AI 知识驱动（攻击设计优先）**（你写，质量来源）：
- **先设计完整攻击，再标注原语，而不是"挑个技法套到模板上"**。起手式是"构造一个从 flags 表读出 flag 的注入/命令/脚本"，然后决定用什么组合、什么上下文，最后把用到的原语**事后**标注进 `mechanism.primitives`。
- **攻击类别横切（必须）**：每批至少覆盖 4 种攻击类别，**禁止收敛在单一形态**（前几轮全 UNION SELECT 就是没横切）。各场景类别清单：
  - sqli = UNION/集合 · 布尔盲注 · 时间盲注 · 报错注入 · 堆叠查询 · 预处理 · 无列名 · 文件读写 · 宽字节 · sys库
  - cmdi = 读文件 · 命令执行 · 外带 · 环境变量 · 解释器 · 进程替换 · 时间探测
  - xss = 标签/事件 · mXSS · DOM遮蔽 · 模板上下文 · 协议 · CSS注入 · meta/base · 两阶段
  - upload = 扩展名 · 内容混淆 · 配置注入 · multipart解析器差异
  - log4j2 = JNDI · 非JNDI泄露 · 嵌套外带 · 大小写/Unicode折叠
- **未测原语优先**：生成前查该场景 KB 未测原语（knowledge_gaps / grep advanced_bypass.md），优先补测新类别，**而不是继续深挖已 confirmed 的**（深挖是保量，横切才是发散）。
- **先读结构覆盖（治本纪律）**：生成前必跑 `python3 -c "from lib import structures; ..."` 读结构覆盖报告，设计目标 = `novelty_gaps` 的 **zero_pass / low_coverage / boundary** 结构，禁止只深化已 confirmed 结构。结构新颖性是第一目标，通过率是第二。
- **默认多层组合**：≥2 个原语、≥2 个层；单技法变换只作对照补充，不作为主力
- **优先展开**：confirmed 技法（深度+跨层双轴）、boundary 技法（熵最高）、未测原语
- **跳过**：dead 原语（除非有跨层组合的新理由）
- 每个 payload 必须满足四条纪律；reason ≥20 字符；**能说清"WAF 看到什么、解析器做什么、为什么漏"**
- 每批 10-30 条 AI 探针（控制质量，不要一次堆几百条粗制滥造）

**Layer2 — 代码派生**（机械，交给脚本）：run_round.py 会对你的探针自动施加语义保持变换批量派生变体（含多层组合变换）。

**Layer2.5 — 语句合成器（结构性生成，必开）**：`run_round.py --compose N` 从"语句骨架 × 语法部件"（`lib/composer.py`）自动组合**全新语句**，不依赖手写种子。
- **为什么必须有它**：Layer-2 只能对已有 payload 做词法突变，永远无法创造新语句（这就是"样本全是一句话变体"的根因）。新颖性必须由结构性生成产生，不能靠手写种子碰运气。
- **已验证**：composer 自动生成的 `IS_FREE_LOCK('x')` 锁函数盲注突破 114 条（从未手写过）；`GET_LOCK`/`ST_X`/`JSON_KEYS`/`@@version`/`TABLE`/`VALUES`/`CTE`/`HANDLER`/`DO` 等新语句类型系统化覆盖。
- **每轮建议**：`--compose 30-40` 常开，与 Layer-1 手写种子并用。

```bash
# 写探针到文件（每行一个 JSON，字段见下）
# 然后跑一轮机械循环
python3 scripts/run_round.py --scenario <scenario> --input probes.jsonl --name run_<scenario>_r<N>
```

**探针格式**（AI 门禁校验通过才能入库）：
```json
{"payload": "1 UN'ION' SE'LECT' 1,2,3",
 "scenario": "sqli", "category": "semantic_bypass",
 "mechanism": {"layers": ["lexical"],
               "primitives": [{"id": "sqli:lexical:quote_split", "kb_ref": "advanced_bypass.md#sqli-lexical"}],
               "encodings": [], "summary": "UN'ION' 引号拆分"},
 "generation": {"source": "ai", "reason": "WAF 正则匹配连续 UNION；MySQL 相邻字符串字面量自动连接，UN'ION' 语义等价 UNION，引号打断关键字连续匹配"}}
```

### Step 2 — 执行 + 学习（机械，run_round.py 完成）
脚本自动：入库去重 → Layer2 派生 → 远程实测（并发3+限速）→ 学习回写（维度统计/confirmed/dead/pending/WAF UUID 追踪）→ 知识缺口自检（knowledge_gaps）→ 输出摘要。

**成功样本迭代（skill 变强）**：对已通过的样本做两类迭代——
- **同义近义迭代**（机械）：`--iterate-synonyms N` 按 `knowledge/synonyms.json` 换词派生（AND→&&、=→LIKE）。已实测 sqli 一轮 124/296 通过。
- **AI 重构**（智力）：取已通过样本，**保留绕过机制、重构整体形态**——换结构、叠加新层、套不同上下文（如把 `1 UNIONunion SELECT 1,2,3` 重构为 `1/*!50000UNI''ON*/%0aSEL/**/ECT 1,(SELECT flag FROM flags),3-- -`）。同一条有效机制由此放大成一批完全不同字面的攻击，而不是近义词微调。

你只需要读摘要：`stats`（passed/blocked）、`top_dimensions`（通过率排序）、`pending_directions`、`knowledge_gaps`。

### Step 2.5 — 变强检查（主动性，必须）
读 `skill_state.json` 的 `knowledge_gaps`：
- **有缺口** → 你**主动**判断这是"知识不足"还是"WAF 太强"，然后**向用户提出联网检索申请**，附具体检索主题（如 `sqli 冷门绕过 2024-2025`、`cloud WAF xss semantic blindspot`）。用户批准后执行检索，把新技法**追加进 advanced_bypass.md**（KB 持续长大，这就是变强）。
- **原理驱动而非排列组合**：生成 payload 时从原语的**原理**（WAF 看到 X / 解析器做 Y）推导新表达，不要只照抄 KB 模板换参数。排列组合是保量，原理推导才是质。
- **已确认技法深挖**：confirmed 技法（≥60% 通过）做"同义迭代 + 跨层叠加"双轴展开，把它变成一批而非一条。

### Step 3 — 汇报 + 询问（必须）
输出本批摘要并询问用户：
```
第 N 批完成: 探针 X | 放行 Y (绕过率 Z%) | 新confirmed: ... | 新dead: ...
有效方向: UN'ION'(53%) 双重写(38%)
新增待探索: 引号拆分×版本注释组合、跨场景移植到 xss on'er'ror'
下一批建议:
  1. 深挖 UN'ION' × 更多变体（已验证 53%，冲 confirmed）
  2. 换场景（cmdi 引号拆分在本地lab全过，远程值得测）
  3. 协议层: HPP 参数污染
继续？(选 1/2/3 / 自定义方向 / stop)
```

**AI 不能默默停下，也不能闷头狂跑。** 每批结束必须：摘要 → 推荐方向 → 询问。用户说停才停。

### 方向永不枯竭（四轴）
每批后沿四轴追加 pending_directions 到 skill_state.json：
- **深度**：同一原语更多变体/更强混淆
- **广度**：知识库同层其他原语逐个试
- **跨层**：词法×语法×语义叠加（组合爆炸是无限引擎）
- **跨场景**：已验证技法移植到别的场景（CMDi `c'a't` → SQLi `UN'ION'` → XSS `on'er'ror'`）

## 最终报告（终止时输出）

```
═══ 语义挖掘报告 — <scenario> ═══
📊 数据: 轮次 N | 总探针 M | 绕过率 P% | confirmed A 项 | dead B 项
🎯 有效样本(通过WAF): 列出前 N 条（payload + 原语 + 通过证据）
📈 维度有效排行: 表格（原语 | 测试数 | 通过率 | 评价）
💡 关键洞察: 2-3 条（对当前 WAF 的能力边界结论）
📁 数据: corpus/samples.jsonl + tests.jsonl + skill_state.json
```

## 文件与命令速查

- 知识库: `knowledge/advanced_bypass.md`（原语 id 与 corpus 一一对应）
- 样本库: `corpus/samples.jsonl`（平台读取这里）、`corpus/tests.jsonl`（测试事件流）
- 记忆: `skill_state.json`、`knowledge/confirmed_techniques.jsonl`
- 目标: `targets/profile.json`（IP+Host、placements、block_signals）
- 自检: `python3 lib/executor.py --selfcheck`
- 一轮: `python3 scripts/run_round.py --scenario <s> --input probes.jsonl`
- 单条实测: `python3 -c "from lib import executor; ..."`（或平台 CLI）

## 技术约束

1. 黑盒。信息通过 HTTP 探测推断，不读源站源码。
2. 假设后端：SQLi=MySQL、CMDi=POSIX sh、Upload=PHP、XSS/Log4j2 判 WAF 层。
3. 对公网 WAF 保持礼貌：并发≤3、间隔 300ms+jitter；`--dry-run` 先验不实发。
4. 语义有效性 = 知识库确认制（payload 对应已文档化的真实攻击原语）。无法证明是真攻击的样本标 boundary_marker，不吹成绕过。
5. 不做编码 payload。
