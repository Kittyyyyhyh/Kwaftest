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

**Layer1 — AI 知识驱动**（你写，质量来源）：
- 从 advanced_bypass.md 该场景章节 + skill_state 的 pending_directions 选方向
- **优先展开**：confirmed 技法（深度+跨层双轴）、boundary 技法（熵最高）、未测原语
- **跳过**：dead 原语（除非有跨层组合的新理由）
- 每个 payload 必须满足四条纪律；reason ≥20 字符
- 每批 10-30 条 AI 探针（控制质量，不要一次堆几百条粗制滥造）

**Layer2 — 代码派生**（机械，交给脚本）：run_round.py 会对你的探针自动施加语义保持变换批量派生变体。

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

**成功样本迭代（skill 变强）**：对已通过的样本做同义近义迭代派生新表达——`--iterate-synonyms N` 取前 N 个已成功样本，按 `knowledge/synonyms.json` 同义词表 + 混淆加深派生新候选，再实测。已实测 sqli 同义迭代一轮 124/296 通过（AND→&&、=→LIKE 全 100%）。

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
