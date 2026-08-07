# OWASP CRS PL4 已知盲区

基于 CRS PL4（Paranoia Level 4）规则集的实际测试发现，按规则编号组织。

---

## CMDi — 932 系列 RCE 规则

### 932100 — Unix 命令注入（分隔符）

**检测内容**：`;` `|` `&` 作为命令分隔符
**实际发现**：
- ✅ `;` → PL4 下**放行**（对 P1/P2 路径）
- ✅ `|` → PL4 下**放行**
- ✅ `||` → PL4 下**放行**
- ✅ `&&` → PL4 下**放行**
- ✅ `%0a`（换行注入）→ PL4 下**放行**
- 🛡️ `$()` → PL4 下**拦截**
- 🛡️ `` ` `` → PL4 下**拦截**
- 🛡️ `${IFS}` → PL4 下**拦截**

**盲区结论**：CRS 对简单分隔符（`;` `|` `||` `&&`）的评分不足触发 PL4 阈值。复杂语法（命令替换）被精准拦截。

### 932105 — Unix 命令注入（直接命令）

**检测内容**：`/bin/sh` `/bin/bash` `|/bin/sh`
**实际发现**：`;cat` 等简单命令组合未被拦，但 `|sh` 管道执行模式需要警惕。

### 932115 — Unix 命令注入（路径前缀）

**检测内容**：`/etc/` `/proc/` `/sys/` `/var/log/` `/var/www/` `/tmp/` `/root/` `/home/`
**实际发现**（基于 71 条路径探测）：
- `/etc/*` → 🛡️ 100% 拦截
- `/proc/*` `/sys/*` → 🛡️ 100% 拦截
- `/var/log/*` → 🛡️ 100% 拦截
- `/var/www/*` → 🛡️ 100% 拦截
- `/tmp/*` `/root/*` `/home/*` → 🛡️ 100% 拦截
- `/usr/share/*` → ✅ 放行（不在黑名单）
- `/srv/*` → ✅ **完全放行**（不在任何路径黑名单）

**盲区结论**：CRS PL4 路径检测基于**路径前缀黑名单**，`/srv/*` 不在黑名单中。这是 CMDi 的 P1/P2 目标能成功绕过的核心原因。

### 932150 — Unix 命令注入（网络工具黑名单）

**检测内容**：`wget` `curl` `nc` `ncat` `socat` `fetch` `lwp-request`
**盲区**：
- `ftp` `tftp` `scp` → 不在黑名单
- Python/Perl 单行网络请求 → 不在黑名单
- `busybox wget` → busybox 前缀可能绕过（需要实际测试）

### 932160 — Unix 命令注入（文件读取工具黑名单）

**检测内容**：`sleep` `tail` `head` `od` `strings` `base64` `xxd`
**实际发现**：
- 🛡️ `base64 -d` → 拦截（`;echo B64|base64 -d|sh` 模式触发了规则）
- 🛡️ `whoami` `uname` → 拦截（因为这些命令名在其他规则中被引用）

**盲区**（大量文件读取/处理命令不在黑名单）：
- `dd` → ✅ 不在黑名单，可读文件
- `tee` → ✅ 不在黑名单，可读文件
- `cut` → ✅ 不在黑名单，可读文件
- `sort` → ✅ 不在黑名单，可读文件
- `tr` → ✅ 不在黑名单
- `file` → ✅ 不在黑名单
- `awk` → ✅ 不在黑名单
- `sed` → ✅ 不在黑名单
- `expr` → ✅ 不在黑名单
- `printf` → ✅ 不在黑名单
- `fold` → ✅ 不在黑名单
- `hexdump` → ✅ 不在黑名单

**盲区结论**：932160 的黑名单覆盖率非常有限。至少 12 个文件读取命令完全不在黑名单中。

---

## SQLi — 942 系列 SQL 注入规则

### 942100 — SQL 注入（Libinjection）

**检测内容**：基于 libinjection 指纹算法，检测 SQL 注入攻击 token 序列
**实际发现**（基于探针缓存）：
- 🛡️ UNION SELECT → 100% 拦截
- 🛡️ UNION ALL SELECT → 100% 拦截
- 🛡️ 注释混淆 `/**/` → 100% 拦截
- 🛡️ MySQL 版本注释 `/*!50000*/` → 100% 拦截
- 🛡️ extractvalue → 100% 拦截

**盲区可能性**：
- ORDER BY + CASE WHEN 的 token 序列与 WHERE + UNION 完全不同 → libinjection 可能漏检
- 深度嵌套函数（`CONVERT(CONCAT(...))`）超出 libinjection 训练深度
- 非 WHERE 子句的攻击模式（HAVING、LIMIT）训练覆盖率低

### 942150 — SQL 注入（UNION SELECT）

**检测内容**：`UNION SELECT` `UNION ALL SELECT` `UNION DISTINCT SELECT`
**盲区**：
- `UNION(SELECT)` → 括号替代空格
- 子查询无 UNION 前缀：`AND (SELECT ... FROM ...)`
- ORDER BY + 子查询（无 UNION 关键字）

### 942190 — SQL 注入（十六进制编码）

**检测内容**：`0x` 后跟十六进制字符
**盲区**：
- `X'NNNN'` → 替代十六进制字面量
- `UNHEX('NNNN')` → 函数调用形式
- `CHAR(78,78,78)` → 十进制字符构造

### 942360 — SQL 注入（经典注入模式）

**检测内容**：`OR 1=1` `' OR '1'='1`
**盲区**：这些特征在 WHERE 子句中常见，但在 ORDER BY/GROUP BY/HAVING 中不适用

### 总体 SQLi 盲区评估

CRS PL4 对 SQLi 的检测**极其完备**（基于 libinjection + 关键词 regex 双层检测）。主要突破口：
1. 非 WHERE 子句注入（ORDER BY + CASE WHEN）
2. 深度函数嵌套混淆
3. MySQL 特有扩展语法（PROCEDURE ANALYSE）

---

## Upload — 933 系列 PHP 注入规则

### 933110 — PHP 注入（脚本标签）

**检测内容**：`<?php` `<?=`
**实际发现的 W1 结论**：100% 拦截，包括 GIF header 伪装后仍被拦

**盲区可能性**：
- `<?=` 短标签同样被检测，因为 CRS 已更新覆盖
- 极短 webshell + 动态函数可能降低内容评分

### 933150 — PHP 注入（高风险函数）

**检测内容**：`system(` `exec(` `passthru(` `shell_exec(` `popen(` `proc_open(`
**盲区**：
- 反引号在 PHP 中执行命令：`` `cmd` ``（CRS 检测反引号吗？）
- 动态调用：`$f='sys'.'tem'; $f('cmd');`
- `call_user_func('system', 'cmd')`

### 933160 — PHP 注入（中风险函数）

**检测内容**：`file_get_contents(` `file(` `fopen(` `readfile(`
**盲区**：
- OOP 方式：`new SplFileObject('/etc/motd')`
- `glob('/etc/*')` 目录扫描

---

## XSS — 941 系列 XSS 规则

### 941100 — XSS 攻击检测

**检测内容**：`<script>` 标签、事件处理器、`javascript:` 协议
**通用盲区**：
- 标签/属性名大小写混合
- HTML 实体编码在属性值中
- 省略引号、省略闭合标签
- 浏览器容错解析的边界情况

---

## 自定义规则

### Z-custom-rules.conf

项目中已有的自定义规则：
- 路径前缀白名单/黑名单
- 自定义评分阈值

### REQUEST-945-CUSTOM-HEADERS.conf

自定义请求头检测规则。
