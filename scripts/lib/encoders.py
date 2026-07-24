"""
编码函数库 — 每种编码提供 encode/decode 对，用于自校验

所有 encode 函数签名: (text: str) -> str
所有 decode 函数签名: (text: str) -> str
"""
import urllib.parse
import base64
import random
import re


# ============================================================
# URL 编码
# ============================================================
def url_encode(text: str) -> str:
    """标准 URL 百分号编码（保留常用字符不编码以减小体积）"""
    return urllib.parse.quote(text, safe='')

def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)


# ============================================================
# 双重 URL 编码
# ============================================================
def double_url_encode(text: str) -> str:
    """两轮 URL 编码：先编码一次，再对 % 符号编码"""
    return urllib.parse.quote(urllib.parse.quote(text, safe=''), safe='')

def double_url_decode(text: str) -> str:
    return urllib.parse.unquote(urllib.parse.unquote(text))


# ============================================================
# Base64 命令编码 (CMDi 专用)
# ============================================================
def base64_cmd_encode(text: str) -> str:
    """将命令编码为 echo BASE64|base64 -d|sh 管道形式"""
    b64 = base64.b64encode(text.encode()).decode()
    return f";echo {b64}|base64 -d|sh"

def base64_cmd_decode(text: str) -> str:
    """从 echo...|base64 -d|sh 格式中提取原始命令"""
    m = re.search(r'echo ([A-Za-z0-9+/=]+)\|base64 -d\|sh', text)
    if m:
        try:
            return base64.b64decode(m.group(1)).decode()
        except Exception:
            pass
    return text


# ============================================================
# 十六进制编码 (MySQL 兼容)
# ============================================================
def hex_encode(text: str) -> str:
    """将字符串转换为 MySQL 0xNNNNNN 十六进制形式"""
    return '0x' + text.encode().hex()

def hex_decode(text: str) -> str:
    """从 0xNNNN 或纯十六进制字符串解码"""
    h = text
    if h.startswith('0x') or h.startswith('0X'):
        h = h[2:]
    try:
        return bytes.fromhex(h).decode(errors='replace')
    except ValueError:
        return text


# ============================================================
# Unicode 转义
# ============================================================
def unicode_escape_encode(text: str) -> str:
    """将非ASCII字符转换为 \\uXXXX Unicode转义"""
    result = []
    for ch in text:
        if ord(ch) > 127:
            result.append(f'\\u{ord(ch):04x}')
        else:
            result.append(ch)
    return ''.join(result)

def unicode_escape_decode(text: str) -> str:
    """解码 \\uXXXX Unicode转义"""
    def replace_unicode(m):
        return chr(int(m.group(1), 16))
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, text)


# ============================================================
# HTML 实体编码
# ============================================================
def html_entity_encode(text: str) -> str:
    """将字符编码为 &#xNN; HTML十六进制实体"""
    result = []
    for ch in text:
        if ch.isalnum() and ch.isascii():
            result.append(ch)
        else:
            result.append(f'&#x{ord(ch):02x};')
    return ''.join(result)

def html_entity_decode(text: str) -> str:
    """解码 &#xNN; HTML实体"""
    import html
    return html.unescape(text)


# ============================================================
# 八进制编码 (Shell 兼容)
# ============================================================
def octal_encode(text: str) -> str:
    """将非字母字符转换为 \\ooo 八进制形式 (shell可解析)"""
    result = []
    for ch in text:
        if ch.isalpha() or ch == '/':
            result.append(ch)
        else:
            result.append(f'\\{oct(ord(ch))[2:].zfill(3)}')
    return ''.join(result)

def octal_decode(text: str) -> str:
    """解码 \\ooo 八进制转义"""
    def replace_octal(m):
        return chr(int(m.group(1), 8))
    return re.sub(r'\\([0-7]{3})', replace_octal, text)


# ============================================================
# JavaScript 转义
# ============================================================
def js_escape_encode(text: str) -> str:
    """将非打印字符转换为 \\xNN JavaScript十六进制转义"""
    result = []
    for ch in text:
        if ch.isalnum() and ch.isascii():
            result.append(ch)
        else:
            result.append(f'\\x{ord(ch):02x}')
    return ''.join(result)

def js_escape_decode(text: str) -> str:
    """解码 \\xNN JavaScript转义"""
    def replace_js(m):
        return chr(int(m.group(1), 16))
    return re.sub(r'\\x([0-9a-fA-F]{2})', replace_js, text)


# ============================================================
# 空白字符随机替换 (SQLi 专用)
# ============================================================
def whitespace_random_encode(text: str) -> str:
    """将空格随机替换为制表符/换行/注释等SQL空白变体"""
    whitespace_variants = [
        '\t',           # 制表符
        '\n',           # 换行
        '\r\n',         # 回车换行
        '/**/',         # 空注释
        '/**_**/',      # 注释变体
        '  ',           # 双空格
    ]

    result = []
    for ch in text:
        if ch == ' ' and random.random() < 0.6:
            result.append(random.choice(whitespace_variants))
        else:
            result.append(ch)
    return ''.join(result)

def whitespace_random_decode(text: str) -> str:
    """将SQL空白变体还原为空格"""
    # 移除非功能性空白变体，保留空格
    cleaned = re.sub(r'/\*\*_?\*?\*/', ' ', text)
    cleaned = re.sub(r'[\t\n\r]+', ' ', cleaned)
    cleaned = re.sub(r' +', ' ', cleaned)
    return cleaned


# ============================================================
# 大小写随机翻转
# ============================================================
def case_random_encode(text: str) -> str:
    """随机翻转SQL关键字的字母大小写"""
    sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
                    'FLAGS', 'FLAG', 'DESCRIPTION', 'CHALLENGE',
                    'CAT', 'EXTRACTVALUE', 'CONCAT', 'ORDER', 'BY']

    result = text
    for kw in sql_keywords:
        # 随机选择大小写模式
        mode = random.choice(['upper', 'lower', 'mixed'])
        if mode == 'upper':
            replacement = kw.upper()
        elif mode == 'lower':
            replacement = kw.lower()
        else:
            # 随机混合: SeLeCt
            replacement = ''.join(
                ch.upper() if random.random() > 0.5 else ch.lower()
                for ch in kw
            )
        # 不区分大小写替换
        result = re.sub(kw, replacement, result, flags=re.IGNORECASE)
    return result

def case_random_decode(text: str) -> str:
    """大小写还原（实际上不需要，SQL不区分大小写）"""
    return text


# ============================================================
# SQL 关键字内联注释注入
# ============================================================
def comment_inline_encode(text: str) -> str:
    """在SQL关键字内部插入内联注释破坏连续匹配"""
    sql_keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'FLAGS',
                    'EXTRACTVALUE', 'CONCAT', 'ORDER']

    result = text
    for kw in sql_keywords:
        if len(kw) >= 4 and kw in result.upper():
            # 在关键字中间插入 /**/
            mid = len(kw) // 2
            injected = kw[:mid] + '/**/' + kw[mid:]
            # 不区分大小写替换第一个匹配
            pattern = re.compile(kw, re.IGNORECASE)
            result = pattern.sub(injected, result, count=1)
    return result

def comment_inline_decode(text: str) -> str:
    """移除内联注释"""
    return re.sub(r'/\*\*/', '', text)


# ============================================================
# 编码函数注册表
# ============================================================
ENCODE_FUNCTIONS = {
    'url_encode': url_encode,
    'double_url_encode': double_url_encode,
    'base64_cmd_encode': base64_cmd_encode,
    'hex_encode': hex_encode,
    'unicode_escape_encode': unicode_escape_encode,
    'html_entity_encode': html_entity_encode,
    'octal_encode': octal_encode,
    'js_escape_encode': js_escape_encode,
    'whitespace_random_encode': whitespace_random_encode,
    'case_random_encode': case_random_encode,
    'comment_inline_encode': comment_inline_encode,
}

DECODE_FUNCTIONS = {
    'url_encode': url_decode,
    'double_url_encode': double_url_decode,
    'base64_cmd_encode': base64_cmd_decode,
    'hex_encode': hex_decode,
    'unicode_escape_encode': unicode_escape_decode,
    'html_entity_encode': html_entity_decode,
    'octal_encode': octal_decode,
    'js_escape_encode': js_escape_decode,
    'whitespace_random_encode': whitespace_random_decode,
    'case_random_encode': case_random_decode,
    'comment_inline_encode': comment_inline_decode,
}


def apply_encoding_chain(payload: str, encode_functions: list[str]) -> str:
    """按顺序应用编码链"""
    result = payload
    for func_name in encode_functions:
        fn = ENCODE_FUNCTIONS.get(func_name)
        if fn:
            result = fn(result)
    return result


def verify_encoding_chain(original: str, encoded: str, encode_functions: list[str]) -> bool:
    """自校验：编码后再解码，应该还原为原始内容"""
    result = encoded
    for func_name in reversed(encode_functions):
        decode_fn = DECODE_FUNCTIONS.get(func_name)
        if decode_fn:
            result = decode_fn(result)
    return result.strip() == original.strip()
