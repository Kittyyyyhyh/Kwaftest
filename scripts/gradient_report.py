#!/usr/bin/env python3
"""梯度矩阵报告"""
import sys,io,json,os,glob
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
results_dir = os.path.join(BASE, 'samples', 'results')
files = glob.glob(os.path.join(results_dir, '*.jsonl'))
if not files:
    print("No results found"); sys.exit(1)
latest = max(files, key=os.path.getmtime)

results = []
with open(latest, 'r', encoding='utf-8') as f:
    for line in f:
        if line.strip():
            results.append(json.loads(line.strip()))

cmdi = [r for r in results if r.get('scenario') == 'cmdi' and '_none' in r.get('sample_id','')]
seen = {}
for r in cmdi:
    seen[r['sample_id']] = r

print('=' * 120)
print('  CMDi 蜜标梯度矩阵 — 技法 x 目标敏感度 — WAF ON (direct)')
print('=' * 120)
print()
print(f'  {"语法":<6} {"P0 /etc/motd":<24} {"P0 /etc/hostname":<24} {"P1 /srv/config":<24} {"P1 /usr/local":<24} {"P2 /app/config":<22}')
print(f'  {"":<6} {"(WAF应拦=正确)":<24} {"(WAF应拦=正确)":<24} {"(WAF可放=盲区)":<24} {"(WAF可放=盲区)":<24} {"(WAF应放=无害)":<22}')
print('  ' + '-' * 115)

for sep, label in [(';cat', ';'), ('|cat', '|'), ('||cat', '||'), ('$(cat', '$()')]:
    cells = {}
    for sid, r in seen.items():
        pid = r.get('applied_payload', '')
        if not pid.startswith(sep):
            continue
        target = pid.split('cat ', 1)[1] if 'cat ' in pid else pid
        if '/etc/motd' in target: tier = 'P0-motd'
        elif '/etc/hostname' in target: tier = 'P0-host'
        elif '/srv/config' in target: tier = 'P1-srv'
        elif '/usr/local' in target: tier = 'P1-usr'
        elif '/app/config/db.php' in target or '/app/config/db.*' in target: tier = 'P2-db'
        elif '/app/config/.env' in target: tier = 'P2-env'
        else: continue

        blocked = r.get('waf_blocked', False)
        flag = r.get('flag_captured')
        if blocked:
            cells[tier] = '403 WAF拦截'
        elif flag:
            cells[tier] = f'泄露 {flag[-14:]}'
        else:
            cells[tier] = '200 无蜜标'

    row = f'  {label:<6}'
    for tier in ['P0-motd', 'P0-host', 'P1-srv', 'P1-usr', 'P2-db', 'P2-env']:
        row += f' {cells.get(tier, "—"):<24}'
    print(row)

print()
print('  P0: WAF正确拦截系统文件读取 — CRS路径规则有效')
print('  P1: ; | || 绕过WAF,蜜标泄露 — 应用路径是检测盲区')
print('  P2: ; | || 放行,蜜标泄露 — 无害路径符合预期')
print('  $(): 语法本身被拦 — 不论目标路径敏感度')
print('=' * 120)
