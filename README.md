# WAF 语义引擎测试靶场

> OWASP ModSecurity CRS Paranoia Level 4 + PHP-Apache + MySQL  
> 6 关靶场 × 自定义 403 拦截回显 × AI 批量攻击 API × 自动报告生成

## 快速启动

```bash
# 1. 启动所有容器
docker compose up -d

# 2. 打开靶场
open http://localhost:8090/index.php

# 3. 验证 WAF 拦截
curl "http://localhost:8090/sqli/level1.php?id=1+UNION+SELECT+1,2,3"  # → 403
```

## 架构

```
浏览器 → WAF (ModSecurity CRS PL4 :8090) → App (PHP-Apache 内网) → DB (MySQL)
              ↑ 拦截 403 + 审计日志            ↑ 纯漏洞，零防御
```

## 靶场关卡 (6 关)

### SQL 注入
| 关卡 | 注入上下文 | 路径 |
|------|-----------|------|
| L1 | 数字型 UNION | `/sqli/level1.php?id=` |
| L2 | ORDER BY 排序型 | `/sqli/level2.php?id=` |

### 命令注入
| 关卡 | 注入上下文 | 路径 |
|------|-----------|------|
| L1 | 基础命令拼接 | `/cmdi/level1.php?cmd=` |
| L2 | 参数位注入 | `/cmdi/level2.php?cmd=` |

### 文件上传
| 关卡 | 上传上下文 | 路径 |
|------|-----------|------|
| L1 | 基础上传 | `/upload/level1.php` |
| L2 | 条件竞争 (TOCTOU) | `/upload/level2.php` |

## 手测反馈

- **被 WAF 拦截** → 🛡️ 自定义 403 页面，即时显示异常评分 + 触发规则表
- **攻击成功** → 🎉 绿色"攻击成功!"横幅 + Flag 高亮
- **正常通过** → 页面底部 WAF 状态栏

## 批量工具

```bash
# API 攻击（供 AI 批量调用）
curl -X POST http://localhost:8090/api/attack.php \
  -H "Content-Type: application/json" \
  -d '{"scenario":"sqli","level":1,"payload":"1 UNION SELECT 1,flag,3,4 FROM flags","encoding":"none","waf":"on"}'

# 导出样本
curl "http://localhost:8090/api/export.php?format=json"   # JSON + 统计
curl "http://localhost:8090/api/export.php?format=csv" -o logs/samples.csv

# 生成报告
PYTHONIOENCODING=utf-8 python scripts/generate_report.py
```

## WAF 配置

| 参数 | 值 |
|------|-----|
| 引擎 | ModSecurity 2.9 + OWASP CRS v4.25 |
| Paranoia Level | 4 (最高) |
| 异常阈值 | 入站 5 / 出站 4 |
| 审计日志 | `docker exec waf-proxy tail -f /var/log/modsecurity/audit.log` |

## 项目结构

```
├── app/                    # 靶场 PHP 应用（零防御）
│   ├── sqli/               # SQL 注入 2 关
│   ├── cmdi/               # 命令注入 2 关
│   ├── upload/             # 文件上传 2 关
│   ├── api/                # 批量攻击 API + 样本导出
│   ├── error/403.php       # 自定义 403 页面（动态规则回显）
│   ├── success-banner.php  # 攻击成功横幅组件
│   └── waf-status.php      # WAF 状态栏组件
├── waf/                    # WAF 自定义规则
│   ├── REQUEST-945-CUSTOM-HEADERS.conf  # Phase 2 评分注入
│   ├── Z-custom-rules.conf             # 审计日志 + 白名单
│   └── httpd-modsecurity.conf          # 响应头 + ErrorDocument
├── db/init.sql             # 数据库初始化
├── flags/flag.txt          # Flag 文件
├── scripts/                # 报告生成
└── docker-compose.yml      # 三容器编排
```

## 技术约束

- 仅用于安全研究和教育目的
- 本地/隔离部署，不对外暴露
- 靶场漏洞为故意设计
- 遵守负责任披露原则
