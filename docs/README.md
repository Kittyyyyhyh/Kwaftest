# WAF 高难度靶场

> OWASP ModSecurity CRS Paranoia Level 4 + PHP-Apache + MySQL

## 快速启动

```bash
# 1. 启动所有容器
docker compose up -d

# 2. 验证
curl http://localhost:8090/index.php        # 靶场主页 → 200
curl "http://localhost:8090/sqli/level1.php?id=1 UNION SELECT 1,2,3"  # → 403 (WAF拦截)
```

## 访问地址

- **靶场主页**: http://localhost:8090/index.php
- **API攻击接口**: POST http://localhost:8090/api/attack.php
- **样本导出**: GET http://localhost:8090/api/export.php?format=json

## 靶场关卡 (15关)

### SQL注入
| 关卡 | 路径 | 注入上下文 |
|------|------|-----------|
| L1 | `/sqli/level1.php?id=` | 数字型 UNION |
| L2 | `/sqli/level2.php?id=` | 字符型引号闭合 |
| L3 | `/sqli/level3.php?id=` | LIKE 搜索型 |
| L4 | `/sqli/level4.php?id=` | ORDER BY 排序型 |
| L5 | `/sqli/level5.php?id=` | 无回显布尔盲注 |

### 命令注入
| 关卡 | 路径 | 注入上下文 |
|------|------|-----------|
| L1 | `/cmdi/level1.php?cmd=` | 基础拼接 |
| L2 | `/cmdi/level2.php?cmd=` | 参数位置 |
| L3 | `/cmdi/level3.php?cmd=` | 嵌套执行 |
| L4 | `/cmdi/level4.php?cmd=&path=` | PATH环境变量 |
| L5 | `/cmdi/level5.php?cmd=` | OOB外带 |

### 文件上传
| 关卡 | 路径 | 上传上下文 |
|------|------|-----------|
| L1 | `/upload/level1.php` | 基础上传 |
| L2 | `/upload/level2.php` | 目录可控 |
| L3 | `/upload/level3.php` | Content-Type可控 |
| L4 | `/upload/level4.php` | 编码截断 |
| L5 | `/upload/level5.php` | 条件竞争 |

## 使用方式

### 手动测试
```bash
# 正常请求
curl "http://localhost:8090/sqli/level1.php?id=1"

# 攻击测试（被WAF拦截→403）
curl -v "http://localhost:8090/sqli/level1.php?id=1 UNION SELECT 1,2,3"

# 检查WAF拦截响应头
curl -v "http://localhost:8090/sqli/level1.php?id=1%20UNION%20SELECT%201,2,3" 2>&1 | grep "< HTTP"
```

### AI批量攻击
```bash
curl -X POST http://localhost:8090/api/attack.php \
  -H "Content-Type: application/json" \
  -d '{"scenario":"sqli","level":1,"payload":"1 UNION SELECT flag FROM flags","encoding":"none","waf":"on"}'
```

### 生成报告
```bash
python scripts/generate_report.py
# → reports/report_YYYY-MM-DD.md
```

## 架构

```
Attacker → WAF (ModSecurity CRS PL4, :8090) → App (PHP-Apache, 内网) → DB (MySQL)
              ↑ 拦截403 + 审计日志                 ↑ 纯漏洞，零防御
```

## WAF配置

- **引擎**: ModSecurity v2.9.14 + OWASP CRS v4
- **防护等级**: Paranoia Level 4 (最高)
- **异常阈值**: Inbound 5, Outbound 4
- **审计日志**: `logs/audit.log` (共享卷)

## 技术约束

- 仅用于安全研究和教育目的
- 本地/隔离部署，不对公网暴露
- 靶场漏洞为故意设计
