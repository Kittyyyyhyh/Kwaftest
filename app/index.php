<?php
/**
 * WAF 靶场主页 — 6关导航
 */
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>WAF 靶场 — OWASP CRS PL4</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', monospace; background: #0a0a1a; color: #e0e0e0; min-height: 100vh; }
        .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }

        header { text-align: center; padding: 40px 0; border-bottom: 2px solid #e94560; margin-bottom: 40px; }
        header h1 { font-size: 2.5em; color: #e94560; margin-bottom: 10px; }
        header p { color: #888; font-size: 1.1em; }

        .waf-badge { display: inline-block; background: #e94560; color: #fff; padding: 8px 20px; border-radius: 20px; font-weight: bold; margin-top: 15px; }
        .waf-badge small { opacity: 0.8; }

        .section { margin-bottom: 50px; }
        .section h2 { font-size: 1.6em; margin-bottom: 20px; padding-bottom: 8px; border-bottom: 1px solid #333; }
        .section h2 .emoji { margin-right: 10px; }

        .levels { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }

        .card {
            background: #16213e;
            border: 1px solid #1a1a3e;
            border-radius: 8px;
            padding: 20px;
            transition: all 0.2s;
            text-decoration: none;
            color: #e0e0e0;
            display: block;
        }
        .card:hover { border-color: #e94560; transform: translateY(-2px); box-shadow: 0 4px 20px rgba(233, 69, 96, 0.2); }
        .card .level-tag {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .card .level-tag.l1 { background: #53d769; color: #000; }
        .card .level-tag.l2 { background: #ffd700; color: #000; }
        .card .level-tag.l3 { background: #ff9800; color: #000; }
        .card .level-tag.l4 { background: #ff5722; color: #fff; }
        .card .level-tag.l5 { background: #e94560; color: #fff; }
        .card h3 { margin: 10px 0; font-size: 1.1em; }
        .card p { color: #888; font-size: 0.9em; line-height: 1.5; }
        .card .sql-preview { background: #0f3460; padding: 8px; border-radius: 3px; margin-top: 10px; font-size: 0.8em; color: #53d769; word-break: break-all; }

        .footer { text-align: center; padding: 30px; color: #555; font-size: 0.85em; border-top: 1px solid #222; margin-top: 50px; }
        .footer a { color: #e94560; text-decoration: none; }
        .footer .tools { margin-top: 15px; }
        .footer .tools a { display: inline-block; background: #16213e; padding: 8px 16px; border-radius: 5px; margin: 5px; }

        .endpoints { margin-top: 30px; background: #16213e; padding: 20px; border-radius: 8px; }
        .endpoints h3 { color: #e94560; margin-bottom: 15px; }
        .endpoints code { display: block; padding: 8px 0; color: #53d769; }
        .endpoints .method { color: #ffd700; font-weight: bold; margin-right: 10px; }
    </style>
</head>
<body>
<div class="container">

<header>
    <h1>🛡️ WAF 语义引擎测试靶场</h1>
    <p>OWASP ModSecurity CRS — Paranoia Level 4</p>
    <div class="waf-badge">🔥 WAF: CRS PL4 <small>(最高防护等级)</small></div>
    <p style="margin-top:15px; color:#666; font-size:0.85em;">
        靶场不含任何防御逻辑 — 所有拦截由 ModSecurity WAF 层完成<br>
        用于验证 WAF 语义引擎在编码绕过和语义绕过方面的能力边界<br>
        <span style="color:#ffd700;">🎯 每个关卡隐藏一个 flag{...} —— 代表真实生产环境中的敏感凭证</span>
    </p>
</header>

<!-- SQL 注入 -->
<div class="section">
    <h2><span class="emoji">💉</span> SQL 注入</h2>
    <div class="levels">
        <?php
        $sqliLevels = [
            ['L1', '数字型联合查询', 'WHERE id=$id 直接拼接', 'l1', 'sqli/level1.php?id=1'],
            ['L2', 'ORDER BY 排序型', 'ORDER BY $id 不能用UNION', 'l2', 'sqli/level2.php?id=score'],
        ];
        foreach ($sqliLevels as [$tag, $title, $desc, $cls, $link]) {
            echo "<a href='$link' class='card'>";
            echo "<span class='level-tag $cls'>$tag</span>";
            echo "<h3>$title</h3>";
            echo "<p>$desc</p>";
            echo "<div class='sql-preview'>→ $link</div>";
            echo "</a>";
        }
        ?>
    </div>
</div>

<!-- 命令注入 -->
<div class="section">
    <h2><span class="emoji">💻</span> 命令注入</h2>
    <div class="levels">
        <?php
        $cmdiLevels = [
            ['L1', '基础命令拼接', 'ping -c 1 $input', 'l1', 'cmdi/level1.php?cmd=127.0.0.1'],
            ['L2', '参数位置变化', 'nslookup $input (参数位)', 'l2', 'cmdi/level2.php?cmd=localhost'],
        ];
        foreach ($cmdiLevels as [$tag, $title, $desc, $cls, $link]) {
            echo "<a href='$link' class='card'>";
            echo "<span class='level-tag $cls'>$tag</span>";
            echo "<h3>$title</h3>";
            echo "<p>$desc</p>";
            echo "<div class='sql-preview'>→ $link</div>";
            echo "</a>";
        }
        ?>
    </div>
</div>

<!-- 文件上传 -->
<div class="section">
    <h2><span class="emoji">📁</span> 文件上传</h2>
    <div class="levels">
        <?php
        $uploadLevels = [
            ['L1', '基础上传', '保存到uploads/，保留原名', 'l1', 'upload/level1.php'],
            ['L2', '条件竞争', '先.tmp→重命名.php', 'l2', 'upload/level2.php'],
        ];
        foreach ($uploadLevels as [$tag, $title, $desc, $cls, $link]) {
            echo "<a href='$link' class='card'>";
            echo "<span class='level-tag $cls'>$tag</span>";
            echo "<h3>$title</h3>";
            echo "<p>$desc</p>";
            echo "<div class='sql-preview'>→ $link</div>";
            echo "</a>";
        }
        ?>
    </div>
</div>

<!-- XSS -->
<div class="section">
    <h2><span class="emoji">🎭</span> 跨站脚本 (XSS)</h2>
    <div class="levels">
        <?php
        $xssLevels = [
            ['L1', '反射型搜索', 'echo $_GET["q"] 无过滤', 'l1', 'xss/level1.php?q=test'],
            ['L2', '存储型留言板', '留言直接echo，无输出转义', 'l2', 'xss/level2.php'],
        ];
        foreach ($xssLevels as [$tag, $title, $desc, $cls, $link]) {
            echo "<a href='$link' class='card'>";
            echo "<span class='level-tag $cls'>$tag</span>";
            echo "<h3>$title</h3>";
            echo "<p>$desc</p>";
            echo "<div class='sql-preview'>→ $link</div>";
            echo "</a>";
        }
        ?>
    </div>
</div>

<!-- Log4j2 -->
<div class="section">
    <h2><span class="emoji">🪵</span> Log4j2 Lookup 注入</h2>
    <div class="levels">
        <?php
        $log4jLevels = [
            ['L1', 'URL 参数注入', '?name= 参数经 Log4j2 lookup 解析', 'l1', 'log4j/level1.php?name=test'],
            ['L2', 'HTTP Header 注入', 'User-Agent / X-Forwarded-For 头注入', 'l2', 'log4j/level2.php'],
        ];
        foreach ($log4jLevels as [$tag, $title, $desc, $cls, $link]) {
            echo "<a href='$link' class='card'>";
            echo "<span class='level-tag $cls'>$tag</span>";
            echo "<h3>$title</h3>";
            echo "<p>$desc</p>";
            echo "<div class='sql-preview'>→ $link</div>";
            echo "</a>";
        }
        ?>
    </div>
    <p style="color:#888;font-size:0.82em;margin-top:12px;">
        🔧 PHP 模拟 Log4j2 lookup 引擎 — 支持 <code>${env:}</code> <code>${java:}</code> <code>${jndi:}</code> <code>${lower:}</code> <code>${::-}</code> 等语法<br>
        🔑 Flag 通过 <code>${env:LOG4J_FLAG_L1}</code> 语法泄露环境变量
    </p>
</div>

<!-- API 端点 -->
<div class="endpoints">
    <h3>🔌 API 端点（AI 批量攻击用）</h3>
    <code><span class="method">POST</span> /api/attack.php — 发送攻击请求，返回结构化结果 + 自动记录</code>
    <code><span class="method">GET</span> /api/export.php?format=json — 导出所有样本数据（含统计）</code>
    <code><span class="method">GET</span> /api/export.php?format=csv — 导出 CSV 原始数据</code>
    <br>
    <h3>📊 报告生成</h3>
    <code>python scripts/generate_report.py → reports/report_YYYY-MM-DD.md</code>
</div>

<div class="footer">
    <p>WAF 靶场 v1.0 | OWASP ModSecurity CRS Paranoia Level 4 | PHP-Apache + MySQL</p>
    <div class="tools">
        <a href="/sqli/level1.php">SQLi L1</a>
        <a href="/cmdi/level1.php">CMDi L1</a>
        <a href="/upload/level1.php">Upload L1</a>
        <a href="/xss/level1.php">XSS L1</a>
        <a href="/log4j/level1.php">Log4j2</a>
        <a href="/api/export.php?format=json">📊 导出样本</a>
    </div>
    <p style="margin-top:15px; font-size:0.75em; color:#444;">
        ⚠️ 本靶场仅用于安全研究和教育目的。所有漏洞均为故意设计。禁止对外攻击。
    </p>
</div>

</div>
<?php include 'waf-status.php'; ?>
</body>
</html>
