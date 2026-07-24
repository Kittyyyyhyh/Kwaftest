<?php
/**
 * 命令注入 L2 - 参数位置变化
 * 注入上下文: nslookup $input 2>&1 (参数位注入，非命令位)
 * WAF难点: 注入点在工具参数位而非命令本身，WAF 需要理解 shell 语法树
 * 蜜标位置: /app/config/app.conf (hp-7d3b9e1f)
 * 成功标志: 输出中包含蜜标 hp-[0-9a-f]{8}
 */

$cmd = $_GET['cmd'] ?? 'localhost';

// ⚠️ 纯漏洞代码，不做任何过滤
$output = shell_exec("nslookup " . $cmd . " 2>&1");
$cmdOutput = $output ?? '';

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>CMDi L2 - 参数位置</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; }
        pre { background: #0f3460; padding: 15px; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; color: #53d769; }
        input[type="text"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🔫 命令注入 L2 — 参数位置变化</h2>
    <div class="info">
        <strong>说明:</strong> DNS 查询工具。参数 <code>cmd</code> 在 nslookup 的参数位置。<br>
        <strong>目标:</strong> 读取 <code>/app/config/app.conf</code> 获取蜜标 hp-7d3b9e1f<br>
        <strong>命令:</strong> <span class="code">nslookup <?php echo htmlspecialchars($cmd); ?> 2>&1</span><br>
        <strong>提示:</strong> 使用反引号 `` ` `` 或 <code>$()</code> 在参数中嵌套执行命令
    </div>

    <form method="GET">
        <input type="text" name="cmd" value="<?php echo htmlspecialchars($cmd); ?>" placeholder="域名 (如: localhost)">
        <input type="submit" value="查询DNS">
    </form>

    <?php include '../success-banner.php'; ?>
    <h3>输出:</h3>
    <pre><?php echo htmlspecialchars($output ?: '(无输出)'); ?></pre>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
