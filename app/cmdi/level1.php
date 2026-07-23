<?php
/**
 * 命令注入 L1 - 基础拼接
 * 注入上下文: ping -c 1 $input (直接拼接命令)
 * WAF难点: 经典分隔符注入，; | & 等会被 CRS PL4 拦截
 * 成功标志: 读取 /flag.txt 第一行 flag{cmdi_l1_b4s1c_1nj3ct10n}
 */

$cmd = $_GET['cmd'] ?? '127.0.0.1';

// ⚠️ 纯漏洞代码，不做任何过滤
$output = shell_exec("ping -c 1 " . $cmd);

// 命令输出用于成功检测
$cmdOutput = $output ?? '';

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>CMDi L1 - 基础拼接</title>
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
    <h2>🔫 命令注入 L1 — 基础拼接</h2>
    <div class="info">
        <strong>说明:</strong> Ping 工具。参数 <code>cmd</code> 直接拼入 shell 命令。<br>
        <strong>目标:</strong> 读取 <code>/flag.txt</code> 文件<br>
        <strong>命令:</strong> <span class="code">ping -c 1 <?php echo htmlspecialchars($cmd); ?></span>
    </div>

    <form method="GET">
        <input type="text" name="cmd" value="<?php echo htmlspecialchars($cmd); ?>" placeholder="IP地址 (如: 127.0.0.1)">
        <input type="submit" value="Ping">
    </form>

    <?php include '../success-banner.php'; ?>
    <h3>输出:</h3>
    <pre><?php echo htmlspecialchars($output ?: '(无输出)'); ?></pre>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
