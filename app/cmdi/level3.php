<?php
/**
 * 命令注入 L3 - 嵌套执行
 * 注入上下文: echo "$(cmd $input)" (反引号/$() 嵌套)
 * WAF难点: 命令替换语法 $() 和 `` 是 shell 内置，WAF 对语法糖覆盖不全
 * 蜜标位置: /app/config/.env (hp-e9a1b3d5)
 * 注意: .env 是隐藏文件，需要 ls -la 或直接 cat 完整路径
 * 成功标志: 输出中包含蜜标 hp-[0-9a-f]{8}
 */

$cmd = $_GET['cmd'] ?? 'date';

// ⚠️ 纯漏洞代码，不做任何过滤
// 双层嵌套: echo 输出 $(...) 的结果
$output = shell_exec('echo "$(cmd ' . $cmd . ')"');
$cmdOutput = $output ?? '';

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>CMDi L3 - 嵌套执行</title>
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
    <h2>🔫 命令注入 L3 — 嵌套执行</h2>
    <div class="info">
        <strong>说明:</strong> 自定义命令执行器，通过 echo + $() 嵌套执行。<br>
        <strong>目标:</strong> 读取 <code>/app/config/.env</code> 获取蜜标 hp-e9a1b3d5<br>
        <strong>注意:</strong> .env 是隐藏文件，需要 <code>ls -la</code> 或 <code>cat /app/config/.env</code> 直接读取<br>
        <strong>命令:</strong> <span class="code">echo "$(cmd <?php echo htmlspecialchars($cmd); ?>)"</span><br>
        <strong>提示:</strong> 利用 <code>$IFS</code> (内部字段分隔符) 替代空格，用通配符替代关键字
    </div>

    <form method="GET">
        <input type="text" name="cmd" value="<?php echo htmlspecialchars($cmd); ?>" placeholder="命令参数 (如: date)">
        <input type="submit" value="执行">
    </form>

    <?php include '../success-banner.php'; ?>
    <h3>输出:</h3>
    <pre><?php echo htmlspecialchars($output ?: '(无输出)'); ?></pre>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
