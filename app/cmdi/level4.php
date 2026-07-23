<?php
/**
 * 命令注入 L4 - 环境变量注入
 * 注入上下文: PATH 环境变量被污染后执行命令
 * WAF难点: 环境变量投毒是间接攻击，WAF 建模的是输入→输出，非环境侧信道
 * 成功标志: 读取 /flag.txt 第四行 flag{cmdi_l4_3nv_v4r_p01s0n}
 */

$cmd = $_GET['cmd'] ?? 'ls';

// ⚠️ 纯漏洞代码，不做任何过滤
// 允许用户设置 PATH 环境变量，污染执行环境
if (isset($_GET['path'])) {
    putenv("PATH=" . $_GET['path']);
}
putenv("CMD_ENV=" . $cmd);

$output = shell_exec($cmd . ' 2>&1');
$cmdOutput = $output ?? '';

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>CMDi L4 - 环境变量</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; }
        pre { background: #0f3460; padding: 15px; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; color: #53d769; }
        input[type="text"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; margin: 5px 0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
        label { display: block; margin: 10px 0 5px; color: #aaa; }
    </style>
</head>
<body>
    <h2>🔫 命令注入 L4 — 环境变量投毒</h2>
    <div class="info">
        <strong>说明:</strong> 执行系统命令，同时可以设置 PATH 环境变量。PATH 污染可导致命令劫持。<br>
        <strong>目标:</strong> 读取 <code>/flag.txt</code> 文件<br>
        <strong>PATH:</strong> <span class="code"><?php echo htmlspecialchars(getenv('PATH')); ?></span><br>
        <strong>提示:</strong> PATH 注入 + 命令注入组合使用。也可以直接注入 cmd 参数执行 cat 等命令
    </div>

    <form method="GET">
        <label>PATH 环境变量:</label>
        <input type="text" name="path" value="<?php echo htmlspecialchars($_GET['path'] ?? ''); ?>" placeholder="PATH (如: /tmp:/bin)">
        <label>命令:</label>
        <input type="text" name="cmd" value="<?php echo htmlspecialchars($cmd); ?>" placeholder="命令 (如: ls)">
        <input type="submit" value="执行">
    </form>

    <?php include '../success-banner.php'; ?>
    <h3>输出:</h3>
    <pre><?php echo htmlspecialchars($output ?: '(无输出)'); ?></pre>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
