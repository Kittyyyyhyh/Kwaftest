<?php
/**
 * CMDi L1 — ping -c 1 $input（直接拼接）
 * 成功标志: 命令输出中出现 flag{...}
 *
 * 攻击目标（不同危害级别）:
 *   /srv/app/config/database.cnf    — 数据库密码（高危）
 *   /srv/app/config/credentials.env — Stripe+Mailgun密钥（严重）
 *   /srv/data/server_config.yml     — SSH密钥+S3凭证（严重）
 *   /var/backups/db_dump_202607.sql — 备份用户令牌（中危）
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
        <strong>说明:</strong> Ping 工具，参数 <code>cmd</code> 直接拼入 shell。<br>
        <strong>目标:</strong> 读取以下任一配置文件中的敏感凭证：<br>
        &nbsp;&nbsp;• <code>/srv/app/config/database.cnf</code> — 数据库密码<br>
        &nbsp;&nbsp;• <code>/srv/app/config/credentials.env</code> — Stripe/Mailgun 密钥<br>
        &nbsp;&nbsp;• <code>/srv/data/server_config.yml</code> — SSH 密钥 / S3 凭证<br>
        &nbsp;&nbsp;• <code>/var/backups/db_dump_202607.sql</code> — 备份中的用户令牌<br>
        <strong>成功标志:</strong> 命令输出中出现 <code>flag{...}</code><br>
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
