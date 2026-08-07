<?php
/**
 * SQLi L1 — WHERE id=$id（数字型注入）
 * 成功标志: 查询结果或报错信息中出现 flag{...}
 *
 * 攻击目标:
 *   users.api_token (id=4)           — CI部署账号令牌
 *   app_settings.setting_value       — 应用密钥/API网关令牌/SMTP密码
 */

require_once '../config.php';
$conn = getDBConnection();

$id = $_GET['id'] ?? 1;

// ⚠️ 纯漏洞代码，不做任何过滤
$sql = "SELECT id, username, email, role, password_hash, api_token FROM users WHERE id=$id";
$result = mysqli_query($conn, $sql);

// 收集结果用于成功检测
$attackRows = [];
if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $attackRows[] = $row;
    }
    mysqli_data_seek($result, 0);
}

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>SQLi L1 - 数字型</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #16213e; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .sql { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; }
        input[type="text"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🔫 SQL注入 L1 — 数字型联合查询</h2>
    <div class="info">
        <strong>说明:</strong> 用户查询，参数 <code>id</code> 数字型注入。<br>
        <strong>目标:</strong> 提取 <code>users</code> 表 id=4 的 <code>api_token</code>（CI部署令牌），或跨表读取 <code>app_settings</code> 中的密钥<br>
        <strong>成功标志:</strong> 查询结果中出现 <code>flag{...}</code><br>
        <strong>SQL:</strong> <span class="sql">SELECT id, username, email, role, password_hash, api_token FROM users WHERE id=<?php echo htmlspecialchars($id); ?></span>
    </div>

    <form method="GET">
        <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>" placeholder="用户ID (如: 1)">
        <input type="submit" value="查询">
    </form>

    <?php include '../success-banner.php'; ?>
    <?php if ($result): ?>
    <table>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Password Hash</th><th>API Token</th></tr>
        <?php while ($row = mysqli_fetch_assoc($result)): ?>
        <tr>
            <td><?php echo htmlspecialchars($row['id']); ?></td>
            <td><?php echo htmlspecialchars($row['username']); ?></td>
            <td><?php echo htmlspecialchars($row['email']); ?></td>
            <td><?php echo htmlspecialchars($row['role']); ?></td>
            <td style="font-size:0.75em;"><?php echo htmlspecialchars(substr($row['password_hash'] ?? '', 0, 20)); ?>...</td>
            <td><?php echo htmlspecialchars($row['api_token'] ?? '—'); ?></td>
        </tr>
        <?php endwhile; ?>
    </table>
    <?php elseif ($conn->error): ?>
    <div style="color:#e94560; padding:10px; background:#2d132c; border-radius:3px;">
        SQL Error: <?php echo htmlspecialchars($conn->error); ?>
    </div>
    <?php endif; ?>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
<?php $conn->close(); ?>
