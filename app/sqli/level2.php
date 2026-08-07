<?php
/**
 * SQLi L2 — ORDER BY $column（排序注入，不能用 UNION）
 * 成功标志: 通过 CASE WHEN 排序差异逐字符提取出 flag{...}
 *
 * 攻击目标: app_settings.setting_value（app.secret / api.gateway / smtp.password）
 */

require_once '../config.php';
$conn = getDBConnection();

$id = $_GET['id'] ?? 'score';

// ⚠️ 纯漏洞代码，不做任何过滤
$sql = "SELECT player, game, score FROM game_scores ORDER BY $id";
$result = mysqli_query($conn, $sql);

$attackRows = [];
if ($result) { while ($row = mysqli_fetch_assoc($result)) { $attackRows[] = $row; } mysqli_data_seek($result, 0); }

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>SQLi L2 - ORDER BY</title>
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
    <h2>🔫 SQL注入 L2 — ORDER BY 排序型</h2>
    <div class="info">
        <strong>说明:</strong> 游戏排行榜，按指定列排序。ORDER BY 后不能 UNION。<br>
        <strong>目标:</strong> CASE WHEN 布尔盲注从 <code>app_settings</code> 表逐字符提取密钥<br>
        <strong>成功标志:</strong> 逐字符提取出完整 <code>flag{...}</code><br>
        <strong>SQL:</strong> <span class="sql">SELECT player, game, score FROM game_scores ORDER BY <?php echo htmlspecialchars($id); ?></span>
    </div>

    <form method="GET">
        <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>" placeholder="排序列 (如: score)">
        <input type="submit" value="排序">
    </form>

    <?php include '../success-banner.php'; ?>
    <?php if ($result): ?>
    <table>
        <tr><th>Player</th><th>Game</th><th>Score</th></tr>
        <?php while ($row = mysqli_fetch_assoc($result)): ?>
        <tr>
            <td><?php echo htmlspecialchars($row['player']); ?></td>
            <td><?php echo htmlspecialchars($row['game']); ?></td>
            <td><?php echo htmlspecialchars($row['score']); ?></td>
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
