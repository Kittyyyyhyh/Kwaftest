<?php
/**
 * SQL注入 L2 - 字符型引号闭合
 * 注入上下文: WHERE name='$id' (字符型，需闭合单引号)
 * WAF难点: 单引号 + UNION 组合，WAF 对引号闭合+注入的组合更敏感
 * 成功标志: 读取 flags 表中的 flag{sqli_l2_qu0t3_br34k}
 */

require_once '../config.php';
$conn = getDBConnection();

$id = $_GET['id'] ?? 'Laptop Pro 15';

// ⚠️ 纯漏洞代码，不做任何过滤
$sql = "SELECT id, name, category, price FROM sqli_l2_products WHERE name='$id'";
$result = mysqli_query($conn, $sql);

$attackRows = [];
if ($result) { while ($row = mysqli_fetch_assoc($result)) { $attackRows[] = $row; } mysqli_data_seek($result, 0); }

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>SQLi L2 - 字符型</title>
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
    <h2>🔫 SQL注入 L2 — 字符型引号闭合</h2>
    <div class="info">
        <strong>说明:</strong> 根据产品名查询。参数 <code>id</code> 为字符串，用单引号包裹。<br>
        <strong>目标:</strong> 读取 <code>flags</code> 表中的 flag<br>
        <strong>SQL:</strong> <span class="sql">SELECT id, name, category, price FROM sqli_l2_products WHERE name='<?php echo htmlspecialchars($id); ?>'</span>
    </div>

    <form method="GET">
        <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>" placeholder="产品名 (如: Laptop Pro 15)">
        <input type="submit" value="查询">
    </form>

    <?php include '../success-banner.php'; ?>
    <?php if ($result): ?>
    <table>
        <tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th></tr>
        <?php while ($row = mysqli_fetch_assoc($result)): ?>
        <tr>
            <td><?php echo htmlspecialchars($row['id']); ?></td>
            <td><?php echo htmlspecialchars($row['name']); ?></td>
            <td><?php echo htmlspecialchars($row['category']); ?></td>
            <td>$<?php echo htmlspecialchars($row['price']); ?></td>
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
