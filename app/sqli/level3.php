<?php
/**
 * SQL注入 L3 - LIKE 搜索型
 * 注入上下文: WHERE title LIKE '%$id%' (LIKE 模糊搜索，百分号包裹)
 * WAF难点: LIKE 上下文 + % 通配符干扰，WAF 规则对 LIKE 注入耦合度低
 * 蜜标位置: sqli_l3_articles.content WHERE id=4 (hp-9e6b1d3f)
 * 成功标志: 输出中包含蜜标 hp-[0-9a-f]{8}
 */

require_once '../config.php';
$conn = getDBConnection();

$id = $_GET['id'] ?? 'Security';

// ⚠️ 纯漏洞代码，不做任何过滤
// 注意：mysqli_multi_query 支持堆叠查询，增加攻击面
$sql = "SELECT id, title, author FROM sqli_l3_articles WHERE title LIKE '%$id%'";
$result = mysqli_query($conn, $sql);

$attackRows = [];
if ($result) { while ($row = mysqli_fetch_assoc($result)) { $attackRows[] = $row; } mysqli_data_seek($result, 0); }

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>SQLi L3 - LIKE搜索型</title>
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
    <h2>🔫 SQL注入 L3 — LIKE 搜索型</h2>
    <div class="info">
        <strong>说明:</strong> 文章搜索功能。参数 <code>id</code> 被 LIKE 模糊匹配。此关同时支持 <code>mysqli_multi_query</code>。<br>
        <strong>目标:</strong> 通过 UNION SELECT 读取 <code>sqli_l3_articles.content WHERE id=4</code> 获取蜜标 hp-9e6b1d3f<br>
        <strong>SQL:</strong> <span class="sql">SELECT id, title, author FROM sqli_l3_articles WHERE title LIKE '%<?php echo htmlspecialchars($id); ?>%'</span>
    </div>

    <form method="GET">
        <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>" placeholder="搜索关键词 (如: Security)">
        <input type="submit" value="搜索">
    </form>

    <?php include '../success-banner.php'; ?>
    <?php if ($result): ?>
    <table>
        <tr><th>ID</th><th>Title</th><th>Author</th></tr>
        <?php while ($row = mysqli_fetch_assoc($result)): ?>
        <tr>
            <td><?php echo htmlspecialchars($row['id']); ?></td>
            <td><?php echo htmlspecialchars($row['title']); ?></td>
            <td><?php echo htmlspecialchars($row['author']); ?></td>
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
