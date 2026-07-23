<?php
/**
 * SQL注入 L5 - 无回显布尔盲注
 * 注入上下文: WHERE id=$id (数字型，无回显数据，只返回"存在/不存在")
 * WAF难点: 无UNION、无报错回显，纯盲注。WAF 检测链短，是语义引擎的先天盲区
 * 成功标志: 逐字符盲注读取 flag{sqli_l5_pur3_bl1nd}
 */

require_once '../config.php';
$conn = getDBConnection();

$id = $_GET['id'] ?? 1;

// ⚠️ 纯漏洞代码，不做任何过滤
$sql = "SELECT id FROM sqli_l5_blind WHERE id=$id";
$result = mysqli_query($conn, $sql);

$attackRows = [];
if ($result) { while ($row = mysqli_fetch_assoc($result)) { $attackRows[] = $row; } mysqli_data_seek($result, 0); }

// ⚡ 关键：不返回数据内容，只返回"用户存在"或"用户不存在"
$userExists = ($result && mysqli_num_rows($result) > 0);

?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>SQLi L5 - 布尔盲注</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .sql { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; }
        .exists { color: #53d769; font-size: 24px; font-weight: bold; }
        .not-exists { color: #e94560; font-size: 24px; font-weight: bold; }
        input[type="text"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🔫 SQL注入 L5 — 无回显布尔盲注</h2>
    <div class="info">
        <strong>说明:</strong> 用户查询，只返回"存在"或"不存在"，无任何数据回显。<br>
        <strong>目标:</strong> 通过布尔盲注逐字符读取 <code>flags</code> 表中的 flag<br>
        <strong>SQL:</strong> <span class="sql">SELECT id FROM sqli_l5_blind WHERE id=<?php echo htmlspecialchars($id); ?></span><br>
        <strong>提示:</strong> 使用 <code>AND SUBSTRING((SELECT flag FROM flags WHERE challenge='sqli_l5'),N,1)='X'</code> 逐字符判断
    </div>

    <form method="GET">
        <input type="text" name="id" value="<?php echo htmlspecialchars($id); ?>" placeholder="用户ID (如: 1)">
        <input type="submit" value="查询">
    </form>

    <?php include '../success-banner.php'; ?>
    <div style="margin: 20px 0;">
        <?php if ($userExists): ?>
        <div class="exists">✅ 用户存在</div>
        <?php else: ?>
        <div class="not-exists">❌ 用户不存在</div>
        <?php endif; ?>
    </div>

    <?php if ($conn->error): ?>
    <div style="color:#e94560; padding:10px; background:#2d132c; border-radius:3px;">
        SQL Error: <?php echo htmlspecialchars($conn->error); ?>
    </div>
    <?php endif; ?>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
<?php $conn->close(); ?>
