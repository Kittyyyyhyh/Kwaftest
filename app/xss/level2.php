<?php
/**
 * XSS L2 — 存储型留言板
 * 成功标志: 提交的 payload 在页面 HTML 中不转义出现
 *
 * 攻击目标: comments 表 System 公告中的 API 迁移令牌 flag{api_migration_7c3f}
 * 入库时 WAF 检测 POST body，出库渲染时 WAF 不在数据路径上
 */

require_once '../config.php';
$conn = getDBConnection();

$message = '';
$cmdOutput = '';

// 处理留言提交
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['msg'])) {
    $username = $_POST['username'];
    $msg = $_POST['msg'];

    // ⚠️ 纯漏洞代码: 直接拼接 SQL，XSS payload 原样入库
    $sql = "INSERT INTO comments (author, content) VALUES ('$username', '$msg')";
    $result = mysqli_query($conn, $sql);
    if ($result) {
        $message = "✅ 留言发布成功!";
    } else {
        $message = "❌ 发布失败: " . $conn->error;
    }
    $cmdOutput = $message;
}

// 读取所有留言（包括 XSS payload）
$sql = "SELECT author, content, created_at FROM comments ORDER BY created_at DESC";
$messages = mysqli_query($conn, $sql);
// success-banner 仅在攻击者通过 POST 提交了 XSS payload 时才触发检测
$attackRows = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $messages) {
    while ($row = mysqli_fetch_assoc($messages)) {
        $attackRows[] = $row;
    }
    mysqli_data_seek($messages, 0);
}
// 把最新提交的内容也加入 cmdOutput 检测
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cmdOutput = ($_POST['msg'] ?? '') . ' ' . ($_POST['username'] ?? '');
}
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>XSS L2 - 存储型留言板</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .msg-box { background: #0f3460; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .msg-box .user { color: #ffd700; font-weight: bold; margin-bottom: 8px; }
        .msg-box .body { color: #e0e0e0; line-height: 1.6; }
        .msg-box .time { color: #666; font-size: 0.8em; margin-top: 8px; }
        input[type="text"], textarea { width: 100%; padding: 10px; font-size: 14px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; margin: 5px 0; }
        textarea { height: 80px; resize: vertical; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
        .note { color: #888; font-size: 0.8em; margin: 10px 0; }
    </style>
</head>
<body>
    <h2>🔫 XSS L2 — 存储型留言板</h2>
    <div class="info">
        <strong>说明:</strong> 用户留言直接存入数据库，无任何输入过滤；展示时直接 echo（无输出转义）。<br>
        <strong>目标:</strong> 注入 XSS payload 使其在页面渲染时执行，窃取管理员会话或展示隐藏的 flag<br>
        <strong>提示:</strong> 1) 入库时的 WAF 检测是主要障碍 2) 出库时 WAF 不在数据路径上<br>
        <strong>WAF检测:</strong> POST body 中的 &lt;script&gt; 和事件处理器会被 CRS PL4 检测
    </div>

    <h3>💬 留言</h3>
    <?php if ($messages): ?>
        <?php while ($msg = mysqli_fetch_assoc($messages)): ?>
        <div class="msg-box">
            <div class="user"><?php echo htmlspecialchars($msg['author']); ?></div>
            <!-- ⚠️ 纯漏洞代码: 留言内容直接 echo，不做 htmlspecialchars -->
            <div class="body"><?php echo $msg['content']; ?></div>
            <div class="time"><?php echo htmlspecialchars($msg['created_at']); ?></div>
        </div>
        <?php endwhile; ?>
    <?php endif; ?>

    <h3>✍️ 发布留言</h3>
    <form method="POST">
        <input type="text" name="username" placeholder="昵称" required><br>
        <textarea name="msg" placeholder="留言内容..." required></textarea><br>
        <input type="submit" value="发布">
    </form>
    <?php if ($message): ?>
        <div class="note"><?php echo $message; ?></div>
    <?php endif; ?>

    <?php include '../success-banner.php'; ?>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
<?php $conn->close(); ?>
