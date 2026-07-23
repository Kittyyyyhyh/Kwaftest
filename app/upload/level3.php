<?php
/**
 * 文件上传 L3 - Content-Type 可控
 * 上传上下文: 根据 Content-Type 决定存储目录
 * WAF难点: 伪造 MIME + PHP 内容，WAF 需同时校验声明和实际
 * 成功标志: 上传 PHP webshell 到 images 目录并执行，读取 /flag.txt 第三行
 */

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    // ⚠️ 纯漏洞代码，不做任何过滤
    $filename = $_FILES['file']['name'];
    $tmpPath = $_FILES['file']['tmp_name'];
    $contentType = $_FILES['file']['type']; // 客户端可控！

    // 根据 Content-Type 分目录存储（虚假的安全感）
    if (strpos($contentType, 'image/') === 0) {
        $subdir = 'images';
    } elseif (strpos($contentType, 'text/') === 0) {
        $subdir = 'documents';
    } else {
        $subdir = 'others';
    }

    $uploadDir = __DIR__ . '/../uploads/' . $subdir;
    if (!file_exists($uploadDir)) {
        @mkdir($uploadDir, 0777, true);
    }

    $targetPath = $uploadDir . '/' . $filename;
    if (move_uploaded_file($tmpPath, $targetPath)) {
        $webPath = '../uploads/' . $subdir . '/' . $filename;
        $message = "✅ 上传成功 (类型: $contentType → $subdir/)<br>";
        $message .= "📁 <a href='" . htmlspecialchars($webPath) . "' target='_blank'>" . htmlspecialchars($webPath) . "</a>";
    } else {
        $message = "❌ 上传失败";
    }
}
$cmdOutput = $message;
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Upload L3 - Content-Type</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; margin: 10px 0; }
        .msg { padding: 15px; border-radius: 5px; margin: 15px 0; background: #16213e; }
        input[type="file"] { margin: 10px 0; padding: 10px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🔫 文件上传 L3 — Content-Type 可控</h2>
    <div class="info">
        <strong>说明:</strong> 根据上传文件的 Content-Type 分目录存储。但 Content-Type 来自客户端，完全可控。<br>
        <strong>目标:</strong> 上传 PHP webshell，读取 <code>/flag.txt</code> 的第三行 flag<br>
        <strong>提示:</strong> 用 Burp Suite 或 curl 修改 Content-Type 为 image/png，内容为 PHP 代码<br>
        <code>curl -F "file=@shell.php;type=image/png" http://localhost:8000/upload/level3.php</code>
    </div>

    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br>
        <input type="submit" value="上传">
    </form>

    <?php include '../success-banner.php'; ?>
    <?php if ($message): ?>
    <div class="msg"><?php echo $message; ?></div>
    <?php endif; ?>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
