<?php
/**
 * 文件上传 L1 - 基础上传
 * 上传上下文: 直接保存上传文件到 uploads 目录，保留原始文件名
 * WAF难点: PHP 后缀 + <?php 内容，CRS PL4 内容检测拦截
 * 蜜标位置: /app/config/db.php (hp-4f8a2c1b)
 * 成功标志: 上传 webshell 后读取蜜标文件
 */

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $filename = $_FILES['file']['name'];
    $tmpPath = $_FILES['file']['tmp_name'];

    // ⚠️ 纯漏洞代码，不做任何过滤
    $targetPath = __DIR__ . '/../uploads/' . $filename;
    if (move_uploaded_file($tmpPath, $targetPath)) {
        $message = "✅ 上传成功: <a href='../uploads/" . htmlspecialchars($filename) . "' target='_blank'>" . htmlspecialchars($filename) . "</a>";
    } else {
        $message = "❌ 上传失败";
    }
}
$cmdOutput = $message;  // 用于成功横幅检测
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Upload L1 - 基础上传</title>
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
    <h2>🔫 文件上传 L1 — 基础上传</h2>
    <div class="info">
        <strong>说明:</strong> 上传文件到 <code>uploads/</code> 目录，文件名由用户控制。<br>
        <strong>目标:</strong> 上传 PHP webshell，读取 <code>/app/config/db.php</code> 获取蜜标 hp-4f8a2c1b<br>
        <strong>提示:</strong> 直接上传 .php 文件，内容用 &lt;?php system('cat /app/config/db.php'); ?&gt;<br>
        <strong>WAF检测:</strong> CRS PL4 会检测请求体中的 PHP 代码和 .php 后缀
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
