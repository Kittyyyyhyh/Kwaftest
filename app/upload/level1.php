<?php
/**
 * Upload L1 — 基础上传（保留原始文件名）
 * 成功标志: 访问上传的 webshell 后，输出中出现 flag{...}
 *
 * 攻击目标: 上传 webshell，执行 cat /srv/app/config/database.cnf 等
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
        <strong>说明:</strong> 上传文件到 <code>uploads/</code>，文件名由用户控制。<br>
        <strong>目标:</strong> 上传 webshell → 访问上传文件 → 执行命令读取配置文件中的凭证<br>
        <strong>成功标志:</strong> webshell 输出中出现 <code>flag{...}</code><br>
        <strong>WAF检测:</strong> CRS PL4 检测 PHP 代码内容和 .php 后缀
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
