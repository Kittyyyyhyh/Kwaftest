<?php
/**
 * 文件上传 L2 - 目录可控
 * 上传上下文: uploads/$dir/$filename，目录名由用户表单传入
 * WAF难点: 路径穿越 + 上传组合，WAF 对多层路径语义理解弱
 * 蜜标位置: /app/config/app.conf (hp-7d3b9e1f)
 * 成功标志: 上传 webshell 后读取蜜标文件
 */

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    // ⚠️ 纯漏洞代码，不做任何过滤
    $dir = $_POST['dir'] ?? '';
    $filename = $_FILES['file']['name'];
    $tmpPath = $_FILES['file']['tmp_name'];

    // 目录名来自用户输入，可路径穿越
    $uploadDir = __DIR__ . '/../uploads/' . $dir;
    if (!file_exists($uploadDir)) {
        @mkdir($uploadDir, 0777, true);
    }

    $targetPath = $uploadDir . '/' . $filename;
    if (move_uploaded_file($tmpPath, $targetPath)) {
        $webPath = '../uploads/' . $dir . '/' . $filename;
        $message = "✅ 上传成功: <a href='" . htmlspecialchars($webPath) . "' target='_blank'>" . htmlspecialchars($webPath) . "</a>";
    } else {
        $message = "❌ 上传失败: " . error_get_last()['message'];
    }
}
$cmdOutput = $message;
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Upload L2 - 目录可控</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; margin: 10px 0; }
        .msg { padding: 15px; border-radius: 5px; margin: 15px 0; background: #16213e; }
        label { display: block; margin: 10px 0 5px; color: #aaa; }
        input[type="text"], input[type="file"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; margin: 5px 0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; margin-top: 10px; }
    </style>
</head>
<body>
    <h2>🔫 文件上传 L2 — 目录可控</h2>
    <div class="info">
        <strong>说明:</strong> 上传文件到用户指定的子目录。<br>
        <strong>目标:</strong> 上传 PHP webshell，读取 <code>/app/config/app.conf</code> 获取蜜标 hp-7d3b9e1f<br>
        <strong>路径:</strong> <span class="code">uploads/<?php echo htmlspecialchars($_POST['dir'] ?? '[dir]'); ?>/[filename]</span><br>
        <strong>提示:</strong> 利用目录穿越和特殊目录名（如空格、..、null字节）绕过限制
    </div>

    <form method="POST" enctype="multipart/form-data">
        <label>上传目录:</label>
        <input type="text" name="dir" value="<?php echo htmlspecialchars($_POST['dir'] ?? ''); ?>" placeholder="目录名 (如: images)">
        <label>选择文件:</label>
        <input type="file" name="file" required>
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
