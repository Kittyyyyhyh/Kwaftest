<?php
/**
 * 文件上传 L4 - 文件名编码截断
 * 上传上下文: 对文件名做 UTF-8 → GBK 编码转换后保存
 * WAF难点: 编码转换导致"WAF看到的字节"≠"文件系统解释的字节"
 * 蜜标位置: /app/logs/access.log (hp-c2d5f8a3)
 * 成功标志: 上传 webshell 后读取蜜标文件
 *
 * 关键: 某些多字节字符在 GBK 转换后会吃掉后面的字节
 * 例如: 0xC0 0xAE → GBK 解码 → 替换为 ?  → 截断效果
 */

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    // ⚠️ 纯漏洞代码，不做任何过滤
    $filename = $_FILES['file']['name'];
    $tmpPath = $_FILES['file']['tmp_name'];

    // 尝试 UTF-8 → GBK 编码转换（如果系统支持）
    // 这可能导致多字节字符截断问题
    if (function_exists('iconv')) {
        $converted = @iconv('UTF-8', 'GBK//IGNORE', $filename);
        if ($converted !== false) {
            $filename = $converted;
        }
    }

    $targetPath = __DIR__ . '/../uploads/' . $filename;
    if (move_uploaded_file($tmpPath, $targetPath)) {
        $message = "✅ 上传成功: <a href='../uploads/" . htmlspecialchars($filename) . "' target='_blank'>" . htmlspecialchars($filename) . "</a>";
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
    <title>Upload L4 - 编码截断</title>
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
    <h2>🔫 文件上传 L4 — 文件名编码截断</h2>
    <div class="info">
        <strong>说明:</strong> 上传文件后对文件名做 UTF-8 → GBK 编码转换。编码差异可导致后缀截断。<br>
        <strong>目标:</strong> 上传 PHP webshell，读取 <code>/app/logs/access.log</code> 获取蜜标 hp-c2d5f8a3<br>
        <strong>编码链:</strong> <span class="code">UTF-8 文件名 → iconv → GBK → 文件系统保存</span><br>
        <strong>提示:</strong> filename=<code>shell.php%c0%ae.jpg</code>，GBK 解码后 %c0%ae 可能截断 .jpg<br>
        <strong>注意:</strong> Linux 环境下 GBK 截断效果不同于 Windows
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
