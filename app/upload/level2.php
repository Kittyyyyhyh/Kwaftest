<?php
/**
 * 文件上传 L2 - 条件竞争 (TOCTOU)
 * 上传上下文: 先存 .tmp，1秒后 rename 为 .php
 * WAF难点: 同步检测模型无法覆盖时间窗口，检测后文件名才变为 .php
 * 蜜标位置: /app/logs/access.log (hp-c2d5f8a3)
 * 成功标志: 上传 webshell 后读取蜜标文件
 */

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    // ⚠️ 纯漏洞代码，不做任何过滤
    $filename = $_FILES['file']['name'];
    $tmpPath = $_FILES['file']['tmp_name'];

    // 第一步：以临时名保存（.tmp 后缀）
    $tmpFile = __DIR__ . '/../uploads/' . time() . '_' . rand(1000, 9999) . '.tmp';
    if (move_uploaded_file($tmpPath, $tmpFile)) {
        $message = "✅ 文件已暂存: " . basename($tmpFile) . ".tmp<br>";
        $message .= "⏳ 1秒后重命名为: " . htmlspecialchars($filename) . "<br>";

        // 第二步：延迟后重命名为用户指定的文件名（模拟异步处理）
        // 在这 1 秒的窗口期内，.tmp 文件可被 PHP 解析（如果 Apache 配置了 .tmp → PHP）
        sleep(1);

        $finalPath = __DIR__ . '/../uploads/' . $filename;
        if (rename($tmpFile, $finalPath)) {
            $message .= "✅ 最终文件: <a href='../uploads/" . htmlspecialchars($filename) . "' target='_blank'>" . htmlspecialchars($filename) . "</a>";
        } else {
            $message .= "⚠️ 重命名失败，文件仍在: " . basename($tmpFile) . ".tmp";
        }
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
    <title>Upload L2 - 条件竞争</title>
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
    <h2>🔫 文件上传 L2 — 条件竞争</h2>
    <div class="info">
        <strong>说明:</strong> 文件先保存为 <code>.tmp</code>，1秒后再重命名为用户指定的文件名。<br>
        <strong>目标:</strong> 上传 webshell 后读取 <code>/app/logs/access.log</code> 获取蜜标 hp-c2d5f8a3<br>
        <strong>流程:</strong> <span class="code">上传 → 存为 .tmp → (1秒窗口) → rename 为 .php</span><br>
        <strong>提示:</strong> 1) Apache 可能解析 .tmp 为 PHP 2) 并发上传可竞争文件名<br>
        <strong>攻击思路:</strong> 同时发起多次上传 + 多次访问请求，争夺时间窗口
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
