<?php
/**
 * XSS L1 - 反射型搜索框
 * 注入上下文: echo $_GET['q'] — 无任何转义，输入直接回显到 HTML
 * WAF难点: <script> 标签和事件处理器被 CRS PL4 941 系列规则检测
 * Flag: 页面隐藏 DOM 元素中包含会话令牌，XSS 成功后可通过 JS 读取
 * 成功标志: 攻击者能通过 XSS 窃取并在页面上显示 flag
 */

$query = $_GET['q'] ?? '';
$cmdOutput = $query; // 用于 success-banner 检测
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>XSS L1 - 反射型</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; }
        .result { background: #0f3460; padding: 15px; border-radius: 3px; margin: 15px 0; min-height: 40px; }
        input[type="text"] { width: 300px; padding: 10px; font-size: 16px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 16px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🔫 XSS L1 — 反射型搜索</h2>
    <div class="info">
        <strong>说明:</strong> 搜索输入直接回显到 HTML（无过滤）。<br>
        <strong>目标:</strong> 注入脚本，读取 <code>&lt;meta name="csrf-token"&gt;</code> 中的令牌<br>
        <strong>成功标志:</strong> payload 在页面 HTML 中不转义地出现，且可读取到 <code>flag{...}</code><br>
        <strong>WAF检测:</strong> CRS PL4 检测 &lt;script&gt;、事件处理器和 javascript: 协议
    </div>

    <form method="GET">
        <input type="text" name="q" value="<?php echo htmlspecialchars($query); ?>" placeholder="搜索关键词...">
        <input type="submit" value="搜索">
    </form>

    <h3>搜索结果:</h3>
    <div class="result">
        <?php
        // ⚠️ 纯漏洞代码: 直接 echo 用户输入，不做任何过滤
        if ($query) {
            echo "搜索 \"$query\" 的结果：<br><br>";
            echo "未找到相关结果。请尝试其他关键词。";
        } else {
            echo "请输入搜索关键词。";
        }
        ?>
    </div>

    <?php include '../success-banner.php'; ?>

    <!-- XSS 攻击目标: CSRF 令牌 — 攻击者通过 XSS 读取并外传 -->
    <meta name="csrf-token" content="flag{csrf_token_5e8a}">

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
