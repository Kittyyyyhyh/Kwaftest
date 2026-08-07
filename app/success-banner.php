<?php
/**
 * 攻击成功标志组件 — 检测输出中是否包含 flag
 *
 * flag 格式: flag{描述_hex4}
 * 嵌入位置:
 *   - 文件: /etc/motd, /etc/hostname, /srv/app/settings.json 等
 *   - 数据库: sqli_l1_users.api_key, app_config.config_value
 *   - 每个 flag 代表一个真实生产凭证（API密钥、数据库密码、部署令牌等）
 *
 * 检测模式:
 *   SQLi: 查询结果中包含 flag{...}
 *   CMDi: 命令输出中包含 flag{...}
 *   Upload: 上传 webshell 后执行命令，输出中包含 flag{...}
 *   XSS: 页面内容或 DOM 中包含 flag{...}
 */

$showSuccess = false;
$tokens = [];

// flag 正则: flag{...}，内容为字母/数字/下划线/连字符
define('FLAG_PATTERN', '/flag\{[a-z0-9_-]+\}/i');

// SQLi 模式: 检查 $attackRows 中的 flag
if (!empty($attackRows)) {
    foreach ($attackRows as $row) {
        foreach ((array)$row as $val) {
            if (preg_match_all(FLAG_PATTERN, (string)$val, $m)) {
                $showSuccess = true;
                $tokens = array_merge($tokens, $m[0]);
            }
        }
    }
}

// CMDi / Upload 模式: 检查 $cmdOutput 中的 flag
if (!empty($cmdOutput) && preg_match_all(FLAG_PATTERN, (string)$cmdOutput, $m)) {
    $showSuccess = true;
    $tokens = array_merge($tokens, $m[0]);
}

// Upload 模式: 上传成功也是成果（但需配合 webshell 执行才算完整攻击）
if (!$showSuccess && !empty($cmdOutput) && preg_match('/上传成功|文件已暂存/', (string)$cmdOutput)) {
    $showSuccess = true;
    $tokens[] = '上传成功';
}
$tokens = array_unique($tokens);
?>

<?php if ($showSuccess): ?>
<div style="background:linear-gradient(135deg,#0d2818,#0f6620);border:2px solid #53d769;
    border-radius:10px;padding:18px 22px;margin:18px 0;text-align:center;
    animation:wafSuccess 0.5s ease-in-out;box-shadow:0 0 40px rgba(83,215,105,0.3);">
    <div style="font-size:2em;margin-bottom:6px;">🎉</div>
    <div style="font-size:1.4em;font-weight:bold;color:#53d769;margin-bottom:8px;">攻击成功! Flag 泄露</div>
    <?php foreach ($tokens as $token): ?>
    <div style="background:#0a2a10;color:#53d769;font-family:monospace;font-size:1.05em;
        padding:8px 16px;border-radius:4px;display:inline-block;margin:4px;
        border:1px dashed #53d769;">
        ✅ <?= htmlspecialchars($token) ?>
    </div>
    <?php endforeach; ?>
    <div style="color:#888;font-size:0.78em;margin-top:8px;">
        Flag 已触发 — 此载荷绕过了 WAF 检测并获取了敏感凭证
    </div>
</div>
<style>
@keyframes wafSuccess {
    0% { opacity:0; transform:scale(0.9) translateY(-10px); }
    60% { transform:scale(1.02); }
    100% { opacity:1; transform:scale(1) translateY(0); }
}
</style>
<?php endif; ?>
