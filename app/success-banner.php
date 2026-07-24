<?php
/**
 * 攻击成功标志组件 — 检测输出中是否包含蜜标 (honeytoken)
 *
 * 蜜标格式: hp-xxxxxxxx (8位hex)
 * 嵌入位置:
 *   - 文件: /app/config/db.php, app.conf
 *   - 文件: /app/logs/access.log
 *   - 数据库: sqli_l1_users.email, sqli_l2_products.name,
 *            sqli_l3_articles.content, app_config.config_value
 *
 * 检测模式:
 *   SQLi: 查询结果中包含 hp-[0-9a-f]{8}
 *   CMDi: 命令输出中包含 hp-[0-9a-f]{8}
 *   Upload: 上传成功 + webshell执行输出中包含蜜标
 */

$showSuccess = false;
$tokens = [];

// 蜜标正则
define('HP_PATTERN', '/hp-[0-9a-f]{8}/i');

// SQLi 模式: 检查 $attackRows 中的蜜标
if (!empty($attackRows)) {
    foreach ($attackRows as $row) {
        foreach ((array)$row as $val) {
            if (preg_match_all(HP_PATTERN, (string)$val, $m)) {
                $showSuccess = true;
                $tokens = array_merge($tokens, $m[0]);
            }
        }
    }
}

// CMDi 模式: 检查 $cmdOutput 中的蜜标
if (!empty($cmdOutput) && preg_match_all(HP_PATTERN, (string)$cmdOutput, $m)) {
    $showSuccess = true;
    $tokens = array_merge($tokens, $m[0]);
}

// Upload 模式: 检查文件上传成功
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
    <div style="font-size:1.4em;font-weight:bold;color:#53d769;margin-bottom:8px;">攻击成功! 蜜标泄露</div>
    <?php foreach ($tokens as $token): ?>
    <div style="background:#0a2a10;color:#53d769;font-family:monospace;font-size:1.05em;
        padding:8px 16px;border-radius:4px;display:inline-block;margin:4px;
        border:1px dashed #53d769;">
        ✅ <?= htmlspecialchars($token) ?>
    </div>
    <?php endforeach; ?>
    <div style="color:#888;font-size:0.78em;margin-top:8px;">
        蜜标已触发 — 此载荷绕过了 WAF 检测并获取了敏感数据
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
