<?php
/**
 * 攻击成功标志组件 — 检测输出中包含 flag 时显示醒目的成功横幅
 * 用法:
 *   SQLi 页面: $attackRows 设为查询结果数组，组件自动检测 flag 字段
 *   CMDi 页面: $cmdOutput 设为命令输出字符串，组件自动检测 flag 模式
 */

$showSuccess = false;
$flags = [];

// SQLi 模式: 检查 $attackRows 中是否包含 flag
if (!empty($attackRows)) {
    foreach ($attackRows as $row) {
        foreach ((array)$row as $val) {
            if (preg_match_all('/flag\{[^}]+}/', (string)$val, $m)) {
                $showSuccess = true;
                $flags = array_merge($flags, $m[0]);
            }
        }
    }
}

// CMDi 模式: 检查 $cmdOutput 中是否包含 flag
if (!empty($cmdOutput) && preg_match_all('/flag\{[^}]+}/', (string)$cmdOutput, $m)) {
    $showSuccess = true;
    $flags = array_merge($flags, $m[0]);
}

// Upload 模式: 检查文件是否上传成功
if (!$showSuccess && !empty($cmdOutput) && preg_match('/上传成功|文件已暂存/', (string)$cmdOutput)) {
    $showSuccess = true;
    $flags[] = '文件上传成功';
}
$flags = array_unique($flags);
?>

<?php if ($showSuccess): ?>
<div style="background:linear-gradient(135deg,#0d2818,#0f6620);border:2px solid #53d769;
    border-radius:10px;padding:18px 22px;margin:18px 0;text-align:center;
    animation:wafSuccess 0.5s ease-in-out;box-shadow:0 0 40px rgba(83,215,105,0.3);">
    <div style="font-size:2em;margin-bottom:6px;">🎉</div>
    <div style="font-size:1.4em;font-weight:bold;color:#53d769;margin-bottom:8px;">攻击成功!</div>
    <?php foreach ($flags as $flag): ?>
    <div style="background:#0a2a10;color:#53d769;font-family:monospace;font-size:1.05em;
        padding:8px 16px;border-radius:4px;display:inline-block;margin:4px;
        border:1px dashed #53d769;">
        ✅ <?= htmlspecialchars($flag) ?>
    </div>
    <?php endforeach; ?>
    <div style="color:#888;font-size:0.78em;margin-top:8px;">
        成功标志已触发 — 此载荷绕过了 WAF 检测
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
