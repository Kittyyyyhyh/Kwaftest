<?php
/**
 * WAF 状态栏组件 — 嵌入靶场PHP页面
 * 显示当前 WAF 防护状态，便于手测时直观看到拦截结果
 */

$wafEngine = $_SERVER['HTTP_X_WAF_ENGINE'] ?? 'OWASP-CRS-PL4';
$wafActive  = isset($_SERVER['HTTP_X_WAF_ACTIVE']);
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$method     = $_SERVER['REQUEST_METHOD'] ?? 'GET';
?>
<style>
.waf-status-bar {
    position: fixed; bottom: 0; left: 0; right: 0; z-index: 9999;
    background: #16213e; border-top: 2px solid #53d769;
    padding: 10px 20px; font-family: 'Segoe UI', monospace;
    font-size: 0.82em; color: #e0e0e0;
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 10px;
}
.waf-status-bar .status-pass {
    color: #53d769; font-weight: bold;
}
.waf-status-bar .status-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; margin-right: 6px;
    background: #53d769; animation: pulse 2s infinite;
}
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.waf-status-bar .info-item {
    display: inline-flex; align-items: center; gap: 6px;
}
.waf-status-bar .info-label { color: #888; }
.waf-status-bar .info-value { color: #ffd700; }
.waf-status-bar .pl-badge {
    display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: 0.75em; font-weight: bold;
    background: #ff5722; color: #fff;
}
.waf-status-bar .tooltip {
    cursor: help; border-bottom: 1px dashed #888;
}
</style>
<div class="waf-status-bar">
    <div>
        <span class="status-dot"></span>
        <span class="status-pass">WAF 放行</span>
        <span style="color:#888;margin:0 10px;">|</span>
        <span class="info-item">
            <span class="info-label">引擎:</span>
            <span class="info-value"><?= htmlspecialchars($wafEngine) ?></span>
        </span>
        <span class="pl-badge">PL4</span>
    </div>
    <div style="color:#666;">
        <span class="tooltip" title="WAF 允许此请求通过，未触发拦截阈值(≥5分)">✅ 此请求通过 WAF 检测</span>
        <span style="margin-left:10px;">|</span>
        <span style="margin-left:10px;">被拦截时在此处会看到红色 403 页面</span>
    </div>
</div>
