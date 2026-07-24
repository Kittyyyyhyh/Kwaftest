<?php
/**
 * WAF 403 错误页面 — 从共享 audit.log 读取拦截详情
 * 首次加载评分可能来自上一条记录，1秒后自动刷新获取当前请求数据
 */
$auditLog = '/var/log/waf/audit.log';
$blockInfo = null;
$rules = [];
$scores = ['SQLI' => 0, 'XSS' => 0, 'RCE' => 0, 'LFI' => 0, 'RFI' => 0];
$totalScore = 0;
$reqLine = '';

if (file_exists($auditLog) && is_readable($auditLog)) {
    // 只读最后500行，避免大文件撑爆内存
    $fp = fopen($auditLog, 'r');
    if ($fp) {
        fseek($fp, -min(filesize($auditLog), 500000), SEEK_END); // 最后500KB
        fgets($fp); // 跳过可能不完整的第一行
        $tail = stream_get_contents($fp);
        fclose($fp);
        $lines = array_filter(explode("\n", $tail));
        $lines = array_reverse($lines); // 从后往前读
        foreach ($lines as $line) {
            $entry = json_decode($line, true);
            if (!$entry) continue;
            if (($entry['response']['status'] ?? 0) == 403
                && strpos($entry['request']['request_line'] ?? '', '/error/') === false) {
                $blockInfo = $entry;
                break;
            }
        }
    }
    if ($blockInfo) {
        $reqLine = $blockInfo['request']['request_line'] ?? '';
        $msgs = $blockInfo['audit_data']['messages'] ?? [];
        foreach ($msgs as $msgStr) {
            preg_match('/\[id "([^"]+)"\]/', $msgStr, $idM);
            $id = $idM[1] ?? '';
            if (!$id || $id == '949110' || $id == '980170') continue;
            preg_match('/\[msg "([^"]*)"\]/', $msgStr, $msgM);
            preg_match('/\[data "([^"]*)"\]/', $msgStr, $dataM);
            preg_match('/\[tag "paranoia-level\/(\d+)"\]/', $msgStr, $plM);
            $rules[] = [
                'id' => $id, 'msg' => $msgM[1] ?? '',
                'data' => $dataM[1] ?? '', 'pl' => $plM[1] ?? '',
            ];
        }
        $lastMsg = end($msgs);
        if ($lastMsg && is_string($lastMsg)) {
            preg_match_all('/(SQLI|XSS|RFI|LFI|RCE)=(\d+)/', $lastMsg, $m);
            foreach ($m[1] as $idx => $cat) $scores[$cat] = (int)$m[2][$idx];
            // 总评分 = 分类评分之和（比 CRS 的 COMBINED_SCORE 更直观）
            $totalScore = array_sum($scores);
        }
    }
}
$hasRules = count($rules) > 0;
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>403 — WAF 拦截</title>
    <meta http-equiv="refresh" content="1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', 'Microsoft YaHei', monospace;
            background: #0a0a1a; color: #e0e0e0; min-height: 100vh; padding: 30px 0; }
        .container { max-width: 850px; margin: 0 auto; padding: 0 20px; }
        .header-box { background: #16213e; border: 2px solid #e94560;
            border-radius: 12px; padding: 35px; text-align: center;
            margin-bottom: 25px; box-shadow: 0 0 60px rgba(233,69,96,0.25); }
        .icon { font-size: 56px; }
        h1 { color: #e94560; font-size: 2em; margin: 15px 0 5px; }
        .subtitle { color: #ff6b81; font-size: 1.05em; }
        .badge-row { margin: 15px 0; }
        .badge { display: inline-block; padding: 4px 14px; border-radius: 14px;
            font-size: 0.78em; font-weight: bold; margin: 3px; }
        .badge.engine { background: #e94560; color: #fff; }
        .badge.pl4 { background: #ff5722; color: #fff; }
        .badge.live { background: #53d769; color: #000; }
        .section { margin-bottom: 25px; }
        .section h2 { font-size: 1.2em; color: #ffd700; margin-bottom: 12px;
            padding-bottom: 6px; border-bottom: 1px solid #333; }
        .score-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }
        .score-card { background: #16213e; border-radius: 8px; padding: 14px;
            text-align: center; border: 1px solid #1a1a3e; }
        .score-card.triggered { border-color: #e94560; }
        .score-card .cat { color: #888; font-size: 0.8em; text-transform: uppercase; }
        .score-card .val { font-size: 1.8em; font-weight: bold; margin-top: 5px; }
        .score-card .val.hit { color: #e94560; }
        .score-card .val.safe { color: #53d769; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85em;
            background: #16213e; border-radius: 8px; overflow: hidden; }
        th { background: #0f3460; color: #ffd700; padding: 10px 12px; text-align: left; }
        td { padding: 8px 12px; border-top: 1px solid #1a1a3e; }
        td.rule-id { color: #e94560; font-weight: bold; width: 70px; }
        td.rule-pl { color: #ff5722; text-align: center; width: 45px; }
        td.rule-msg { color: #ccc; }
        td.rule-data { color: #53d769; font-size: 0.82em; max-width: 350px; word-break: break-all; }
        .req-box { background: #0f3460; border-radius: 6px; padding: 15px;
            font-family: monospace; font-size: 0.82em; color: #53d769; word-break: break-all; line-height: 1.6; }
        .total-score { text-align: center; margin-top: 12px; }
        .total-score .ts { font-size: 1.4em; font-weight: bold; }
        .loading { text-align: center; padding: 20px; color: #888; }
        .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #333;
            border-top-color: #ffd700; border-radius: 50%; animation: spin 0.7s linear infinite;
            margin-right: 8px; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .btn-row { text-align: center; margin-top: 30px; padding-bottom: 40px; }
        .btn { display: inline-block; background: #e94560; color: #fff; padding: 10px 28px;
            border-radius: 6px; text-decoration: none; font-weight: bold; }
        .btn:hover { background: #ff6b81; }
        .btn.alt { background: #0f3460; margin-left: 10px; }
        .btn.alt:hover { background: #1a4a80; }
    </style>
</head>
<body>
<div class="container">
<div class="header-box">
    <div class="icon">🛡️</div>
    <h1>403 · WAF 拦截</h1>
    <p class="subtitle">ModSecurity CRS 检测到攻击特征，已拦截此请求</p>
    <div class="badge-row">
        <span class="badge engine">OWASP CRS v4.25</span>
        <span class="badge pl4">Paranoia Level 4</span>
        <span class="badge pl">阈值 ≥ 5 分</span>
        <?php if ($hasRules): ?>
        <span class="badge live">● 规则已加载</span>
        <?php endif; ?>
    </div>
</div>

<div class="section">
    <h2>📊 异常评分</h2>
    <div class="score-grid">
        <?php foreach ($scores as $cat => $score): ?>
        <div class="score-card <?= $score > 0 ? 'triggered' : '' ?>">
            <div class="cat"><?= $cat ?></div>
            <div class="val <?= $score > 0 ? 'hit' : 'safe' ?>"><?= $score ?></div>
        </div>
        <?php endforeach; ?>
    </div>
    <div class="total-score">
        <span style="color:#888;">总评分: </span>
        <span class="ts" style="color:<?= $totalScore >= 5 ? '#e94560' : '#53d769' ?>;"><?= $totalScore ?></span>
        <span style="color:#888;margin-left:10px;">≥ 阈值 5 → 拦截</span>
    </div>
</div>

<div class="section">
    <h2>🔍 触发规则 (<?= count($rules) ?> 条)</h2>
    <?php if ($hasRules): ?>
    <table>
        <thead><tr><th>ID</th><th>PL</th><th>描述</th><th>匹配数据</th></tr></thead>
        <tbody>
            <?php foreach ($rules as $r): ?>
            <tr>
                <td class="rule-id"><?= $r['id'] ?></td>
                <td class="rule-pl"><?= $r['pl'] ? "PL{$r['pl']}" : '-' ?></td>
                <td class="rule-msg"><?= htmlspecialchars($r['msg']) ?></td>
                <td class="rule-data" title="<?= htmlspecialchars($r['data']) ?>"><?= htmlspecialchars($r['data']) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php else: ?>
    <div class="loading">
        <span class="spinner"></span>页面每秒自动刷新，等待审计日志写入...
    </div>
    <?php endif; ?>
</div>

<?php if ($reqLine): ?>
<div class="section">
    <h2>📝 被拦截请求</h2>
    <div class="req-box"><?= htmlspecialchars($reqLine) ?></div>
</div>
<?php endif; ?>

<div class="btn-row">
    <a href="/index.php" class="btn">← 返回靶场主页</a>
    <a href="javascript:history.back()" class="btn alt">↩ 返回上一页</a>
</div>
</div>
</body>
</html>
