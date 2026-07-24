<?php
/**
 * AI 批量攻击 API
 * POST /api/attack.php
 *
 * 请求体 (JSON):
 * {
 *   "scenario": "sqli|cmdi|upload",
 *   "level": 1-5,
 *   "payload": "攻击载荷",
 *   "encoding": "编码方式 (none|url|unicode|base64|hex|double_url|... )",
 *   "waf": "on|off"
 * }
 *
 * 响应 (JSON):
 * {
 *   "timestamp": "...",
 *   "scenario": "sqli",
 *   "level": 1,
 *   "payload": "...",
 *   "encoding": "none",
 *   "waf_enabled": true,
 *   "waf_blocked": true|false,
 *   "waf_rule_id": "942100" | null,
 *   "http_status": 403,
 *   "flag": "flag{xxx}" | null,
 *   "response_preview": "..."
 * }
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Only POST method is supported']);
    exit;
}

// 解析请求
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || !isset($input['scenario']) || !isset($input['level']) || !isset($input['payload'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing required fields: scenario, level, payload']);
    exit;
}

$scenario = $input['scenario'];
$level = (int)$input['level'];
$payload = $input['payload'];
$encoding = $input['encoding'] ?? 'none';
$wafEnabled = ($input['waf'] ?? 'on') === 'on';

// 映射到实际的靶场 URL
$routes = [
    'sqli' => '/sqli/level{level}.php?id={payload}',
    'cmdi' => '/cmdi/level{level}.php?cmd={payload}',
    'upload' => null, // 文件上传需要特殊处理
];

if (!isset($routes[$scenario])) {
    http_response_code(400);
    echo json_encode(['error' => "Unknown scenario: $scenario"]);
    exit;
}

// 构建目标 URL
$targetPath = str_replace(['{level}', '{payload}'], [$level, urlencode($payload)], $routes[$scenario]);

// 发起内部请求到 app 容器（绕过 WAF 的话需要直接请求 app:80）
// 如果要经过 WAF，请求 waf:80（但这里从 app 容器内部发起，可能绕过了 WAF）
//
// 实际的测试流程应该是：
// 1. 攻击者 → WAF(waf:80) → App(app:80)
// 2. 如果被 WAF 拦截，会收到 403 + 响应头
// 3. 如果通过，会收到 app 的响应
//
// 此 API 从 app 容器内部发起请求到 waf 容器，模拟真实攻击路径
$wafHost = $wafEnabled ? 'waf' : 'app';
$wafPort = $wafEnabled ? 8080 : 80;
$targetUrl = "http://$wafHost:$wafPort$targetPath";

// 使用 file_get_contents 或 curl 发起请求
$context = stream_context_create([
    'http' => [
        'method' => 'GET',
        'timeout' => 10,
        'ignore_errors' => true, // 不抛异常，手动处理状态码
        'header' => "User-Agent: WAF-Lab-AI-Attacker/1.0\r\n"
    ]
]);

$response = @file_get_contents($targetUrl, false, $context);
$httpStatus = 200;

// 解析响应状态码
if (isset($http_response_header)) {
    foreach ($http_response_header as $header) {
        if (preg_match('#^HTTP/\d+\.\d+\s+(\d+)#', $header, $m)) {
            $httpStatus = (int)$m[1];
            break;
        }
    }
}

// 检查是否被 WAF 拦截
$wafBlocked = ($httpStatus === 403);
$wafRuleId = null;
$wafRuleMsg = null;
$wafScoreSqli = null;
$wafScoreXss = null;
$wafScoreRce = null;
$wafScoreLfi = null;

// 从响应头中提取 WAF 规则信息（REQUEST-945-CUSTOM-HEADERS 注入）
if (isset($http_response_header)) {
    foreach ($http_response_header as $header) {
        $hl = strtolower($header);
        if (stripos($header, 'X-WAF-Blocked:') !== false) $wafBlocked = true;
        if (stripos($header, 'X-WAF-Score-Total:') !== false) $wafScoreTotal = trim(explode(':', $header, 2)[1]);
        if (stripos($header, 'X-WAF-Score-SQLi:') !== false) $wafScoreSqli = trim(explode(':', $header, 2)[1]);
        if (stripos($header, 'X-WAF-Score-XSS:') !== false) $wafScoreXss = trim(explode(':', $header, 2)[1]);
        if (stripos($header, 'X-WAF-Score-RCE:') !== false) $wafScoreRce = trim(explode(':', $header, 2)[1]);
        if (stripos($header, 'X-WAF-Score-LFI:') !== false) $wafScoreLfi = trim(explode(':', $header, 2)[1]);
    }
}

// 如果被 WAF 拦截，尝试从审计日志 JSON 获取详细规则
if ($wafBlocked) {
    $wafRuleMsg = 'WAF Blocked (CRS PL4)';
    $auditLog = '/var/log/waf/audit.log';
    if (file_exists($auditLog) && is_readable($auditLog)) {
        $fp = fopen($auditLog, 'r');
        if ($fp) {
            fseek($fp, -min(filesize($auditLog), 500000), SEEK_END);
            fgets($fp);
            $tail = stream_get_contents($fp);
            fclose($fp);
            $lines = array_filter(explode("
", $tail));
            $lines = array_reverse($lines);
            foreach ($lines as $line) {
                $entry = json_decode($line, true);
                if ($entry && ($entry['response']['status'] ?? 0) == 403) {
                    $msgs = $entry['audit_data']['messages'] ?? [];
                    $ids = [];
                    foreach ($msgs as $msg) {
                        if (preg_match('/\[id "(\d+)"\]/', $msg, $m)) $ids[] = $m[1];
                    }
                    $wafRuleId = implode(',', array_unique($ids));
                    $wafRuleMsg = $ids ? 'Rules: ' . implode(', ', $ids) : 'WAF Blocked';
                    break;
                }
            }
        }
    }
}

// 检查是否拿到 flag
$flag = null;
if (!$wafBlocked && $response !== false) {
    if (preg_match_all('/hp-[0-9a-f]{8}/', $response, $m)) {
        $flag = end($m[0]);
    }
}

// 构建响应
$result = [
    'timestamp' => date('Y-m-d\TH:i:s\Z'),
    'scenario' => $scenario,
    'level' => $level,
    'payload' => $payload,
    'encoding' => $encoding,
    'waf_enabled' => $wafEnabled,
    'waf_blocked' => $wafBlocked,
    'waf_rule_id' => $wafRuleId,
    'waf_rule_msg' => $wafRuleMsg,
    'http_status' => $httpStatus,
    'flag' => $flag,
    'response_preview' => $response !== false ? substr(strip_tags($response), 0, 500) : null,
];

// 追加到 CSV 日志（用 fputcsv 自动处理引号转义）
$csvFile = '/var/log/waf/samples.csv';
$csvRow = [
    date('Y-m-d\TH:i:s\Z'),
    $scenario,
    "L$level",
    $wafEnabled ? 'on' : 'off',
    $encoding,
    $payload,
    $wafBlocked ? 'blocked' : ($flag ? 'passed_flag' : 'passed_noflag'),
    $wafRuleId ?? '-',
    $wafRuleMsg ?? '-',
    $flag ?? '-'
];

$csvHeader = !file_exists($csvFile) || filesize($csvFile) === 0;
$fp = fopen($csvFile, 'a');
if ($fp) {
    if ($csvHeader) {
        fputcsv($fp, ['timestamp','scenario','level','waf','encoding','payload','result','waf_rule_id','waf_rule_msg','flag']);
    }
    fputcsv($fp, $csvRow);
    fclose($fp);
}

// 返回 JSON
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
