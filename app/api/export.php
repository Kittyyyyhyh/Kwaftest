<?php
/**
 * 样本导出 API
 * GET /api/export.php?format=csv|json
 *
 * 从 samples.csv 读取所有攻击记录，按格式导出
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$format = $_GET['format'] ?? 'json';
$csvFile = '/var/log/waf/samples.csv';

if (!file_exists($csvFile)) {
    echo json_encode(['error' => 'No samples found. Run some attacks first.']);
    exit;
}

$rows = array_map('str_getcsv', file($csvFile));
if (count($rows) < 2) {
    echo json_encode(['error' => 'No sample data yet.']);
    exit;
}

$header = array_shift($rows);
$samples = [];
foreach ($rows as $row) {
    if (count($row) >= 8) {
        $samples[] = array_combine($header, $row);
    }
}

if ($format === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="waf_samples_export.csv"');
    readfile($csvFile);
    exit;
}

// JSON 格式：包含统计信息
$stats = [
    'total' => count($samples),
    'by_scenario' => [],
    'by_result' => [],
    'bypass_rate' => 0,
];

foreach ($samples as $s) {
    $scenario = $s['scenario'];
    $result = $s['result'];

    if (!isset($stats['by_scenario'][$scenario])) {
        $stats['by_scenario'][$scenario] = ['total' => 0, 'blocked' => 0, 'passed' => 0, 'passed_flag' => 0];
    }
    if (!isset($stats['by_result'][$result])) {
        $stats['by_result'][$result] = 0;
    }

    $stats['by_scenario'][$scenario]['total']++;
    $stats['by_result'][$result]++;
    if ($result === 'blocked') $stats['by_scenario'][$scenario]['blocked']++;
    if ($result === 'passed_flag' || $result === 'passed_noflag') $stats['by_scenario'][$scenario]['passed']++;
    if ($result === 'passed_flag') $stats['by_scenario'][$scenario]['passed_flag']++;
}

$passed = ($stats['by_result']['passed_flag'] ?? 0) + ($stats['by_result']['passed_noflag'] ?? 0);
$wafOn = array_filter($samples, fn($s) => ($s['waf'] ?? 'on') === 'on');
$wafOnPassed = array_filter($wafOn, fn($s) => ($s['result'] === 'passed_flag' || $s['result'] === 'passed_noflag'));
$stats['bypass_rate'] = count($wafOn) > 0 ? round(count($wafOnPassed) / count($wafOn) * 100, 1) : 0;

echo json_encode([
    'stats' => $stats,
    'samples' => $samples,
    'exported_at' => date('Y-m-d\TH:i:s\Z')
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
