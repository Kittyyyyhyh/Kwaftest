<?php
/**
 * WAF 靶场 - 数据库配置
 * 注意：此文件不含任何过滤逻辑，仅提供数据库连接
 */

define('DB_HOST', getenv('DB_HOST') ?: 'db');
define('DB_USER', getenv('DB_USER') ?: 'labuser');
define('DB_PASS', getenv('DB_PASS') ?: 'labpass_2026');
define('DB_NAME', getenv('DB_NAME') ?: 'waf_lab');

// 低权限连接（部分关卡使用）
define('DB_USER_LOW', 'sqli_reader');
define('DB_PASS_LOW', 'reader_pass');

function getDBConnection($lowPrivilege = false) {
    $user = $lowPrivilege ? DB_USER_LOW : DB_USER;
    $pass = $lowPrivilege ? DB_PASS_LOW : DB_PASS;

    $conn = new mysqli(DB_HOST, $user, $pass, DB_NAME);
    if ($conn->connect_error) {
        die("Database connection failed: " . $conn->connect_error);
    }
    return $conn;
}
