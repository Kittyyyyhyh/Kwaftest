-- =============================================================================
-- AppProduction 数据库 — WAF 靶场 v5
-- 所有表名、列名、数据模拟真实生产环境。flag 嵌入在真实凭证字段中。
-- Skill 生成的样本如 "UNION SELECT password_hash FROM users" 即为有意义的攻击。
-- =============================================================================

CREATE DATABASE IF NOT EXISTS waf_lab;
USE waf_lab;

-- =============================================================================
-- users — 用户表 (SQLi L1: 数字型 WHERE id=$id)
-- 攻击场景: 通过 UNION SELECT 或报错注入提取用户密码哈希和 API 令牌
-- =============================================================================
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    role ENUM('admin','developer','analyst','service') DEFAULT 'developer',
    api_token VARCHAR(64) DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) DEFAULT CHARSET=utf8mb4;

INSERT INTO users (username, email, password_hash, role, api_token) VALUES
('admin',       'admin@app-prod.internal',   '$2y$10$xK8mN3vQ7pL2jR5sW9tY1uA4bC6dE8fG0hI', 'admin',    NULL),
('alice.chen',  'alice.chen@company.com',     '$2y$10$mP3nQ7rL2sW5tY8xZ1aB4cD6eF8gH0iJ2kL', 'developer', NULL),
('bob.liu',     'bob.liu@company.com',        '$2y$10$qR2sT5uW8xY1zA3bC5dE7fG9hI1jK3lM5nO', 'analyst',   NULL),
('ci_deploy',   'ci@deploy.internal',          '$2y$10$sT5uW8xY1zA3bC5dE7fG9hI1jK3lM5nO7pQ', 'service',   'flag{ci_deploy_token_a3c5}');

-- =============================================================================
-- game_scores — 游戏排行榜 (SQLi L2: ORDER BY $column)
-- 攻击场景: ORDER BY 子句注入，无法用 UNION，需 CASE WHEN 布尔盲注
-- 从 app_settings 表逐字符推断密钥值
-- =============================================================================
CREATE TABLE game_scores (
    id INT PRIMARY KEY AUTO_INCREMENT,
    player VARCHAR(50) NOT NULL,
    game VARCHAR(50) NOT NULL,
    score INT NOT NULL,
    played_at DATETIME NOT NULL
) DEFAULT CHARSET=utf8mb4;

INSERT INTO game_scores (player, game, score, played_at) VALUES
('Player01', 'SpaceRanger',  15200, '2026-07-20 10:15:00'),
('Player02', 'DungeonCrawl', 28400, '2026-07-20 11:30:00'),
('Player03', 'SpaceRanger',  19800, '2026-07-21 14:45:00'),
('Player04', 'PixelFarm',     9600, '2026-07-21 16:00:00'),
('Player05', 'DungeonCrawl', 35100, '2026-07-22 09:20:00');

-- =============================================================================
-- app_settings — 应用配置表 (SQLi 跨表查询目标)
-- 攻击场景: 从 users 表注入后跨表读取 app_settings 中的密钥和令牌
-- =============================================================================
CREATE TABLE app_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    setting_key VARCHAR(100) NOT NULL,
    setting_value VARCHAR(255) NOT NULL,
    description VARCHAR(255) DEFAULT ''
) DEFAULT CHARSET=utf8mb4;

INSERT INTO app_settings (setting_key, setting_value, description) VALUES
('db.host',      'prod-db-01.internal',               'Database host'),
('db.port',      '3306',                               'Database port'),
('app.secret',   'flag{app_master_secret_b7d3}',       'Application master secret'),
('api.gateway',  'flag{api_gateway_token_f8a9}',       'API gateway bearer token'),
('backup.key',   'flag{backup_encryption_key_2c6e}',   'Offsite backup encryption key'),
('smtp.host',    'smtp.internal.local',                'Mail relay host'),
('smtp.password','flag{smtp_relay_password_4d1b}',     'SMTP relay authentication'),
('cache.ttl',    '3600',                               'Cache TTL seconds');

-- =============================================================================
-- comments — 用户留言表 (XSS L2: 存储型)
-- 攻击场景: 注入 XSS payload 到留言中，其他用户浏览时触发
-- 管理员消息中包含 API 迁移令牌
-- =============================================================================
CREATE TABLE comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    author VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) DEFAULT CHARSET=utf8mb4;

INSERT INTO comments (author, content, created_at) VALUES
('System', '<div class="announcement"><strong>API 网关迁移通知</strong><br>新版网关已上线 (api-v2.internal.local)。旧版 Token 将于 8月15日 失效。<br>迁移期间临时管理员令牌: <code>flag{migration_admin_token_7c3f}</code></div>', '2026-07-15 09:00:00'),
('张三', 'DungeonCrawl 的排行榜接口响应太慢了，每次加载要5秒多', '2026-07-15 10:30:00'),
('李四', '数据导出功能有问题，导出来的CSV里中文全是乱码', '2026-07-16 14:20:00');

-- =============================================================================
-- 数据库用户
-- =============================================================================
CREATE USER IF NOT EXISTS 'sqli_reader'@'%' IDENTIFIED BY 'reader_pass';
GRANT SELECT ON waf_lab.* TO 'sqli_reader'@'%';
FLUSH PRIVILEGES;
