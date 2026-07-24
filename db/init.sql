-- WAF 靶场数据库 v3 — 分布式蜜标矩阵
-- 每个攻击面一个独立token，支持溯源

CREATE DATABASE IF NOT EXISTS waf_lab;
USE waf_lab;

-- ==========================================
-- L1: 用户信息表 (UNION注入)
-- 蜜标: hp-3a5c7e9b → sqli_l1_users.email (id=4)
-- ==========================================
CREATE TABLE sqli_l1_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    email VARCHAR(100),
    role VARCHAR(20)
);
INSERT INTO sqli_l1_users (username, email, role) VALUES
('admin', 'admin@company.local', 'administrator'),
('alice', 'alice@company.local', 'user'),
('bob', 'bob@company.local', 'user'),
('sys_backup', 'hp-3a5c7e9b@internal.local', 'backup');

-- ==========================================
-- L2: 排行榜 (ORDER BY盲注)
-- 蜜标: hp-a1b3c5d7 → app_config表 (靶场配置表)
-- ==========================================
CREATE TABLE sqli_l4_scores (
    id INT PRIMARY KEY AUTO_INCREMENT,
    player VARCHAR(50),
    game VARCHAR(50),
    score INT,
    played_at DATETIME
);
INSERT INTO sqli_l4_scores (player, game, score, played_at) VALUES
('Player1', 'Tetris', 15000, '2026-07-01 10:00:00'),
('Player2', 'Pacman', 23000, '2026-07-02 14:30:00'),
('Player3', 'Tetris', 18000, '2026-07-03 09:15:00'),
('Player4', 'Space Invaders', 9500, '2026-07-04 16:45:00'),
('Player5', 'Pacman', 31000, '2026-07-05 11:20:00');

-- ==========================================
-- 蜜标配置表 (跨场景查询目标)
-- 蜜标: hp-a1b3c5d7, hp-e2f4a6b8, hp-c2d5f8a3
-- ==========================================
CREATE TABLE app_config (
    id INT PRIMARY KEY AUTO_INCREMENT,
    config_key VARCHAR(100),
    config_value VARCHAR(255),
    description VARCHAR(255)
);
INSERT INTO app_config (config_key, config_value, description) VALUES
('db.host', 'localhost', 'Database host'),
('db.port', '3306', 'Database port'),
('app.secret', 'hp-a1b3c5d7', 'Application secret key'),
('api.token', 'hp-e2f4a6b8', 'API access token'),
('backup.key', 'hp-c2d5f8a3', 'Backup encryption key'),
('mail.relay', 'smtp.internal.local', 'Mail relay host'),
('cache.ttl', '3600', 'Cache TTL in seconds');

-- 低权限用户
CREATE USER IF NOT EXISTS 'sqli_reader'@'%' IDENTIFIED BY 'reader_pass';
GRANT SELECT ON waf_lab.* TO 'sqli_reader'@'%';
FLUSH PRIVILEGES;
