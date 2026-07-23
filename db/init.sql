-- WAF 靶场数据库初始化
-- 每个场景有独立的 flag 表和测试数据

CREATE DATABASE IF NOT EXISTS waf_lab;
USE waf_lab;

-- ==========================================
-- SQL 注入场景：用户表 + flag 表
-- ==========================================

-- L1 数字型：用户信息表
CREATE TABLE sqli_l1_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    email VARCHAR(100),
    role VARCHAR(20)
);

INSERT INTO sqli_l1_users (username, email, role) VALUES
('admin', 'admin@waf-lab.local', 'administrator'),
('alice', 'alice@example.com', 'user'),
('bob', 'bob@example.com', 'user'),
('charlie', 'charlie@example.com', 'moderator');

-- L2 字符型：产品表
CREATE TABLE sqli_l2_products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100),
    category VARCHAR(50),
    price DECIMAL(10,2)
);

INSERT INTO sqli_l2_products (name, category, price) VALUES
('Laptop Pro 15', 'Electronics', 1299.99),
('Wireless Mouse', 'Accessories', 29.99),
('USB-C Hub', 'Accessories', 49.99),
('Monitor 27"', 'Electronics', 399.99);

-- L3 搜索型：文章表
CREATE TABLE sqli_l3_articles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(200),
    content TEXT,
    author VARCHAR(50)
);

INSERT INTO sqli_l3_articles (title, content, author) VALUES
('Getting Started with Docker', 'Docker is a platform for developing, shipping, and running applications...', 'alice'),
('Understanding SQL Injection', 'SQL injection is a code injection technique...', 'bob'),
('Web Security Best Practices', 'Security should be built into applications from the ground up...', 'admin'),
('Introduction to ModSecurity', 'ModSecurity is an open-source web application firewall...', 'charlie');

-- L4 排序型：分数表
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

-- L5 盲注：用户表（无回显）
CREATE TABLE sqli_l5_blind (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    secret VARCHAR(100)
);

INSERT INTO sqli_l5_blind (username, secret) VALUES
('admin', 'top_secret_admin_token'),
('user1', 'personal_data_001'),
('user2', 'personal_data_002');

-- ==========================================
-- FLAG 表（SQL 注入场景共享）
-- ==========================================
CREATE TABLE flags (
    id INT PRIMARY KEY AUTO_INCREMENT,
    challenge VARCHAR(50),
    flag VARCHAR(100),
    description VARCHAR(255)
);

INSERT INTO flags (challenge, flag, description) VALUES
('sqli_l1', 'flag{sqli_l1_un10n_s3l3ct}', 'SQL注入L1：数字型联合查询'),
('sqli_l2', 'flag{sqli_l2_qu0t3_br34k}', 'SQL注入L2：字符型引号闭合'),
('sqli_l3', 'flag{sqli_l3_l1k3_byp4ss}', 'SQL注入L3：LIKE搜索型注入'),
('sqli_l4', 'flag{sqli_l4_0rd3r_bl1nd}', 'SQL注入L4：ORDER BY盲注'),
('sqli_l5', 'flag{sqli_l5_pur3_bl1nd}', 'SQL注入L5：无回显布尔盲注');

-- 创建低权限查询用户（部分关卡使用）
CREATE USER IF NOT EXISTS 'sqli_reader'@'%' IDENTIFIED BY 'reader_pass';
GRANT SELECT ON waf_lab.* TO 'sqli_reader'@'%';
FLUSH PRIVILEGES;
