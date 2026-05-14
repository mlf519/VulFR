-- VulFR 漏洞靶场管理平台 - 数据库初始化脚本
-- 创建时间: 2026-05-14
-- 适用版本: MySQL 8.0+

-- 创建数据库（如果不存在）
-- CREATE DATABASE IF NOT EXISTS vulfr_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE vulfr_db;

-- 创建靶场环境表
CREATE TABLE IF NOT EXISTS vuln_environment (
    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '主键ID',
    name VARCHAR(100) NOT NULL COMMENT '靶场名称',
    description VARCHAR(500) COMMENT '描述信息',
    cve_id VARCHAR(50) COMMENT 'CVE编号',
    path VARCHAR(500) COMMENT '靶场路径',
    access_urls TEXT COMMENT '访问链接（JSON格式）',
    port INT COMMENT '端口号',
    host_port INT COMMENT '宿主机端口',
    container_port INT COMMENT '容器端口',
    status VARCHAR(20) NOT NULL DEFAULT 'stopped' COMMENT '状态：stopped/starting/running',
    container_id VARCHAR(128) COMMENT '容器ID',
    docker_image VARCHAR(255) NOT NULL DEFAULT 'custom' COMMENT 'Docker镜像',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX idx_status (status),
    INDEX idx_cve_id (cve_id),
    INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='靶场环境表';

-- 插入默认靶场环境数据（仅当数据不存在时）

-- 1. Log4j CVE-2021-44228 漏洞环境
INSERT INTO vuln_environment (name, description, cve_id, path, access_urls, port, host_port, container_port, status, docker_image)
SELECT * FROM (
    SELECT 
        'Log4j CVE-2021-44228' AS name,
        'Apache Log4j 远程代码执行漏洞（CVE-2021-44228）演示环境，存在JNDI注入漏洞，可通过恶意构造的日志消息触发远程代码执行。' AS description,
        'CVE-2021-44228' AS cve_id,
        'vulnerable-apps/log4j/CVE-2021-44228' AS path,
        '[{"name":"博客首页","value":"http://localhost:28083"},{"name":"后台管理","value":"http://localhost:28083/admin"}]' AS access_urls,
        28083 AS port,
        28083 AS host_port,
        28083 AS container_port,
        'stopped' AS status,
        'custom' AS docker_image
) AS temp
WHERE NOT EXISTS (
    SELECT 1 FROM vuln_environment WHERE name = 'Log4j CVE-2021-44228'
);

-- 2. Spring Actuator heapDump 漏洞环境
INSERT INTO vuln_environment (name, description, cve_id, path, access_urls, port, host_port, container_port, status, docker_image)
SELECT * FROM (
    SELECT 
        'Spring Actuator heapDump' AS name,
        'Spring Boot Actuator heapdump 信息泄露漏洞演示环境，未授权访问/actuator/heapdump端点可获取服务器内存快照。' AS description,
        'CVE-2018-1270' AS cve_id,
        'vulnerable-apps/springActuator/heapDump' AS path,
        '[{"name":"博客首页","value":"http://localhost:28084"},{"name":"Actuator端点","value":"http://localhost:28084/actuator"}]' AS access_urls,
        28084 AS port,
        28084 AS host_port,
        28083 AS container_port,
        'stopped' AS status,
        'custom' AS docker_image
) AS temp
WHERE NOT EXISTS (
    SELECT 1 FROM vuln_environment WHERE name = 'Spring Actuator heapDump'
);

-- 创建索引优化查询
CREATE INDEX IF NOT EXISTS idx_vuln_env_port ON vuln_environment(port);
CREATE INDEX IF NOT EXISTS idx_vuln_env_host_port ON vuln_environment(host_port);
