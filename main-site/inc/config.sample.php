<?php
/**
 * config.sample.php — 站点配置文件模板
 *
 * 使用方式：
 *   1. 复制此文件为 config.php
 *   2. 修改 MASTER_KEY 为你的 32 字节十六进制密钥
 *   3. 修改 SERVER_IP 为你的服务器公网 IP
 *
 * 安全须知：
 *   - config.php 不要提交到版本控制
 *   - MASTER_KEY 用于 AES-256-GCM 加密 page.enc
 *   - 建议使用 openssl rand -hex 32 生成密钥
 */

// AES-256 主密钥（32 字节，十六进制格式）
// 生成: php -r "echo bin2hex(random_bytes(32));"
define("MASTER_KEY", hex2bin("YOUR_32_BYTE_HEX_KEY_HERE"));

// 服务器公网 IP（用于前端引用）
define("SERVER_IP", "YOUR_SERVER_IP");
