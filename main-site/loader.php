<?php
/**
 * loader.php — PoW + 短效令牌
 * 流程: challenge -> PoW -> token -> encrypted content
 *
 * 依赖:
 *   inc/config.php — 定义 MASTER_KEY, SERVER_IP 等常量
 *   inc/crypto.php  — AES-256-GCM 加解密函数
 *   inc/page.enc   — MASTER_KEY 加密后的页面内容
 */

require_once __DIR__ . "/inc/config.php";
require_once __DIR__ . "/inc/crypto.php";

header("Content-Type: application/json; charset=utf-8");
header("X-Robots-Tag: noindex");
header("X-Content-Type-Options: nosniff");

$ip = $_SERVER["REMOTE_ADDR"] ?? "0.0.0.0";
$action = $_GET["action"] ?? "";

// 清理过期文件
function cleanup_stale() {
    $dir = sys_get_temp_dir();
    foreach (glob($dir . "/skpnn_*.json") as $f) {
        if (time() - filemtime($f) > 600) @unlink($f);
    }
}
cleanup_stale();

// ========== 1. 获取挑战 ==========
if ($action === "challenge") {
    $challenge = bin2hex(random_bytes(16));
    $difficulty = 5; // 4 hex 零 = 16 bit，预计 16-50ms
    $file = sys_get_temp_dir() . "/skpnn_pow_" . md5($challenge) . ".json";
    file_put_contents($file, json_encode([
        "c" => $challenge,
        "d" => $difficulty,
        "t" => time(),
        "ip" => $ip
    ]), LOCK_EX);
    echo json_encode(["c" => $challenge, "d" => $difficulty]);
    exit;
}

// ========== 2. 验证 PoW + 签发令牌 ==========
if ($action === "fetch") {
    $challenge = $_GET["c"] ?? "";
    $nonce = $_GET["n"] ?? "";
    if (!$challenge || $nonce === "") {
        http_response_code(400);
        die(json_encode(["e" => "missing params"]));
    }

    $pow_file = sys_get_temp_dir() . "/skpnn_pow_" . md5($challenge) . ".json";
    if (!file_exists($pow_file)) {
        http_response_code(400);
        die(json_encode(["e" => "challenge invalid or expired"]));
    }
    $pow = json_decode(file_get_contents($pow_file), true);

    // IP 绑定
    if ($pow["ip"] !== $ip) {
        @unlink($pow_file);
        http_response_code(403);
        die(json_encode(["e" => "ip mismatch"]));
    }

    // 过期检查
    if (time() - $pow["t"] > 120) {
        @unlink($pow_file);
        http_response_code(400);
        die(json_encode(["e" => "challenge expired"]));
    }

    // 验证 PoW: SHA-256(challenge || nonce) 开头 N 位必须为 0
    $hash = hash("sha256", $challenge . $nonce);
    $target = str_repeat("0", $pow["d"]);
    if (substr($hash, 0, $pow["d"]) !== $target) {
        http_response_code(403);
        die(json_encode(["e" => "invalid proof"]));
    }

    // 消耗掉 challenge（防重放）
    @unlink($pow_file);

    // 签发令牌（32 字节 = AES-256 密钥）
    $token = bin2hex(random_bytes(32));
    $token_file = sys_get_temp_dir() . "/skpnn_tok_" . md5($token) . ".json";
    file_put_contents($token_file, json_encode([
        "t" => $token,
        "ip" => $ip,
        "ts" => time(),
        "ttl" => 300
    ]), LOCK_EX);

    echo json_encode(["t" => $token, "ttl" => 300]);
    exit;
}

// ========== 3. 用令牌获取加密页面 ==========
if ($action === "page") {
    $token = $_GET["t"] ?? $_SERVER["HTTP_X_AUTH_TOKEN"] ?? "";
    if (!$token) {
        http_response_code(401);
        die(json_encode(["e" => "missing token"]));
    }

    $tok_file = sys_get_temp_dir() . "/skpnn_tok_" . md5($token) . ".json";
    if (!file_exists($tok_file)) {
        http_response_code(401);
        die(json_encode(["e" => "invalid token"]));
    }
    $tok = json_decode(file_get_contents($tok_file), true);

    // IP 绑定
    if ($tok["ip"] !== $ip) {
        http_response_code(403);
        die(json_encode(["e" => "ip mismatch"]));
    }

    // 过期检查
    if (time() - $tok["ts"] > $tok["ttl"]) {
        @unlink($tok_file);
        http_response_code(401);
        die(json_encode(["e" => "token expired"]));
    }

    // 用 MASTER_KEY 解密页面内容，再用令牌密钥重新加密传给前端
    $token_key = hex2bin($token);
    $encrypted_page = file_get_contents(__DIR__ . "/inc/page.enc");
    $html = aes_decrypt($encrypted_page, MASTER_KEY);
    if ($html === false) {
        http_response_code(500);
        die(json_encode(["e" => "decrypt failed"]));
    }

    // CSRF Token
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION["csrf_token"]) || empty($_SESSION["csrf_time"]) || time() - $_SESSION["csrf_time"] > 3600) {
        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
        $_SESSION["csrf_time"] = time();
    }
    // 每次使用刷新有效期
    $_SESSION["csrf_time"] = time();
    $csrf = $_SESSION["csrf_token"];

    // 注入令牌和 CSRF 到页面 head
    $inject = "<meta name=\"csrf-token\" content=\"" . $csrf . "\">\n";
    $inject .= "<script>window.CSRF_TOKEN=\"" . $csrf . "\";</script>\n";
    $inject .= "<script>window.AUTH_TOKEN=\"" . $token . "\";</script>\n";
    $inject .= "<script>window.SERVER_IP=\"" . SERVER_IP . "\";</script>\n";
    $html = str_replace("</head>", $inject . "</head>", $html);

    // 用令牌密钥加密传输
    $encrypted = aes_encrypt($html, $token_key);

    echo json_encode(["d" => $encrypted, "ttl" => $tok["ttl"] - (time() - $tok["ts"])]);
    exit;
}

// ========== 4. 刷新令牌 ==========
if ($action === "refresh") {
    $old_token = $_GET["t"] ?? $_SERVER["HTTP_X_AUTH_TOKEN"] ?? "";
    if (!$old_token) {
        http_response_code(401);
        die(json_encode(["e" => "missing token"]));
    }

    $tok_file = sys_get_temp_dir() . "/skpnn_tok_" . md5($old_token) . ".json";
    if (!file_exists($tok_file)) {
        http_response_code(401);
        die(json_encode(["e" => "invalid token"]));
    }
    $tok = json_decode(file_get_contents($tok_file), true);

    if ($tok["ip"] !== $ip) {
        @unlink($tok_file);
        http_response_code(403);
        die(json_encode(["e" => "ip mismatch"]));
    }
    if (time() - $tok["ts"] > $tok["ttl"]) {
        @unlink($tok_file);
        http_response_code(401);
        die(json_encode(["e" => "token expired"]));
    }

    // 延长寿命
    $tok["ts"] = time();
    file_put_contents($tok_file, json_encode($tok), LOCK_EX);

    echo json_encode(["ok" => true, "ttl" => $tok["ttl"]]);
    exit;
}

http_response_code(400);
echo json_encode(["e" => "unknown action"]);
