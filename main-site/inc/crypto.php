<?php
/**
 * crypto.php — AES-256-GCM 加密解密函数
 * 主密钥仅存于服务器，绝不外传
 */

/**
 * 用主密钥加密明文
 * @param string $plaintext 要加密的文本
 * @param string $key 二进制密钥（32字节）
 * @return string base64(IV + ciphertext + tag)
 */
function aes_encrypt($plaintext, $key) {
    $iv = random_bytes(12); // GCM 推荐 12 字节 IV
    $tag = '';
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );
    return base64_encode($iv . $ciphertext . $tag);
}

/**
 * 用主密钥解密密文
 * @param string $encoded base64(IV + ciphertext + tag)
 * @param string $key 二进制密钥（32字节）
 * @return string|false 明文或失败
 */
function aes_decrypt($encoded, $key) {
    $data = base64_decode($encoded);
    if ($data === false || strlen($data) < 28) return false;
    $iv = substr($data, 0, 12);
    $tag = substr($data, -16);
    $ciphertext = substr($data, 12, -16);
    return openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );
}

/**
 * 生成随机 AES-256 密钥（用于临时传输加密）
 * @return string 二进制密钥（32字节）
 */
function generate_ephemeral_key() {
    return random_bytes(32);
}
