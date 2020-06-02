<?php

namespace starekrow\SecureToken;

class QuickCoder extends BaseCoder
{
    public $ivLength = self::AES_BLOCK_SIZE;
    public $signatureLength = self::SHA256_LENGTH;
    public $keyLength = self::AES128_KEY_LENGTH;
    public $saltLength = 0;

    public function sign($data, $key, $salt = null)
    {
        $sigkey = self::kdf1_sha256($key, "verify", self::SHA256_LENGTH);
        return self::hmac_sha256($data, $sigkey);
    }

    public function encode($data, $key)
    {
        $cryptkey = self::kdf1_sha256($key, "encrypt", $this->keyLength);
        return self::aes128($data, $cryptkey);
    }

    public function decode($data, $key)
    {
        $cryptkey = self::kdf1_sha256($key, "encrypt", $this->keyLength);
        return self::aes128($data, $cryptkey);
    }
}
