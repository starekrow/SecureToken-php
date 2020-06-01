<?php

namespace starekrow\SecureToken;

class QuickToken extends BaseToken
{
    public $ivLength = self::AES_BLOCK_SIZE;
    public $signatureLength = self::SHA512_LENGTH;
    public $keyLength = self::AES128_KEY_LENGTH;
    public $saltLength = 0;

    public function sign($data, $key, $salt = null)
    {
        return self::hmac_sha256($data, $key);
    }

    public function encode($bytes, $key)
    {
        return self::aes128($data, $key);
    }

    public function decode($bytes, $key)
    {
        return self::aes128($bytes, $key);
    }

}
