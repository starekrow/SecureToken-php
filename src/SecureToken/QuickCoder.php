<?php

namespace starekrow\SecureToken;

class QuickCoder extends BaseCoder
{
    public $macLength = self::HMAC_SHA256_KEY_LENGTH;
    public $saltLength = 16;
    public $ivLength = self::AES_BLOCK_SIZE;
    public $keyLength = self::AES128_KEY_LENGTH;

    public function encryptionKey(string $userKey, string $salt)
    {
        return self::kdf1(self::ALGO_SHA256, $this->macLength, $userKey, "encrypt", $salt);
    }

    public function authorizationKey(string $userKey, string $salt)
    {
        return self::kdf1(self::ALGO_SHA256,$this->macLength, $userKey, "verify", $salt);
    }

    public function getMAC(string $data, string $authorizationKey)
    {
        return self::hmac(self::ALGO_SHA256, $data, $authorizationKey);
    }

    public function verifyMAC(string $data, string $mac, string $authorizationKey)
    {
        $checkmac = $this->getMAC($data, $authorizationKey);
        return \hash_equals($mac, $checkmac);
    }

    public function encrypt(string $payload, string $encryptionKey)
    {
        return self::aes($payload, $encryptionKey);
    }

    public function decrypt(string $cipher, string $encryptionKey)
    {
        return self::aes($cipher, $encryptionKey);
    }
}
