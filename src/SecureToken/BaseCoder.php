<?php

namespace starekrow\SecureToken;

abstract class BaseCoder
{
    const MIN_TEXT_TOKEN_LENGTH = 6;
    const MIN_BINARY_TOKEN_LENGTH = 4;
    const MIN_BINARY_TOKEN_CONTENT_LENGTH = 3;
    const TEXT_HEADER_DELIMITER = '.';
    const TEXT_TOKEN_TERMINATOR = '~';
    const BINARY_ENVELOPE_INDICATOR = 0x80;
    const BINARY_ENVELOPE_LEADING_LENGTH_BITS = 6;

    const OP_ENCRYPT = 1;
    const OP_DECRYPT = 2;

    const ALGO_SHA256 = "sha256";
    const ALGO_SHA512 = "sha512";
    const SHA256_LENGTH                 =   32;
    const SHA512_LENGTH                 =   64;
    const HMAC_SHA256_KEY_LENGTH        =   64;
    const HMAC_SHA512_KEY_LENGTH        =   64;

    const AES_BLOCK_SIZE                =   16;
    const AES128_KEY_LENGTH             =   16;
    const AES256_KEY_LENGTH             =   16;

    public $ivLength;
    public $signatureLength;
    public $keyLength;
    public $saltLength;

    static function hash(string $algo, string $data)
    {
        return hash($algo, $data, true);
    }

    static function hmac(string $algo, string $data, string $key)
    {
        return hash_hmac($algo, $data, $key, true);
    }

    static function hashlen(string $algo)
    {
        switch ($algo) {
        case self::ALGO_SHA256:
            return SHA256_LENGTH;
        case self::ALGO_SHA512:
            return SHA512_LENGTH;
        default:
            return -1;
        }
    }

    static function hmackeylen(string $algo)
    {
        switch ($algo) {
        case self::ALGO_SHA256:
            return self::HMAC_SHA256_KEY_LENGTH;
        case self::ALGO_SHA512:
            return self::HMAC_SHA512_KEY_LENGTH;
        default:
            return -1;
        }
    }

    static function kdf1(string $algo, int $length, string $key, string $context = "", string $salt = "")
    {
        $hashlen = self::hashlen($algo);
        $reps = ceil($length / $hashlen);
        $out = "";
        for ($i = 0; $i < $reps; $i++) {
            $out .= self::hash($algo, $key . pack('N', $i) . $context . $salt);
        }
        return substr($out, 0, $length);
    }

    static function hkdf(string $algo, int $length, string $sourceKey, string $context = "", string $salt = "")
    {
        $hashlen = self::hashlen($algo);
        $reps = ceil($length / $hashlen);
        $out = "";
        for ($i = 0; $i < $reps; $i++) {
            $out .= self::hash($algo, $sourceKey . pack('N', $i) . $context . $salt);
        }
        return substr($out, 0, $length);
    }

    static function pkcs7pad(string $data, int $blocksize)
    {
        $pad = $blocksize - (strlen($data) % $blocksize);
        return $data . str_repeat(chr($pad), $pad);
    }

    static function pkcs7unpad(string $data, int $blocksize)
    {
        $len = strlen($data);
        $pad = ord($data[$len - 1]);
        if ($pad < 1 || $pad > $blocksize || $len % $blocksize != 0) {
            return null;
        }
        return substr($data, 0, $len - $pad);
    }

    static function aes_sodium(int $operation, string $data, string $key, $iv = null)
    {
        switch ($operation) {
        case self::OP_ENCRYPT:
            $payload = self::pkcs7pad($data, self::AES_BLOCK_SIZE);
            if (!$iv) {
                $iv = mcrypt_create_iv(self::AES_BLOCK_SIZE, MCRYPT_DEV_URANDOM);
            }
            $crypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key->encrypt, $payload, MCRYPT_MODE_CBC, $iv);
            return $iv . $crypt;

        case self::OP_DECRYPT:
            $iv = substr($data, 0, self::AES_BLOCK_SIZE);
            $ctext = substr($data, self::AES_BLOCK_SIZE);
            $ptext = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key->encrypt, $ctext, MCRYPT_MODE_CBC, $iv);
            return self::pkcs7unpad($ptext, self::AES_BLOCK_SIZE);
        }
    }

    static function aes_openssl(int $operation, string $data, string $key, string $iv = null)
    {
        switch ($operation) {
        case self::OP_ENCRYPT:
            if (!$iv) {
                $iv = openssl_random_pseudo_bytes(self::AES_BLOCK_SIZE);
            }
            $bits = strlen($key) << 3;
            $crypt = openssl_encrypt($data , "AES-$bits-CBC", $key, OPENSSL_RAW_DATA, $iv);
            return $iv . $crypt;

        case self::OP_ENCRYPT:
            if ($iv) {
                $ctext = $data;
            } else {
                $iv = substr($data, 0, self::AES_BLOCK_SIZE);
                $ctext = substr($data, self::AES_BLOCK_SIZE);
            }
            $bits = strlen($key) << 3;
            $ptext = openssl_decrypt($ctext, "AES-$bits-CBC", $key, OPENSSL_RAW_DATA, $iv);
            return $ptext;
        }
    }

    static function aes($operation, $data, $key)
    {
        if (!self::$aesEncrypt) {
            if (function_exists('openssl_encrypt')) {
                self::$aesEncrypt = 'aes_openssl';
            } else if (function_exists('mcrypt_encrypt')) {
                self::$aesEncrypt = 'aes_sodium';
            } else {
                return null;
            }
        }
        return self::{self::$aesEncrypt}($operation, $data, $key);
    }

    static function base64url_encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }  

    static function base64url_decode($input)
    {
        return base64_decode(str_pad(strtr($input, '-_', '+/'), (4 - strlen($input)) & 3, '='));
    }

    public function wrapText($header, $payload)
    {
        return \implode("",[
            self::base64url_encode($header),
            self::HEADER_DELIMITER,
            self::base64url_encode($cipher),
            self::TOKEN_TERMINATOR,
        ]);
    }

    public function unwrapText($token)
    {
        $len = strlen($token);
        $mid = \strpos($token, self::HEADER_DELIMITER);
        if (
            $len < self::MIN_PARSEABLE_TOKEN_LENGTH
            || $token[$len - 1] != self::TOKEN_TERMINATOR
            || $mid === false
            || $mid == 0
            || $mid == $len - 2
        ) {
            return [null, null];
        }
        $header = self::base64url_decode(substr($token, 0, $mid));
        $cipher = self::base64url_decode(substr($token, $mid + 1, $len - $mid - 2));
        if (!$header || !$cipher) {
            return [null, null];
        }
        return [$header, $cipher];
    }

    public function lengthCode($length, $startingBits = 7)
    {
        $startingLimit = 1 << $startingBits;
        $result = [];
        while (true) {
            if ($length < $startingLimit) {
                break;
            }
            array_unshift($result, chr($length & 0x7f) | 0x80);
            $length >>= 7;
        }
        array_unshift($result, chr($length | (count($result) ? $startingLimit : 0)));
        return implode('', $result);
    }

    public function parseLengthCode(string $data, int $startingBits = 7, int $offset = 0)
    {
        $OVERFLOW_MASK = 0xff000000;
        $MAX_LENGTHCODE_BYTES = 9;
        $EXTENSION_INDICATOR = 0x80;
        $EXTENSION_BITS = 7;
        $EXTENSION_MASK = 0x7f;
        
        $limit = strlen($data) - 1;
        if ($limit < 0) {
            return [false, 0];
        }
        $extensionIndicator = 1 << $startingBits;
        $scan = offset;
        $byte = ord($data[$scan++]);
        $length = $byte & ($extensionIndicator - 1);
        while ($byte & $extensionIndicator) {
            if ($scan >= $limit || $length & $OVERFLOW_MASK || $scan - $offset > $MAX_LENGTHCODE_BYTES) {
                // out of bounds, or length will overflow, or code too long
                $length = false;
                $scan = $limit + 1;
                break;
            }
            $extensionIndicator = $EXTENSION_INDICATOR;
            $byte = ord($data[$scan++]);
            $length = ($length << $EXTENSION_BITS) | ($byte & $EXTENSION_MASK);
        }
        return [$length, $scan - $offset];
    }

    public function unwrapBinary($token)
    {
        if (!is_string($token)) {
            return [null, null];
        }
        $len = strlen($token);
        if ($len < self::MIN_BINARY_TOKEN_LENGTH) {
            return [null, null];
        }
        list($tokenLength, $headerStart) = $this->parseLengthCode($token, self::BINARY_ENVELOPE_LEADING_LENGTH_BITS, 0);
        list($headerLength, $macOffset) = $this->parseLengthCode($token, self::BINARY_HEADER_LEADING_LENGTH_BITS, $headerStart);
        if ($tokenLength === false || $headerLength === false || $headerLength >= $tokenLength - $macOffset || $tokenLength != $len - $headerStart) {
            return [null, null];
        }
        $cipherLength = $tokenLength - $macOffset - $headerLength;
        $header = substr($token, $headerStart + $macOffset, $headerLength);
        $cipher = substr($token, $headerStart + $macOffset + $headerLength);
        return [$header, $cipher];
    }

    public function wrapBinary($header, $payload)
    {
        $headerLengthCode = $this->lengthCode(strlen($header));
        $tokenLength = strlen($header) + strlen($headerLengthCode) + strlen($payload);
        $prefix = $this->lengthCode(tokenLength, self::BINARY_ENVELOPE_LEADING_LENGTH_BITS);
        $prefix[0] = ord($prefix[0]) | self::BINARY_ENVELOPE_INDICATOR;
        return implode('', [
            $prefix,
            $headerLengthCode,
            $header,
            $payload,
        ]);
    }

    public function 

    abstract public function encryptionKey(string $userKey, string $salt);
    abstract public function authorizationKey(string $userKey, string $salt);
    abstract public function getMAC(string $data, string $authorizationKey);
    abstract public function verifyMAC(string $data, string $mac, string $authorizationKey);
    abstract public function encrypt(string $payload, string $encryptionKey);
    abstract public function decrypt(string $cipher, string $encryptionKey);
}
