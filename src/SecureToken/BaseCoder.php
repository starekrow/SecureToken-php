<?php

namespace starekrow\SecureToken;

abstract class BaseCoder
{
    const MIN_TEXT_TOKEN_LENGTH = 6;
    const MIN_BINARY_TOKEN_LENGTH = 6;
    const TEXT_HEADER_DELIMITER = '.';
    const TEXT_TOKEN_TERMINATOR = '~';

    const AES_BLOCK_SIZE                =   16;
    const AES128_KEY_LENGTH             =   16;
    const AES256_KEY_LENGTH             =   16;
    const SHA1_LENGTH                   =   20;
    const SHA256_LENGTH                 =   32;
    const SHA512_LENGTH                 =   64;
    const HMAC_SHA256_KEY_LENGTH        =   64;
    const HMAC_SHA512_KEY_LENGTH        =   64;

    public $ivLength;
    public $signatureLength;
    public $keyLength;
    public $saltLength;

    static function sha256($data)
    {
        return hash("sha256", $data, true);
    }

    static function hash($algo, $data)
    {
        return hash($algo, $data, true);
    }

    static function hmac($algo, $data, $key)
    {
        return hash_hmac($algo, $data, $key, true);
    }
    static function kdf1($algo, $length, $key, $context = "")
    {
        $hashlen = self::hashlen($algo);
        $reps = ceil($length / $hashlen);
        $out = "";
        for ($i = 0; $i < $reps; $i++) {
            $out .= self::hash($algo, $key . pack('N', $i) . $context);
        }
        return substr($out, 0, $length);
    }
    static function hkdf($algo, $length, $sourceKey, $context = "", $salt = "")
    {
        $hashlen = self::hashlen($algo);
        $reps = ceil($length / $hashlen);
        $out = "";
        for ($i = 0; $i < $reps; $i++) {
            $out .= self::hash($algo, $sourceKey . pack('N', $i) . $context);
        }
        return substr($out, 0, $length);
    }

    static function pkcs7pad($data, $blocksize)
    {
        $pad = $blocksize - (strlen($data) % $blocksize);
        return $data . str_repeat(chr($pad), $pad);
    }

    static function pkcs7unpad($data, $blocksize)
    {
        $len = strlen($data);
        $pad = ord($data[$len - 1]);
        if ($pad < 1 || $pad > $blocksize || $len % $blocksize != 0) {
            return null;
        }
        return substr($data, 0, $len - $pad);
    }

    static function aes_mcrypt($operation, $data, $key, $iv = null)
    {
        if ($operation == 'encrypt') {
            $payload = self::pkcs7pad($data, self::AES_BLOCK_SIZE);
            if (!$iv) {
                $iv = mcrypt_create_iv(self::AES_BLOCK_SIZE, MCRYPT_DEV_URANDOM);
            }
            $crypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key->encrypt, $payload, MCRYPT_MODE_CBC, $iv);
            return $iv . $crypt;
        } else if ($operation == 'decrypt') {
            $iv = substr($data, 0, self::AES_BLOCK_SIZE);
            $ctext = substr($data, self::AES_BLOCK_SIZE);
            $ptext = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key->encrypt, $ctext, MCRYPT_MODE_CBC, $iv);
            return self::pkcs7unpad($ptext, self::AES_BLOCK_SIZE);
        }
        return null;
    }

    static function aes_openssl($operation, $data, $key)
    {
        if ($operation == 'encrypt') {
            $iv = openssl_random_pseudo_bytes(self::AES_BLOCK_SIZE);
            $bits = strlen($key->encrypt) << 3;
            $crypt = openssl_encrypt($data , "AES-$bits-CBC", $key->encrypt, OPENSSL_RAW_DATA, $iv);
            return $iv . $crypt;
        } else if ($operation == 'decrypt') {
            $iv = substr($data, 0, self::AES_BLOCK_SIZE);
            $bits = strlen($key->encrypt) << 3;
            $ctext = substr($data, self::AES_BLOCK_SIZE);
            $ptext = openssl_decrypt($ctext, "AES-$bits-CBC", $key->encrypt, OPENSSL_RAW_DATA, $iv);
            return $ptext;
        }
        return null;
    }

    static function aes($operation, $data, $key)
    {
        if (!self::$aesEncrypt) {
            if (function_exists('openssl_encrypt')) {
                self::$aesEncrypt = 'aes_openssl';
            } else if (function_exists('mcrypt_encrypt')) {
                self::$aesEncrypt = 'aes_mcrypt';
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
        $extension = 1 << $startingBits;
        $byte = ord($data[$offset]);
        while ($byte & $extension) {

        }
        
    }

    public function unwrapBinary($token)
    {
        $tokenLength = 0;

        if ($token[0])
    }

    public function wrapBinary($header, $payload)
    {
        $headerLengthCode = $this->lengthCode(strlen($header));
        $tokenLength = strlen($header) + strlen($headerLengthCode) + strlen($payload);
        $prefix = $this->lengthCode($tokenLength);
        $prefix[0] = ord($prefix[0])
        return implode('',[
            $prefix,
            $headerLengthCode,
            $header,
            $payload
        ]);
    }

    abstract public function sign($bytes, $key, $salt = null);
    abstract public function encode($bytes, $key);
    abstract public function decode($bytes, $key);
}
