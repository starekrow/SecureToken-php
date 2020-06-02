<?php

namespace starekrow\SecureToken;

abstract class BaseCoder
{
    const AES_BLOCK_SIZE                =   16;
    const AES128_KEY_LENGTH             =   16;
    const AES256_KEY_LENGTH             =   16;
    const SHA1_LENGTH                   =   20;
    const SHA256_LENGTH                 =   32;
    const SHA512_LENGTH                 =   64;

    public $ivLength;
    public $signatureLength;
    public $keyLength;
    public $saltLength;


    static function base64url_encode($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }  
    static function base64url_decode($input) {
        return base64_decode(str_pad(strtr($input, '-_', '+/'), (4 - strlen($input)) & 3));
    }
    static function hashlen($algo)
    {
        switch (strtolower(str_replace('-', '', $algo))) {
        case 'md5':             return 16;
        case 'sha1':            return 20;
        case 'sha256':          return 32;
        case 'sha512':          return 64;
        }
        return strlen(hash($algo,"test",true));
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


    abstract public function sign($bytes, $key, $salt = null);
    abstract public function encode($bytes, $key);
    abstract public function decode($bytes, $key);
}
