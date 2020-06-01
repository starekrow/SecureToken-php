<?php

namespace starekrow\SecureToken;

abstract class BaseToken
{
    const AES_BLOCK_SIZE                =   16;
    const AES128_KEY_LENGTH             =   16;
    const AES256_KEY_LENGTH             =   16;
    const SHA1_LENGTH                   =   20;
    const SHA256_LENGTH                 =   32;
    const SHA512_LENGTH                 =   64;

    abstract public function ivLength();
    abstract public function keyLength();
    abstract public function saltLength();
    abstract public function sign($bytes, $key, $salt = null);
    abstract public function encode($bytes, $key);
    abstract public function decode($bytes, $key);
}
