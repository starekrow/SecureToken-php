<?php

namespace starekrow;
use starekrow\SecureToken\SecureToken;

/**
 *
 * 
 * 
 * 
 * 
 * 
 */
class SecureToken
{
    const KEY_INDEX_MASK                =   0x0f;
    const TOKEN_TYPE_MASK               =   0x30;
    const PAYLOAD_TYPE_MASK             =   0x40;
    const EXTENSION_FLAG_MASK           =   0x80;

    const SECURE_TOKEN                  =   0x00;
    const QUICK_TOKEN                   =   0x10;
    const COMPACT_TOKEN                 =   0x20;
    const AUTO_TOKEN                    =   -1;

    const BINARY_PAYLOAD                =   0x00;
    const JSON_PAYLOAD                  =   0x40;
    const AUTO_PAYLOAD                  =   -2;

    const TEXT_ENVELOPE                 =   0;
    const BINARY_ENVELOPE               =   1;
    const AUTO_ENVELOPE                 =   -3;

    const MAX_KEY_INDEX                 =   0x0f;

    const ERR_UNKNOWN_TYPE              =   1;
    const ERR_UNKNOWN_PAYLOAD           =   1;
    const ERR_UNKNOWN_ENVELOPE          =   3;
    const ERR_BAD_KEY                   =   4;
    const ERR_BAD_PAYLOAD               =   5;
    const ERR_MISSING_KEY               =   6;
    const ERR_BAD_KEY_INDEX             =   7;
    const ERR_DECODE_FAILED             =   8;

    static $throwErrorsDefault;
    
    public $tokenType;
    public $payloadType;
    public $envelopeType;
    public $keyIndex;
    public $keyData;
    public $keyLibrary;
    public $payload;
    public $token;
    public $throwErrors;

    /**
     * @param mixed $data data to encode
     * @param mixed $key 
     * 
     */
    static function encodeToken($data, string $key)
    {
        return (new SecureToken())->save($data)->encodeWith($key);
    }

    /**
     * Decodes a encoded secure token
     * 
     * @param string $token The encoded token to decode
     * @param string|array $key The key or key library to use for decoding
     * @return mixed The decoded token data, or a TokenError
     */
    static function decodeToken(string $token, $key)
    {
        return (new SecureToken())->load($token)->decodeWith($key);
    }

    /**
     * 
     */


    /**
     * 
     * @return SecureToken|null parsed token or `null` if token is obviously invalid
     */
    static function parse(string $data = null)
    {
        if (!$data) {
            return null;
        }
        $token = new SecureToken();
        if (ord($data[0]) & 0x80) {
            // binary envelope
        } else {
            $token->format = self::FORMAT_TEXT;
            $parts = explode(".", $data);
            if (count($parts) != 2 || strlen($parts[0]) < 1 
                                   || strlen($parts[1]) < 1) {
                return null;
            }
            $header = self::base64url_decode($parts[0]);
            $token->encryptedPayload = self::base64url_decode($parts[1]);
            if  ($header === null || $token->encryptedPayload === null) {
                return null;
            }
            return (object) [
                'flags' => ord($header[0]),
                'sig' => substr($header, 1),
                'payload' => $payload
            ];
    
        }
        $flags = ord($header[0]);
        $token->type = $flags & self::TOKEN_TYPE_MASK;
        $token->keyIndex = $flags & self::KEY_INDEX_MASK;
        $token->payloadType = $flags & self::PAYLOAD_TYPE_MASK;
        $token->encryptedPayload = payload;
        if ($token->type == self::SECURE_TOKEN) {

        }
        return $token;
    }

    public function __construct()
    {
        $this->envelopeType = self::TEXT_ENVELOPE;
        $this->tokenType = self::AUTO_TOKEN;
        $this->payloadType = self::AUTO_PAYLOAD;
        $this->keyIndex = 0;
    }

    public function throwErrors()
    {
        $this->throwErrors = true;
    }

    public function returnErrors()
    {
        $this->throwErrors = false;
    }

    public function clearError()
    {
        $this->error = null;
        return $this;
    }

    protected function error(int $errorCode, string $message = null)
    {
        $explain = $message ?? self::errorMessages[$errorCode] ?? "error #{$errorCode}";
        $error = new SecureTokenError("SecureToken error: {$explain}", $errorCode);
        $this->error = $error;
        return $this->errorRepsonse();
    }

    protected function errorResponse()
    {
        if ($this->throwErrors) {
            throw $this->error;
        }
        return $this->error;
    }

    public function key(string $key, int $keyIndex = null)
    {
        $this->keyData = $key;
        $this->keyLibrary = null;
        if ($keyIndex !== null) {
            return $this->keyIndex($keyIndex);
        }
        return $this;
    }

    public function keys(array $keys, int $keyIndex = null)
    {
        $this->keyData = null;
        $this->keyLibrary = $keys;
        if ($keyIndex !== null) {
            return $this->keyIndex($keyIndex);
        }
        return $this;
    }

    public function keyIndex(int $keyIndex)
    {
        if ($keyIndex < 0 || $keyIndex > self::MAX_KEY_INDEX) {
            $this->error(self::ERR_BAD_KEY, "Key index out of range");
        } else {
            $this->keyIndex = $keyIndex;
        }
        return $this;
    }

    public function tokenType(int $type)
    {
        switch ($type) {
        case self::COMPACT_TOKEN:
        case self::SECURE_TOKEN:
        case self::QUICK_TOKEN:
        case self::AUTO_TOKEN:
            $this->tokenType = $type;
            break;
        default:
            $this->error(self::ERR_UNKNOWN_TYPE);
        }
        return $this;
    }

    public function compactToken()
    {
        return $this->tokenType(self::COMPACT_TOKEN);
    }

    public function quickToken()
    {
        return $this->tokenType(self::QUICK_TOKEN);
    }

    public function secureToken()
    {
        return $this->tokenType(self::SECURE_TOKEN);
    }

    public function autoToken()
    {
        return $this->tokenType(self::AUTO_TOKEN);
    }

    public function envelopeType($type)
    {
        switch ($type) {
        case self::BINARY_ENVELOPE;
        case self::TEXT_ENVELOPE;
        case self::AUTO_ENVELOPE;
            $this->envelopeType = $type;
            break;
        default:
            $this->error(self::ERR_UNKNOWN_ENVELOPE);
        }
        return $this;
    }

    public function textEnvelope()
    {
        return $this->envelopeType(self::TEXT_ENVELOPE);
    }

    public function binaryEnvelope()
    {
        return $this->envelopeType(self::BINARY_ENVELOPE);
    }

    public function autoEnvelope()
    {
        return $this->envelopeType(self::AUTO_ENVELOPE);
    }

    public function load(string $token)
    {
        $this->token = $token;
        return $this;
    }

    public function save($data)
    {

        return $this;
    }

    public function decode($data)
    {
        if ($this->error) {
            return $this->repeatError();
        }
    }

    public function decodeWith($key)
    {
        if (is_string($key)) {
            $useKey = $key;
        } else if (is_array($key)) {

        } else {
            return $this->error(self::ERR_BAD_KEY);
        }        
    }

    protected function encodePayload($payload)
    {
        switch ($this->payloadType) {
        case self::BINARY_PAYLOAD:
            if (!is_string($payload)) {
                return $this->error(self::ERR_BAD_PAYLOAD, "Payload is not a string");
            }
            break;
        case self::AUTO_PAYLOAD:
            if (is_string($payload)) {
                break;
            }
            // fall through
        case self::JSON_PAYLOAD:
            $payload = json_encode($payload);
            if (json_last_error()) {
                return $this->error(self::ERR_BAD_PAYLOAD, "Payload JSON encoding failed");
            }
            break;
        }
        return $payload;
    }

    protected function getKey()
    {
        if ($this->error) {
            return $this->issueError();
        }
        if ($this->keyLibrary) {
            if (!array_key_exists($this->keyIndex, $this->keyLibrary)) {
                return $this->error(self::ERR_BAD_KEY_INDEX);
            }
            $key = $this->keyLibrary[$this->keyIndex];
            if (!is_string($key) || $key === "") {
                return $this->error(self::ERR_BAD_KEY, "Invalid key at given library index");
            }
        } else {
            $key = $this->keyData;
            if (!is_string($key) || $key === "") {
                return $this->error(self::ERR_BAD_KEY, "No key provided");
            }
        }
        return $key;
    }

    public function encode($payload)
    {
        $payload = $this->encodePayload($payload);
        if ($payload instanceof SecureTokenError) {
            return $payload;
        }
        $key = $this->getKey();
        if ($key instanceof SecureTokenError) {
            return $payload;
        }
        return $this->encrypt($payload, $key);
    }

    public function encodeWith($key)
    {
        $payload = $this->processPayload($this->payload);
        if ($payload instanceof SecureTokenError) {
            return $payload;
        }
        if (!is_string($key) || $key === "") {
            return $this->error(self::ERR_BAD_KEY, "No key provided");
        }
        return $this->encrypt($payload, $key);
    }

    public function import($data)
    {

    }

    public function payloadType($type)
    {
        switch ($type) {
        case self::BINARY_PAYLOAD:
        case self::JSON_PAYLOAD:
        case self::AUTO_PAYLOAD:
            $this->payloadType = $type;
            break;
        default:
            $this->error(self::ERR_UNKNOWN_PAYLOAD);
        }
        return $this;
    }

    public function jsonPayload()
    {
        return $this->payloadType(self::JSON_PAYLOAD);
    }

    public function binaryPayload()
    {
        return $this->payloadType(self::BINARY_PAYLOAD);
    }

    public function autoPayload()
    {
        return $this->payloadType(self::AUTO_PAYLOAD);
    }

    protected function setupCoder()
    {

    }

    // TODO: public function cborPayload()
    // TODO: public function pbPayload()

    

    protected function parseHeader(string $header)
    {
        if (strlen($header) < 1) {
            return $this->error(self::ERR_DECODE_FAILED);
        }
        $flags = ord($header[0]);
        if ($flags & self::EXTENSION_BIT) {
            return $this->error(self::ERR_DECODE_FAILED);
        }
        $tokenType = $flags & self::TOKEN_TYPE_MASK;
        if ($tokenType == self::RESERVED_TOKEN) {
            return $this->error(self::ERR_DECODE_FAILED);
        } else if ($this->tokenType == self::AUTO_TOKEN) {
            $this->tokenType = $tokenType;
        } else if ($this->tokenType != $tokenType) {
            return $this->error(self::ERR_DECODE_FAILED);
        }
        $payloadType = $flags & self::PAYLOAD_TYPE_MASK;
        if ($this->payloadType == self::AUTO_PAYLOAD) {
            $this->payloadType = $payloadType;
        } else if ($this->payloadType != $payloadType) {
            return $this->error(self::ERR_DECODE_FAILED);
        }
        $this->keyIndex = $flags & self::KEY_INDEX_MASK;
        $this->setupCoder();
        $this->mac = $this->coder->getMAC($header);
        $this->salt = $this->coder->getSalt($header);
    }

    protected function unwrap()
    {
        if (ord($this->token[0]) & 0x80) {
            $this->envelopeType = self::BINARY_ENVELOPE;
            $this->tokenWrapper = new BinaryWrapper();
        } else {
            $this->envelopeType = self::TEXT_ENVELOPE;
            $this->tokenWrapper = new TextWrapper();
        }
        list($header, $payload) = $this->tokenWrapper->unwrap($token);
        $this->parseHeader($header);
        $this->payload = $payload;
    }

    protected function wrap(int $flags, string $signature, string $cipherText)
    {
        switch ($this->tokenType) {
        case self::BINARY_ENVELOPE:
            $this->tokenWrapper = new BinaryWrapper();
            return $this->wrapBinary($flags, $signature, $cipherText);
        case self::AUTO_ENVELOPE:
            $this->envelopeType = self::TEXT_ENVELOPE;
            // fall through
        case self::TEXT_ENVELOPE:
            $this->tokenWrapper = new TextWrapper();
        }
        $this->token = $this->tokenWrapper->wrap($flags, $signature, $cipherText);
    }

    static function flags($token)
    {
        if (!is_string($token) || strlen($token) < 2) {
            return null;
        }
        $v = self::base64url_decode(substr($token, 0, 4));
        if (!is_array($v)) {
            return null;
        }
        return ord($v[0]);
    }

    static function setupKey($key, $flags, $salt = null)
    {
        if (is_array($key) && isset($key[$flags & self::KEY_INDEX_MASK])) {
            $key = $key[$flags & self::KEY_INDEX_MASK];
        }
        if (is_array($key)) {
            $key = (object)$key;
        }
        if (is_object($key) && isset($key->verify) && isset($key->encrypt)) {
            if (($flags & self::TOKEN_TYPE_MASK) == self::SECURE_TOKEN && !isset($key->salt)) {
                return null;
            }
            return $key;
        }
        if (!is_string($key)) {
            return null;
        }
        switch ($flags & self::TOKEN_TYPE_MASK) {
        case self::QUICK_TOKEN:
            return (object)[
                'verify' => self::kdf1("sha256", self::SHA256_LENGTH, $key, "verify"),
                'encrypt' => self::kdf1("sha256", self::AES128_KEY_LENGTH, $key, "encrypt")
            ];
        case self::COMPACT_TOKEN:
            return (object)[
                'verify' => self::kdf1("sha256", self::SHA256_LENGTH, $key, "verify"),
                'encrypt' => self::kdf1("sha256", self::AES128_KEY_LENGTH, $key, "encrypt")
            ];
        case self::SECURE_TOKEN:
            if ($salt === null) {
                $salt = self::random(self::SHA512_LENGTH);
            }
            return (object)[
                'verify' => self::hkdf("sha512", self::SHA512_LENGTH, $key, "verify", $salt),
                'encrypt' => self::hkdf("sha256", self::AES256_KEY_LENGTH, $key, "encrypt"),
                'salt' => $salt
            ];
        }
        return null;
    }

    static function sign($data, $key, $flags)
    {
        switch ($flags & self::TOKEN_TYPE_MASK) {
        case self::QUICK_TOKEN:
            return self::hmac('sha256', $data, $key->verify);
        case self::COMPACT_TOKEN:
            return substr(self::hmac('sha1', $data, $key->verify), 0, 10);
        case self::SECURE_TOKEN:
            return $key->salt . self::hkdf('sha512', self::SHA512_LENGTH, $data, 'encrypt', $key->salt);
        }
        return null;
    }
/*
    static function encode($data, $key, $flags = 0, $salt = null, $iv = null)
    {
        $key = self::setupKey($key, $flags, $salt);
        if (!$key || !is_int($flags) || $flags > 127 || $flags < 0) {
            return "";
        }
        if (!is_string($data)) {
            $data = json_encode($data);
            if ($data === null) {
                return "";
            }
            $flags |= self::JSON_PAYLOAD;
        }
        $data .= chr($flags);
        $header = chr($flags) . self::sign($data, $key, $flags);
        $payload = self::aes('encrypt', $data, $key);
        return self::base64url_encode($header) . '.' . self::base64url_encode($payload);
    }

    static function decode($token, $key)
    {
        $t = self::parse($token);
        $salt = null;
        if (($t->flags & self::TOKEN_TYPE_MASK) == self::SECURE_TOKEN) {
            $salt = substr($t->sig, 0, self::SHA512_LENGTH);
        }
        $key = self::setupKey($key, $t->flags, $salt);
        $ptext = self::aes('decrypt', $t->payload, $key);
        $plen = strlen($ptext);
        if ($ptext === null || ord($ptext[$plen - 1]) !== $t->flags) {
            return null;
        }
        return substr($ptext, 0, $plen - 1);
    }

    static function random($length)
    {
        if (function_exists("random_bytes")) {
            return random_bytes($length);
        } else if (function_exists("openssl_random_pseudo_bytes")) {
            return openssl_random_pseudo_bytes($length);
        } else if (function_exists('mcrypt_create_iv')) {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }
        // TODO: PHP5 Windows support?
    }

    static function generate($item, $flags)
    {
        $len = 0;
        switch ($item) {
        case 'iv':
            $len = self::AES_BLOCK_SIZE;
            break;
        case 'salt':
            switch ($flags & self::TOKEN_TYPE_MASK) {
            case self::QUICK_TOKEN:
            case self::COMPACT_TOKEN:
                break;
            case self::SECURE_TOKEN:
                $len = self::SHA256_LENGTH;
            }
            break;
        case 'key':
            switch ($flags & self::TOKEN_TYPE_MASK) {
            case self::QUICK_TOKEN:
            case self::COMPACT_TOKEN:
                $len = self::AES128_KEY_LENGTH;
                break;
            case self::SECURE_TOKEN:
                $len = self::AES256_KEY_LENGTH;
            }
            break;
        }
        return $len ? self::random($len) : null;
    }

    static function useLibrary($library)
    {
        self::$aesEncrypt = $library ? "aes_$library" : null;
    }

    static function throw()

    function __construct($flags, $key = null)
    {

    }
*/
}

/*
$flags = SecureToken::COMPACT_TOKEN;
$data = '{"did":1234567890}';
$iv = SecureToken::generate('iv', $flags);
$key = SecureToken::generate('key', $flags);
$salt = SecureToken::generate('salt', $flags);

//SecureToken::useLibrary("mcrypt");
$tok = SecureToken::encode($data, $key, $flags, $salt, $iv);
echo strlen($tok) . " bytes: $tok" . PHP_EOL;

//SecureToken::useLibrary("openssl");
$t2 = SecureToken::decode($tok, $key);
echo $t2 . PHP_EOL;


$data = ["did" => 1234567890];

// context-free encoding (SECURE tokens only)
$key = SecureToken::randomKey();
$keys = loadKeyLibrary();
$keyIndex = 2;
$tok = SecureToken::encodeToken($data, $key);

// context-free decoding
$data = SecureToken::decodeToken($tok, $key);

$tok = (new SecureToken())->compact()->save($data)->encodeWith($key);
$tok = (new SecureToken())->compact()->key($key)->encode($data);
$tok = (new SecureToken())->compact()->save($data)->key($key)->encode();

$data = (new SecureToken())->compact()->load($tok)->decodeWith($key);
$data = (new SecureToken())->compact()->key($key)->decode($tok);

$data = (new SecureToken())->compact()->load($tok)->decodeWith($key);
$data = (new SecureToken())->compact()->load($tok)->decodeWith($keys);
$data = (new SecureToken())->compact()->key($key)->decode($tok);
$data = (new SecureToken())->compact()->keys($keys)->decode($tok);

$data = (new SecureToken())->compact()->jsonFormat()->keyIndex(0)->key($key)->encode($data);


$tok = (new SecureToken())->save($data)->keyIndex($keyIndex)->encodeWith($keys);
$tok = (new SecureToken())->save($data)->keyIndex($keyIndex)->encodeWith($keys);
$data = (new SecureToken())->keys($keys)->keyIndex(0)->encode($data);


*/

