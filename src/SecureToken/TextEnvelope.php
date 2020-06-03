<?php
namespace starekrow\SecureToken;

class TextEnvelope
{
    const MIN_PARSEABLE_TOKEN_LENGTH = 6;
    const HEADER_DELIMITER = '.';
    const TOKEN_TERMINATOR = '~';

    static function base64url_encode($input)
    {
        return str_replace('=', '', strtr(\base64_encode($input), '+/', '-_'));
    }  

    static function base64url_decode($input)
    {
        return \base64_decode(str_pad(strtr($input, '-_', '+/'), (4 - strlen($input)) & 3, '='));
    }

    public function wrap($header, $payload)
    {
        return \implode("",[
            self::base64url_encode($header),
            self::HEADER_DELIMITER,
            self::base64url_encode($cipher),
            self::TOKEN_TERMINATOR,
        ]);
    }

    public function unwrap($token)
    {
        $len = \strlen($token);
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
}
