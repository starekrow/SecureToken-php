<?php

namespace starekrow\SecureToken;

class TokenError extends Error
{
    // Possible error codes
    const ERR_FORMAT = 1;
    const ERR_SIGNATURE = 2;
    const ERR_MISSING_KEY = 3;
    const ERR_BAD_KEY = 5;
    const ERR_BAD_DATA = 6;
}
