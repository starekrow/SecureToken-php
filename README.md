# SecureToken-php

An implementation of the Secure Token specification for PHP

## Introduction

SecureTokens are a compact envelope for encrypted data. They provide the 
following features:

  - HMAC signatures to prevent tampering
  - AES encryption
  - URL-safe representation
  - simple key creation and management
  - easy key rotation and/or token versioning
  - compact form for limited bandwidth connections
  - strong form for future-proof security
  - expandable format

## Use






## Cryptography




## Format

The token format is designed to be URL-safe while still limiting the overhead
required for format and encoding information. It offers a diverse selection
of types that trade off size and complexity against security. The weakest
available token is still more than sufficiently secure to defeat any attempt
to decode or tamper with it using currently available technology.

Structurally, the token is formed of two strings separated by a period
(".") character. The strings are in a URL-safe base-64 encoding, and decode
to binary strings. 

The first string is the header, and the first byte in the header is a "flags
byte", described below. The remainder of the header is a signature for the
payload.

The payload is the second string, and it is encrypted with an algorithm that
depends on the type of the token. This type is specified within the flags 
byte. After decryption, the first byte of the payload is a copy of the flags
byte, and the remainder is either a binary string or JSON-encoded data, 
depending on another field in the flags byte.

### Flags Byte

The flags byte contains the following bitfields:

  - bits 0 - 3: key index
  - bits 4 - 5: token type
    0. Secure
    1. Quick
    2. Compact
    3. there is no 3
  - bit 6: data type
    0. binary string
    1. JSON-encoded data
  - bit 7: reserved for header extension

The key index is a 4-bit unsigned integer field available for the 
application's use. This could be used, for example, to choose a key from a 
set of up to sixteen available keys. This value can be seen and used without
decrypting the token.

The token type selected affects the encryption and authentication of the
token, and influences its total length. The possible types are:

  - Secure: Normal tokens encrypt with AES-256 and use HKDF with SHA-512 for
    authentication. An additional 256-bit salt is generated and stored
    before the MAC.
  - Quick: A quick token uses AES-128 for encryption, SHA-256 for the HMAC
    authentication, and KDF1 to generate keys.
  - Compact: Uses the same algorithms as the normal token, but only 
    includes the first 10 bytes of the HMAC for athentication.

### Data Type

Tokens support the encoding of either binary or JSON-encoded data, as specified
by a bit in the flags byte of the token. This data may be any legal JSON value;
numbers, strings, and boolean values (and null!) are explicitly allowed as well
as arrays and objects. Binary data, of course, may be used to represent data in
any encoding at all (including JSON).

The JSON encoding bit in the flags byte is provided as a convenience for what
is expected to be the most common use case for these tokens: The storage and
transmission of simple secrets like API keys, certificates and other basic
authentication and/or configuration data.

### Binary Tokens

For the hyper-efficient who are blessed with low-cost binary transports, there
is an alternate binary format for tokens. This format is denoted by the first
byte of the token having bit 7 set. The binary format provides a simple envelope
around the token data and allows the flags byte, signature and payload to be 
presented as binary data without any base-64 encoding.

The binary token header contains bitfields as follows:

  - bits 0-3: high-order bits of token length
  - bits 4-6: number of bytes in the length field
  - bit 7: set to indicate a binary token

This header is followed by a variable-length field containing the length of the
token data (that is, the count of bytes following the length field). The 
number of bytes in this length field is specified in the binary header.
The length field is always stored with the most significant byte first, and the
highest-order 4 bits of the length are taken from the binary token header. Note
that while this format provides for tokens up to 2^60 in length, very few 
clients will handily deal with tokens larger than a megabyte or so.

Following the length field are the token flags byte, the signature, and the 
encrypted payload, packed together without delimiters and unencoded.

The theoretical lower limit for packet length then is 45 bytes, arranged as
follows:
  - 1 byte: binary token header
    - bit 7 is set, indicating a binary token
    - bits 6 is set to 0, there are no additional length bytes
    - bits 0-5 are set to 44, the number of token bytes to follow
  - 1 byte: header length, set to 11
  - 1 byte: flags byte
    - bit 7 is set to zero
    - bit 6 indicates whether the decrypted payload is binary or JSON
    - bits 4-5 indicate the token type (compact in this case)
    - bits 0-3 contain the key index
  - 10 bytes: MAC for a compact token
  - 16 bytes: initialization vector for encryption
  - 16 bytes: the encrypted payload, consisting of:
    - 1 byte: copy of the flags byte
    - up to 14 bytes of data
    - at least 1 byte is required for pkcs7 padding

This same token in the normal URL-safe format would require 60 bytes, a 33% 
increase over the size of the binary format. Further savings will be realized
as the length of the payload increases.

## Selective Implementation

It is expected that some implementations of this SecureToken specification will
not support all possible token types and formats. Languages that do not have a
convenient, unambiguous native type to store binary data would not necessarily
be expected to support binary tokens. Firmware for a low-cost SoC that only
supports 300 BPS communication might only worry about decoding compact-type 
binary tokens.

All implementations should be able to decode all fields in the flags byte and
issue an error if an unsupported configuration is found. Also, no changes
may be made to the defined token formats.

Crypto
------

The cryptographic choices behind the SecureToken are intended to give some
flexibility in client architecture without compromising the security or
authentication of the tokens (with one notable exception, see the discussion of
compact tokens below).

Tokens are encrypted with either AES-256 or AES-128 in CBC mode. Plaintext
payloads are padded as per PKCS-7. A new random IV is generated for each token,
and is stored alongside the ciphertext in the token. Tokens carry a message
authentication code (MAC), calculated through an HMAC algorithm based on SHA-256
or SHA-512.

The key supplied to encrypt or decrypt the token is always run through a key
derivation function before use, either HKDF-SHA512 or KDF1-SHA256; this
relieves some of the burden on the client to choose keys of a specific length
or complexity. Random salt is also usually added to the key. The MAC secret key
is based on the client-supplied key, but it is run through key derivation with
a different salt to improve resistance to future theoretical shared-key attacks.

Compact tokens are a special case, designed to minimise token length while
providing full security and somewhat weakened authenticity, improving their
performance in limited-bandwidth environments. In particular, compact tokens
contain no random salt and only a fragment (10 bytes) of the calculated MAC.

The full set of algorithms and inputs is laid out here:

* Secure Token
    - key salt: 256 random bits
    - Key derivation function: HKDF-SHA512
    - MAC key: HKDF(client key + "verify" + padded length + key salt)
    - Encryption key: HKDF(client key + "encrypt" + padded length + key salt)
    - IV: 128 random bits
    - ciphertext: payload is padded with PKCS-7, encrypted with AES-256 using 
      encryption key and IV
    - MAC: HMAC-SHA512 of ciphertext using MAC key
* Quick Token
    - key salt: 128 random bits
    - Key derivation function: KDF1
    - MAC key: KDF1(client key + "verify" + padded length + key salt)
    - Encryption key: KDF1(client key + "encrypt" + padded length + key salt)
    - IV: 128 random bits
    - ciphertext: payload is padded with PKCS-7, encrypted with AES-128 using
      encryption key and IV
    - MAC: HMAC-SHA256 of ciphertext using MAC key
* Compact Token
    - key salt: none
    - Key derivation function: KDF1
    - MAC key: KDF1(client key + "verify" + padded length)
    - Encryption key: KDF1(client key + "encrypt" + padded length)
    - IV: 128 random bits
    - ciphertext: payload is padded with PKCS-7, encrypted with AES-128 using
      encryption key and IV
    - MAC: HMAC-SHA256 (truncated to 10 bytes) of ciphertext using MAC key

The key salt and IV are publicly available in the token, and the padded length
is implied by the structure of the token.

To reduce the possibility of side channel leaks, the library will only report
success or failure of the cryptographic decoding, and will not differentiate 
any errors that may occur during authentication and decryption.

