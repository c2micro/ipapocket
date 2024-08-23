import enum


# https://www.opencore.com/blog/2017/3/kerberos-encryption-types/
# https://web.mit.edu/kerberos/krb5-devel/doc/admin/enctypes.html
# https://www.freeipa.org/page/Releases/4.8.0#highlights-in-4-8-0 (using only AES types since 4.8.0)
# https://www.freeipa.org/page/Releases/4.8.2#enhancements (default AES 256/384 since 4.8.2)
# Only types, that are used in FreeIPA (without deprecated)
class EncryptionType(enum.Enum):
    DES3_CBC_SHA1 = 16  # Triple DES cbc mode with HMAC/sha1
    AES128_CTS_HMAC_SHA1_96 = 17  # AES-128 CTS mode with 96-bit SHA-1 HMAC (https://www.rfc-editor.org/rfc/rfc3962)
    AES256_CTS_HMAC_SHA1_96 = 18  # AES-256 CTS mode with 96-bit SHA-1 HMAC (https://www.rfc-editor.org/rfc/rfc3962)
    AES128_CTS_HMAC_SHA256_128 = 19  # AES-128 CTS mode with 128-bit SHA-256 HMAC (https://www.rfc-editor.org/rfc/rfc8009)
    AES256_CTS_HMAC_SHA384_192 = 20  # AES-256 CTS mode with 192-bit SHA-384 HMAC (https://www.rfc-editor.org/rfc/rfc8009)
    ARCFOUR_HMAC = 23  # ArcFour with HMAC/md5 (https://www.rfc-editor.org/rfc/rfc4757)
    CAMELLIA128_CTS_CMAC = 25  # Camellia-128 CTS mode with CMAC (https://www.rfc-editor.org/rfc/rfc6803.html)
    CAMELLIA256_CTS_CMAC = 26  # Camellia-256 CTS mode with CMAC (https://www.rfc-editor.org/rfc/rfc6803.html)
