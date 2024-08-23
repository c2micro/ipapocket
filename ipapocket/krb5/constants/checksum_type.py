import enum


# https://github.com/krb5/krb5/blob/master/src/include/krb5/krb5.hin#L442
# Only types, that are used in FreeIPA (without unkeyed/deprecated)
class ChecksumType(enum.Enum):
    HMAC_SHA1_96_AES128 = 15  # https://www.rfc-editor.org/rfc/rfc3962
    HMAC_SHA1_96_AES256 = 16  # https://www.rfc-editor.org/rfc/rfc3962
    CMAC_CAMELLIA128 = 17  # https://www.rfc-editor.org/rfc/rfc6803.html
    CMAC_CAMELLIA256 = 18  # https://www.rfc-editor.org/rfc/rfc6803.html
    HMAC_SHA256_128_AES128 = 19  # https://www.rfc-editor.org/rfc/rfc8009
    HMAC_SHA384_192_AES256 = 20  # https://www.rfc-editor.org/rfc/rfc8009
