from ipapocket.krb5.constants import EncryptionTypes
from ipapocket.krb5.crypto.base import _get_etype_profile


def string_to_key(etype, data, salt, params=None):
    """
    Convert data to Key
    """
    if isinstance(data, str):
        data = data.encode()
    e = _get_etype_profile(etype)
    return e.string_to_key(data, salt, params)


def supported_enctypes() -> list[EncryptionTypes]:
    enctypes = list()
    enctypes.append(EncryptionTypes.AES128_CTS_HMAC_SHA1_96)
    enctypes.append(EncryptionTypes.AES256_CTS_HMAC_SHA1_96)
    enctypes.append(EncryptionTypes.AES128_CTS_HMAC_SHA256_128)
    enctypes.append(EncryptionTypes.AES256_CTS_HMAC_SHA384_192)
    return enctypes
