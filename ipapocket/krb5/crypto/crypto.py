from ipapocket.krb5.constants import EncryptionTypes, KeyUsageTypes
from ipapocket.krb5.crypto.backend import (
    _get_etype_profile,
    _get_cksum_profile,
    _cksum_for_etype,
    Key,
)


def string_to_key(etype: EncryptionTypes, data, salt, params=None):
    """
    Convert data to Key
    """
    if isinstance(data, str):
        data = data.encode()
    if isinstance(salt, str):
        salt = salt.encode()
    e = _get_etype_profile(etype)
    return e.string_to_key(data, salt, params)


def checksum(key: Key, keyusage, data):
    """
    Calculate checksum for given type
    """
    c = _get_cksum_profile(_cksum_for_etype(key.enctype))
    if isinstance(keyusage, KeyUsageTypes):
        keyusage = keyusage.value
    return c.checksum(key, keyusage, data)


def encrypt(key: Key, keyusage, data):
    """
    Encrypt data with given type
    """
    e = _get_etype_profile(key.enctype)
    if isinstance(keyusage, KeyUsageTypes):
        keyusage = keyusage.value
    return e.encrypt(key, keyusage, data)


def decrypt(key: Key, keyusage, data):
    """
    Decrypt data with given type
    """
    e = _get_etype_profile(key.enctype)
    if isinstance(keyusage, KeyUsageTypes):
        keyusage = keyusage.value
    return e.decrypt(key, keyusage, data)


def supported_etypes() -> list[EncryptionTypes]:
    """
    List of supported etypes (by client)
    """
    enctypes = list()
    enctypes.append(EncryptionTypes.ARCFOUR_HMAC)
    enctypes.append(EncryptionTypes.AES128_CTS_HMAC_SHA1_96)
    enctypes.append(EncryptionTypes.AES256_CTS_HMAC_SHA1_96)
    enctypes.append(EncryptionTypes.AES128_CTS_HMAC_SHA256_128)
    enctypes.append(EncryptionTypes.AES256_CTS_HMAC_SHA384_192)
    return enctypes
