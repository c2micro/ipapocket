from ipapocket.krb5.constants import EncryptionType, KeyUsageType
from ipapocket.krb5.crypto.backend import (
    get_etype_profile,
    get_cksum_profile,
    cksum_for_etype,
    Key,
)


def string_to_key(etype: EncryptionType, data, salt, params=None):
    """
    Convert data to Key
    """
    if isinstance(data, str):
        data = data.encode()
    if isinstance(salt, str):
        salt = salt.encode()
    e = get_etype_profile(etype)
    return e.string_to_key(data, salt, params)


def checksum(key: Key, keyusage, data):
    """
    Calculate checksum for given type
    """
    c = get_cksum_profile(cksum_for_etype(key.enctype))
    if isinstance(keyusage, KeyUsageType):
        keyusage = keyusage.value
    return c.checksum(key, keyusage, data)


def encrypt(key: Key, keyusage, data):
    """
    Encrypt data with given type
    """
    e = get_etype_profile(key.enctype)
    if isinstance(keyusage, KeyUsageType):
        keyusage = keyusage.value
    return e.encrypt(key, keyusage, data)


def decrypt(key: Key, keyusage, data):
    """
    Decrypt data with given type
    """
    e = get_etype_profile(key.enctype)
    if isinstance(keyusage, KeyUsageType):
        keyusage = keyusage.value
    return e.decrypt(key, keyusage, data)


def supported_etypes() -> list[EncryptionType]:
    """
    List of supported etypes (by client)
    """
    enctypes = list()
    enctypes.append(EncryptionType.ARCFOUR_HMAC)
    enctypes.append(EncryptionType.AES128_CTS_HMAC_SHA1_96)
    enctypes.append(EncryptionType.AES256_CTS_HMAC_SHA1_96)
    enctypes.append(EncryptionType.AES128_CTS_HMAC_SHA256_128)
    enctypes.append(EncryptionType.AES256_CTS_HMAC_SHA384_192)
    return enctypes
