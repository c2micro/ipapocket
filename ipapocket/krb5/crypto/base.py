from ipapocket.exceptions.exceptions import (
    InvalidSeedSize,
    InvalidChecksum,
    InvalidKeyLength,
    UnknownEtype,
)
from ipapocket.krb5.crypto.utils import (
    _nfold,
    _zeropad,
    _random_bytes,
    _mac_equal,
    basic_decrypt_all_aes,
    basic_encrypt_all_aes,
)
from Cryptodome.Hash import HMAC, SHA1, SHA256, SHA384
from Cryptodome.Protocol.KDF import PBKDF2
import struct
from ipapocket.krb5.constants import EncryptionTypes


class Key(object):
    def __init__(self, etype: EncryptionTypes, data):
        e = _get_etype_profile(etype)
        if len(data) != e.keysize and len(data) != e.macsize:
            raise InvalidKeyLength(len(data))
        self.enctype = etype
        self.contents = data


class _EtypeBaseProfile(object):
    """
    Base class for different types of encryptions
    All childrens must have:
        - etype: enctyprion number from RFC
        - keysize: size of key in bytes
        - seedsize: size of seed in bytes
    """

    @classmethod
    def random_to_key(self, seed):
        if len(seed) != self.seedsize:
            raise InvalidSeedSize(seed, self.seedsize)
        return Key(self.etype, seed)


class _EtypeRfc3961Profile(_EtypeBaseProfile):
    """
    Class to implement base encryption profiles by https://www.rfc-editor.org/rfc/rfc3961#section-3
    """

    @classmethod
    def derive(cls, key, constant):
        # RFC 3961 only says to n-fold the constant only if it is
        # shorter than the cipher block size.  But all Unix
        # implementations n-fold constants if their length is larger
        # than the block size as well, and n-folding when the length
        # is equal to the block size is a no-op.
        plaintext = _nfold(constant, cls.blocksize)
        rndseed = b""
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        return cls.random_to_key(rndseed[0 : cls.seedsize])

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ki = cls.derive(key, struct.pack(">IB", keyusage, 0x55))
        ke = cls.derive(key, struct.pack(">IB", keyusage, 0xAA))
        if confounder is None:
            confounder = _random_bytes(cls.blocksize)
        basic_plaintext = confounder + _zeropad(plaintext, cls.padsize)
        hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
        return cls.basic_encrypt(ke, basic_plaintext) + hmac[: cls.macsize]

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        ki = cls.derive(key, struct.pack(">IB", keyusage, 0x55))
        ke = cls.derive(key, struct.pack(">IB", keyusage, 0xAA))
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError("ciphertext too short")
        basic_ctext, mac = bytearray(ciphertext[: -cls.macsize]), bytearray(
            ciphertext[-cls.macsize :]
        )
        if len(basic_ctext) % cls.padsize != 0:
            raise ValueError("ciphertext does not meet padding requirement")
        basic_plaintext = cls.basic_decrypt(ke, bytes(basic_ctext))
        hmac = bytearray(HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest())
        expmac = hmac[: cls.macsize]
        if not _mac_equal(mac, expmac):
            raise InvalidChecksum("ciphertext integrity failure")
        # Discard the confounder.
        return bytes(basic_plaintext[cls.blocksize :])

    @classmethod
    def prf(cls, key, string):
        # Hash the input.  RFC 3961 says to truncate to the padding
        # size, but implementations truncate to the block size.
        hashval = cls.hashmod.new(string).digest()
        truncated = hashval[: -(len(hashval) % cls.blocksize)]
        # Encrypt the hash with a derived key.
        kp = cls.derive(key, b"prf")
        return cls.basic_encrypt(kp, truncated)


class _AesXXXSha1(_EtypeRfc3961Profile):
    blocksize = 16
    padsize = 1
    macsize = 12
    hashmod = SHA1

    @classmethod
    def string_to_key(self, string, salt, params):
        if not isinstance(string, bytes):
            string = string.encode("utf-8")
        if not isinstance(salt, bytes):
            salt = salt.encode("utf-8")

        (iterations,) = struct.unpack(">L", params or b"\x00\x00\x10\x00")
        prf = lambda p, s: HMAC.new(p, s, SHA1).digest()
        seed = PBKDF2(string, salt, self.seedsize, iterations, prf)
        tkey = self.random_to_key(seed)
        return self.derive(tkey, b"kerberos")

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        iv = bytes(cls.blocksize)
        return basic_encrypt_all_aes(cls, key, plaintext, iv)

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        iv = bytes(cls.blocksize)
        return basic_decrypt_all_aes(cls, key, ciphertext, iv)


class _AES128_SHA1(_AesXXXSha1):
    etype = EncryptionTypes.AES128_CTS_HMAC_SHA1_96
    keysize = 16
    seedsize = 16
    hashmod = SHA1


class _AES256_SHA1(_AesXXXSha1):
    etype = EncryptionTypes.AES128_CTS_HMAC_SHA256_128
    keysize = 32
    seedsize = 32
    hashmod = SHA1


class _AES128_SHA256:
    etype = EncryptionTypes.AES128_CTS_HMAC_SHA256_128
    seedsize = 256 // 8
    macsize = 128 // 8
    keysize = 128 // 8
    hashmod = SHA256


class _AES256_SHA384:
    etype = EncryptionTypes.AES256_CTS_HMAC_SHA384_192
    seedsize = 384 // 8
    macsize = 192 // 8
    keysize = 256 // 8
    hashmod = SHA384


def _get_etype_profile(etype: EncryptionTypes):
    """
    Get encryption class (profile)
    """
    if etype not in _etype_table:
        raise UnknownEtype(etype.name)
    return _etype_table[etype]


# dictionary to hold classes for enctypriont
_etype_table: dict = {
    EncryptionTypes.AES128_CTS_HMAC_SHA1_96: _AES128_SHA1,
    # EncryptionTypes.AES128_CTS_HMAC_SHA256_128: _AES128_SHA256,
    # EncryptionTypes.AES256_CTS_HMAC_SHA1_96: _AES256_SHA1,
    # EncryptionTypes.AES256_CTS_HMAC_SHA384_192: _AES256_SHA384,
}
