from ipapocket.exceptions.exceptions import (
    InvalidSeedSize,
    InvalidChecksum,
    InvalidKeyLength,
    UnknownEtype,
    UnknownChecksumType,
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
from ipapocket.krb5.crypto.sp800 import SP800_108_Counter
import struct
from ipapocket.krb5.constants import EncryptionTypes, ChecksumTypes


class Key(object):
    def __init__(self, enctype: EncryptionTypes, data):
        e = _get_etype_profile(enctype)
        if len(data) != e.keysize and len(data) != e.macsize:
            raise InvalidKeyLength(len(data))
        self.enctype = enctype
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
        return Key(self.enctype, seed)

    @classmethod
    def splitter(cls, ciphertext):
        """
        Function to split block on raw ciphertext and mac
        """
        ctext = ciphertext[: -cls.macsize]
        mac = ciphertext[-cls.macsize :]
        return ctext, mac


class _ChecksumBaseProfile(object):
    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        expected = cls.checksum(key, keyusage, text)
        if not _mac_equal(bytearray(cksum), bytearray(expected)):
            raise InvalidChecksum("checksum verification failure")


class _SimplifiedChecksum(_ChecksumBaseProfile):
    @classmethod
    def checksum(cls, key, keyusage, text):
        kc = cls.enc.derive(key, struct.pack(">IB", keyusage, 0x99))
        hmac = HMAC.new(kc.contents, text, cls.enc.hashmod).digest()
        return hmac[: cls.macsize]

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        if key.enctype != cls.enc.enctype:
            raise ValueError("Wrong key type for checksum")
        super(_SimplifiedChecksum, cls).verify(key, keyusage, text, cksum)


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
        basic_ctext, mac = cls.splitter(ciphertext)
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


class _EtypeRfc3962(_EtypeRfc3961Profile):
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


class _EtypeRfc8009(_EtypeRfc3961Profile):
    # Base class for aes128-cts-hmac-sha256-128 and aes256-cts-hmac-sha384-192.
    blocksize = 128 // 8  # Cipher block size
    seedsize = None  # PRF output size
    keysize = None  # Encryption key size
    macsize = None  # Integrity key size
    hashmod = None  # Hash function module
    enctype_name = None  # Encryption type name as byte string

    @classmethod
    def random_to_key(cls, seed):
        return Key(cls.enctype, seed)

    @classmethod
    def basic_encrypt(cls, key, plaintext, iv):
        return basic_encrypt_all_aes(cls, key, plaintext, iv)

    @classmethod
    def basic_decrypt(cls, key, ciphertext, iv):
        return basic_decrypt_all_aes(cls, key, ciphertext, iv)

    @classmethod
    def kdf_hmac_sha2(cls, key, label, k, context=b""):
        hmac_sha2 = lambda p, s: HMAC.new(p, s, cls.hashmod).digest()
        return SP800_108_Counter(
            master=key, key_len=k, prf=hmac_sha2, label=label, context=context
        )

    @classmethod
    def derive(cls, key, constant):
        return cls.random_to_key(
            cls.kdf_hmac_sha2(key=key.contents, label=constant, k=cls.macsize)
        )

    @classmethod
    def prf(cls, input_key, string):
        return cls.kdf_hmac_sha2(
            key=input_key.contents, label=b"prf", k=cls.seedsize, context=string
        )

    @classmethod
    def string_to_key(cls, string, salt, params):
        if not isinstance(string, bytes):
            string = string.encode("utf-8")
        if not isinstance(salt, bytes):
            salt = salt.encode("utf-8")

        saltp = cls.enctype_name + b"\0" + salt

        iter_count = struct.unpack(">L", params)[0] if params else 32768
        tkey = PBKDF2(
            password=string,
            salt=saltp,
            count=iter_count,
            dkLen=cls.keysize,
            hmac_hash_module=cls.hashmod,
        )
        return cls.random_to_key(
            cls.kdf_hmac_sha2(key=tkey, label=b"kerberos", k=cls.keysize)
        )

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ke = cls.random_to_key(
            cls.kdf_hmac_sha2(
                key.contents, struct.pack(">IB", keyusage, 0xAA), cls.keysize
            )
        )
        ki = cls.random_to_key(
            cls.kdf_hmac_sha2(
                key.contents, struct.pack(">IB", keyusage, 0x55), cls.macsize
            )
        )
        n = _random_bytes(cls.blocksize)
        # Initial cipher state is a zeroed buffer
        iv = bytes(cls.blocksize)
        c = cls.basic_encrypt(ke, n + plaintext, iv)
        h = HMAC.new(ki.contents, iv + c, cls.hashmod).digest()
        ciphertext = c + h[: cls.macsize]
        assert plaintext == cls.decrypt(key, keyusage, ciphertext)
        return ciphertext

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        if not isinstance(ciphertext, bytes):
            ciphertext = bytes(ciphertext)
        ke = cls.random_to_key(
            cls.kdf_hmac_sha2(
                key.contents, struct.pack(">IB", keyusage, 0xAA), cls.keysize
            )
        )
        ki = cls.random_to_key(
            cls.kdf_hmac_sha2(
                key.contents, struct.pack(">IB", keyusage, 0x55), cls.macsize
            )
        )
        c, h = cls.splitter(ciphertext)
        # Initial cipher state is a zeroed buffer
        iv = bytes(cls.blocksize)
        if h != HMAC.new(ki.contents, iv + c, cls.hashmod).digest()[: cls.macsize]:
            raise InvalidChecksum("ciphertext integrity failure")
        plaintext = cls.basic_decrypt(ke, c, iv)[cls.blocksize :]
        return plaintext


class _AES128_SHA1(_EtypeRfc3962):
    enctype = EncryptionTypes.AES128_CTS_HMAC_SHA1_96
    keysize = 16
    seedsize = 16
    hashmod = SHA1


class _SHA1_AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128_SHA1


class _AES256_SHA1(_EtypeRfc3962):
    enctype = EncryptionTypes.AES256_CTS_HMAC_SHA1_96
    keysize = 32
    seedsize = 32
    hashmod = SHA1


class _SHA1_AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256_SHA1


class _AES128_SHA256(_EtypeRfc8009):
    enctype = EncryptionTypes.AES128_CTS_HMAC_SHA256_128
    seedsize = 256 // 8
    macsize = 128 // 8
    keysize = 128 // 8
    hashmod = SHA256
    enctype_name = b"aes128-cts-hmac-sha256-128"


class _SHA256_AES128(_SimplifiedChecksum):
    macsize = _AES128_SHA256.macsize
    enc = _AES128_SHA256


class _AES256_SHA384(_EtypeRfc8009):
    enctype = EncryptionTypes.AES256_CTS_HMAC_SHA384_192
    seedsize = 384 // 8
    macsize = 192 // 8
    keysize = 256 // 8
    hashmod = SHA384
    enctype_name = b"aes256-cts-hmac-sha384-192"


class _SHA384_AES256(_SimplifiedChecksum):
    macsize = _AES256_SHA384.macsize
    enc = _AES256_SHA384


def _get_etype_profile(etype: EncryptionTypes):
    """
    Get encryption class (profile)
    """
    if etype not in _etype_table:
        raise UnknownEtype(etype)
    return _etype_table[etype]


def _get_cksum_profile(cksumtype: ChecksumTypes):
    """
    Get checksum class (profile)
    """
    if cksumtype not in _cksum_table:
        raise UnknownChecksumType(cksumtype)
    return _cksum_table[cksumtype]


def _cksum_for_etype(etype: EncryptionTypes) -> ChecksumTypes:
    """
    Get checksum type for etype
    """
    if etype not in _etype_cksum_table:
        raise UnknownEtype(etype)
    return _etype_cksum_table[etype]


# dictionary to hold classes for encryption types
_etype_table: dict = {
    EncryptionTypes.AES128_CTS_HMAC_SHA1_96: _AES128_SHA1,
    EncryptionTypes.AES128_CTS_HMAC_SHA256_128: _AES128_SHA256,
    EncryptionTypes.AES256_CTS_HMAC_SHA1_96: _AES256_SHA1,
    EncryptionTypes.AES256_CTS_HMAC_SHA384_192: _AES256_SHA384,
}

# dictionary to hold classes for checksum types
_cksum_table: dict = {
    ChecksumTypes.HMAC_SHA1_96_AES128: _SHA1_AES128,
    ChecksumTypes.HMAC_SHA1_96_AES256: _SHA1_AES256,
    ChecksumTypes.HMAC_SHA256_128_AES128: _SHA256_AES128,
    ChecksumTypes.HMAC_SHA384_192_AES256: _SHA384_AES256,
}

# dictionary to hold types of checksums for encryption types
_etype_cksum_table: dict = {
    EncryptionTypes.AES128_CTS_HMAC_SHA1_96: ChecksumTypes.HMAC_SHA1_96_AES128,
    EncryptionTypes.AES256_CTS_HMAC_SHA1_96: ChecksumTypes.HMAC_SHA1_96_AES256,
    EncryptionTypes.AES128_CTS_HMAC_SHA256_128: ChecksumTypes.HMAC_SHA256_128_AES128,
    EncryptionTypes.AES256_CTS_HMAC_SHA384_192: ChecksumTypes.HMAC_SHA384_192_AES256,
}
