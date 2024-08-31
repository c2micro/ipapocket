from ipapocket.exceptions.exceptions import (
    InvalidSeedSize,
    InvalidChecksum,
    InvalidKeyLength,
    UnknownEtype,
    UnknownGroup,
    UnknownChecksumType,
)
from ipapocket.krb5.crypto.utils import (
    _nfold,
    _zeropad,
    _random_bytes,
    _mac_equal,
    _xorbytes,
    basic_decrypt_all_aes,
    basic_encrypt_all_aes,
)
from Cryptodome.Hash import HMAC, SHA1, SHA256, SHA384, SHA512
from Cryptodome.Protocol.KDF import PBKDF2
from ipapocket.krb5.crypto.sp800 import SP800_108_Counter
import struct
from binascii import unhexlify
from ipapocket.krb5.constants import EncryptionType, ChecksumType, SpakeGroupType
from ipapocket.krb5.crypto.ed25519.basic import *
import os


class Key(object):
    def __init__(self, enctype: EncryptionType, data):
        if isinstance(enctype, int):
            enctype = EncryptionType(enctype)
        e = get_etype_profile(enctype)
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
    def encrypt(cls, key, keyusage, plaintext, confounder=None):
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
    def prf(cls, key: Key, string):
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

    @classmethod
    def prf_plus(cls, key: Key, pepper: str, multiplier: int):
        nblocks = int((multiplier + cls.blocksize - 1) / cls.blocksize)
        w = b""
        for i in range(nblocks):
            w += cls.prf(key, (i + 1).to_bytes() + pepper)
        return w


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
    def basic_decrypt(cls, key: Key, ciphertext, iv):
        return basic_decrypt_all_aes(cls, key, ciphertext, iv)

    @classmethod
    def kdf_hmac_sha2(cls, key: Key, label, k, context=b""):
        hmac_sha2 = lambda p, s: HMAC.new(p, s, cls.hashmod).digest()
        return SP800_108_Counter(
            master=key, key_len=k, prf=hmac_sha2, label=label, context=context
        )

    @classmethod
    def derive(cls, key: Key, constant):
        return cls.random_to_key(
            cls.kdf_hmac_sha2(key=key.contents, label=constant, k=cls.macsize)
        )

    @classmethod
    def prf(cls, input_key: Key, string):
        return cls.kdf_hmac_sha2(
            key=input_key.contents, label=b"prf", k=cls.seedsize, context=string
        )

    @classmethod
    def prf_plus(cls, key: Key, pepper: str, multiplier: int):
        nblocks = int((multiplier + cls.seedsize - 1) / cls.seedsize)
        w = b""
        for i in range(nblocks):
            w += cls.prf(key, (i + 1).to_bytes() + pepper)
        return w

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
    def encrypt(cls, key, keyusage, plaintext, confounder=None):
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
    enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96
    keysize = 16
    seedsize = 16
    hashmod = SHA1


class _SHA1_AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128_SHA1


class _AES256_SHA1(_EtypeRfc3962):
    enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
    keysize = 32
    seedsize = 32
    hashmod = SHA1


class _SHA1_AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256_SHA1


class _AES128_SHA256(_EtypeRfc8009):
    enctype = EncryptionType.AES128_CTS_HMAC_SHA256_128
    seedsize = 256 // 8
    macsize = 128 // 8
    keysize = 128 // 8
    hashmod = SHA256
    enctype_name = b"aes128-cts-hmac-sha256-128"


class _SHA256_AES128(_SimplifiedChecksum):
    macsize = _AES128_SHA256.macsize
    enc = _AES128_SHA256


class _AES256_SHA384(_EtypeRfc8009):
    enctype = EncryptionType.AES256_CTS_HMAC_SHA384_192
    seedsize = 384 // 8
    macsize = 192 // 8
    keysize = 256 // 8
    hashmod = SHA384
    enctype_name = b"aes256-cts-hmac-sha384-192"


class _SHA384_AES256(_SimplifiedChecksum):
    macsize = _AES256_SHA384.macsize
    enc = _AES256_SHA384


class _GroupBaseProfile:
    g: SpakeGroupType

    @classmethod
    def derive_wbytes(cls, key: Key):
        pepper = b"SPAKEsecret" + cls.g.value.to_bytes(4, byteorder="big")
        return cls.prf_plus(key, pepper, key.enctype)

    @classmethod
    def prf_plus(cls, key: Key, pepper: str, enctype: EncryptionType):
        etype = get_etype_profile(enctype)
        return etype.prf_plus(key, pepper, cls.mlen)

    @classmethod
    def derive_ik(
        cls, etype: EncryptionType, n: int, blob: str, w: str, K: str, thash: str
    ):
        e = get_etype_profile(etype)
        nblock = int(
            (e.seedsize + cls.hashmod.digest_size - 1) / cls.hashmod.digest_size
        )
        ik = b""
        raw = (
            b"SPAKEkey"
            + cls.g.value.to_bytes(4, byteorder="big")
            + etype.value.to_bytes(4, byteorder="big")
            + w
            + K
            + thash
            + blob
            + n.to_bytes(4, byteorder="big")
        )
        for i in range(nblock):
            ik += cls.hashmod.new(raw + (i + 1).to_bytes(1)).digest()
        return e.random_to_key(ik[: e.seedsize])

    @classmethod
    def derive_k0(cls, key: Key, kdc_rbody: str, w: str, K: str, thash: str) -> Key:
        """
        Derive K'[0]
        """
        # get intermediate key for future derivation
        ik = cls.derive_ik(key.enctype, 0, kdc_rbody, w, K, thash)
        e = get_etype_profile(key.enctype)
        # # krb_fx_cf2
        k1 = e.prf_plus(key, b"SPAKE", e.seedsize)
        k2 = e.prf_plus(ik, b"keyderiv", e.seedsize)
        return get_etype_profile(key.enctype).random_to_key(bytes(_xorbytes(k1, k2)))

    @classmethod
    def derive_k1(cls, key: Key, kdc_rbody: str, w: str, K: str, thash: str) -> Key:
        """
        Derive K'[1]
        """
        # get intermediate key for future derivation
        ik = cls.derive_ik(key.enctype, 1, kdc_rbody, w, K, thash)
        e = get_etype_profile(key.enctype)
        # # krb_fx_cf2
        k1 = e.prf_plus(key, b"SPAKE", e.seedsize)
        k2 = e.prf_plus(ik, b"keyderiv", e.seedsize)
        return get_etype_profile(key.enctype).random_to_key(bytes(_xorbytes(k1, k2)))

    @classmethod
    def derive_k2(cls, key: Key, kdc_rbody: str, w: str, K: str, thash: str) -> Key:
        """
        Derive K'[2]
        """
        # get intermediate key for future derivation
        ik = cls.derive_ik(key.enctype, 2, kdc_rbody, w, K, thash)
        e = get_etype_profile(key.enctype)
        # # krb_fx_cf2
        k1 = e.prf_plus(key, b"SPAKE", e.seedsize)
        k2 = e.prf_plus(ik, b"keyderiv", e.seedsize)
        return get_etype_profile(key.enctype).random_to_key(bytes(_xorbytes(k1, k2)))

    @classmethod
    def derive_k3(cls, key: Key, kdc_rbody: str, w: str, K: str, thash: str) -> Key:
        """
        Derive K'[3]
        """
        # get intermediate key for future derivation
        ik = cls.derive_ik(key.enctype, 3, kdc_rbody, w, K, thash)
        e = get_etype_profile(key.enctype)
        # # krb_fx_cf2
        k1 = e.prf_plus(key, b"SPAKE", e.seedsize)
        k2 = e.prf_plus(ik, b"keyderiv", e.seedsize)
        return get_etype_profile(key.enctype).random_to_key(bytes(_xorbytes(k1, k2)))


class _GroupRfc8032(_GroupBaseProfile):
    """
    Implementation for Edwards25519 ECC
    """

    @classmethod
    def calculate_public(cls, wbytes: str):
        # generate client y
        y = random_scalar(os.urandom)
        w = bytes_to_scalar(wbytes)
        S = Base.scalarmult(y).add(bytes_to_element(cls.n).scalarmult(w))
        return S.to_bytes(), scalar_to_bytes(y)

    @classmethod
    def calculate_shared(cls, kdc_public: str, y_b: str, wbytes: str):
        y = bytes_to_scalar(y_b)
        T = bytes_to_element(kdc_public)
        w = bytes_to_scalar(wbytes)
        return T.add(bytes_to_element(cls.m).scalarmult(-w)).scalarmult(y).to_bytes()


class _EDWARDS25519_SHA256(_GroupRfc8032):
    name = b"edwards25519"
    base = 256
    mlen = 32  # multiplier length
    m = unhexlify("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
    n = unhexlify("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")
    hashmod = SHA256
    g = SpakeGroupType.EDWARDS25519


class _P256_SHA256:
    name = b"P-256"
    mlen = 32
    m = unhexlify("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
    n = unhexlify("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
    hashmod = SHA256
    g = SpakeGroupType.P256


class _P384_SHA384:
    name = b"P-384"
    mlen = 48
    m = unhexlify(
        "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853"
    )
    n = unhexlify(
        "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"
    )
    hashmod = SHA384
    g = SpakeGroupType.P384


class _P521_SHA512:
    name = b"P-512"
    mlen = 48
    m = unhexlify(
        "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"
    )
    n = unhexlify(
        "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"
    )
    hashmod = SHA512
    g = SpakeGroupType.P521


def get_etype_profile(
    etype: EncryptionType,
) -> _AES128_SHA1 | _AES128_SHA256 | _AES256_SHA1 | _AES256_SHA384:
    """
    Get encryption class (profile)
    """
    if isinstance(etype, int):
        etype = EncryptionType(etype)
    if etype not in _etype_table:
        raise UnknownEtype(etype)
    return _etype_table[etype]


def get_group_profile(group: SpakeGroupType):
    """
    Get group class (profile)
    """
    if isinstance(group, int):
        group = SpakeGroupType(group)
    if group not in _group_table:
        raise UnknownGroup(group)
    return _group_table[group]


def get_cksum_profile(cksumtype: ChecksumType):
    """
    Get checksum class (profile)
    """
    if isinstance(cksumtype, int):
        cksumtype = ChecksumType(cksumtype)
    if cksumtype not in _cksum_table:
        raise UnknownChecksumType(cksumtype)
    return _cksum_table[cksumtype]


def cksum_for_etype(etype: EncryptionType) -> ChecksumType:
    """
    Get checksum type for etype
    """
    if etype not in _etype_cksum_table:
        raise UnknownEtype(etype)
    return _etype_cksum_table[etype]


# dictionary to hold classes for encryption types
_etype_table: dict = {
    EncryptionType.AES128_CTS_HMAC_SHA1_96: _AES128_SHA1,
    EncryptionType.AES128_CTS_HMAC_SHA256_128: _AES128_SHA256,
    EncryptionType.AES256_CTS_HMAC_SHA1_96: _AES256_SHA1,
    EncryptionType.AES256_CTS_HMAC_SHA384_192: _AES256_SHA384,
}

# dictionary to hold classes for group types
_group_table: dict = {
    SpakeGroupType.EDWARDS25519: _EDWARDS25519_SHA256,
    SpakeGroupType.P256: _P256_SHA256,
    SpakeGroupType.P384: _P384_SHA384,
    SpakeGroupType.P521: _P521_SHA512,
}

# dictionary to hold classes for checksum types
_cksum_table: dict = {
    ChecksumType.HMAC_SHA1_96_AES128: _SHA1_AES128,
    ChecksumType.HMAC_SHA1_96_AES256: _SHA1_AES256,
    ChecksumType.HMAC_SHA256_128_AES128: _SHA256_AES128,
    ChecksumType.HMAC_SHA384_192_AES256: _SHA384_AES256,
}

# dictionary to hold types of checksums for encryption types
_etype_cksum_table: dict = {
    EncryptionType.AES128_CTS_HMAC_SHA1_96: ChecksumType.HMAC_SHA1_96_AES128,
    EncryptionType.AES256_CTS_HMAC_SHA1_96: ChecksumType.HMAC_SHA1_96_AES256,
    EncryptionType.AES128_CTS_HMAC_SHA256_128: ChecksumType.HMAC_SHA256_128_AES128,
    EncryptionType.AES256_CTS_HMAC_SHA384_192: ChecksumType.HMAC_SHA384_192_AES256,
}
