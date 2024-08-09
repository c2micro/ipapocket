from functools import reduce
from Cryptodome.Util.number import GCD as gcd
from os import urandom
from Cryptodome.Cipher import AES


def _random_bytes(lenBytes: int) -> bytes:
    # We don't really need super strong randomness here to use PyCrypto.Random
    return urandom(lenBytes)


def _zeropad(s, padsize):
    # Return s padded with 0 bytes to a multiple of padsize.
    padlen = (padsize - (len(s) % padsize)) % padsize
    return s + b"\0" * padlen


def _nfold(ba, nbytes):
    # Convert bytearray to a string of length nbytes using the RFC 3961 nfold
    # operation.

    # Rotate the bytes in ba to the right by nbits bits.
    def rotate_right(ba, nbits):
        ba = bytearray(ba)
        nbytes, remain = (nbits // 8) % len(ba), nbits % 8
        return bytearray(
            (ba[i - nbytes] >> remain) | ((ba[i - nbytes - 1] << (8 - remain)) & 0xFF)
            for i in range(len(ba))
        )

    # Add equal-length strings together with end-around carry.
    def add_ones_complement(str1, str2):
        n = len(str1)
        v = [a + b for a, b in zip(str1, str2)]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xFF for x in v):
            v = [(v[i - n + 1] >> 8) + (v[i] & 0xFF) for i in range(n)]
        return bytearray(x for x in v)

    # Concatenate copies of str to produce the least common multiple
    # of len(str) and nbytes, rotating each copy of str to the right
    # by 13 bits times its list position.  Decompose the concatenation
    # into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slen = len(ba)
    lcm = nbytes * slen // gcd(nbytes, slen)
    bigstr = bytearray()
    for i in range(lcm // slen):
        bigstr += rotate_right(ba, 13 * i)
    slices = (bigstr[p : p + nbytes] for p in range(0, lcm, nbytes))
    return bytes(reduce(add_ones_complement, slices))


def _mac_equal(mac1, mac2):
    # Constant-time comparison function.  (We can't use HMAC.verify
    # since we use truncated macs.)
    assert len(mac1) == len(mac2)
    res = 0
    for x, y in zip(mac1, mac2):
        res |= x ^ y
    return res == 0


def _xorbytes(b1, b2):
    # xor two strings together and return the resulting string.
    assert len(b1) == len(b2)
    return bytearray((x ^ y) for x, y in zip(b1, b2))


def basic_encrypt_all_aes(cls, key, plaintext, iv):
    bs = cls.blocksize
    assert len(plaintext) >= bs
    aes = AES.new(key.contents, AES.MODE_CBC, iv)
    ctext = aes.encrypt(_zeropad(bytes(plaintext), bs))
    if len(plaintext) > bs:
        # Swap the last two ciphertext blocks and truncate the
        # final block to match the plaintext length.
        lastlen = len(plaintext) % bs or bs
        ctext = ctext[: -(bs * 2)] + ctext[-bs:] + ctext[-(bs * 2) : -bs][:lastlen]
    return ctext


def basic_decrypt_all_aes(cls, key, ciphertext, iv):
    bs = cls.blocksize
    assert len(ciphertext) >= bs
    aes = AES.new(key.contents, AES.MODE_ECB)
    if len(ciphertext) == bs:
        return aes.decrypt(ciphertext)
    # Split the ciphertext into blocks.  The last block may be partial.
    cblocks = [bytearray(ciphertext[p : p + bs]) for p in range(0, len(ciphertext), bs)]
    lastlen = len(cblocks[-1])
    # CBC-decrypt all but the last two blocks.
    prev_cblock = bytearray(iv)
    plaintext = b""
    for bb in cblocks[:-2]:
        plaintext += _xorbytes(bytearray(aes.decrypt(bytes(bb))), prev_cblock)
        prev_cblock = bb
    # Decrypt the second-to-last cipher block.  The left side of
    # the decrypted block will be the final block of plaintext
    # xor'd with the final partial cipher block; the right side
    # will be the omitted bytes of ciphertext from the final
    # block.
    bb = bytearray(aes.decrypt(bytes(cblocks[-2])))
    lastplaintext = _xorbytes(bb[:lastlen], cblocks[-1])
    omitted = bb[lastlen:]
    # Decrypt the final cipher block plus the omitted bytes to get
    # the second-to-last plaintext block.
    plaintext += _xorbytes(
        bytearray(aes.decrypt(bytes(cblocks[-1]) + bytes(omitted))), prev_cblock
    )
    return plaintext + lastplaintext
