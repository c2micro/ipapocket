from Cryptodome.Util.py3compat import iter_range
from Cryptodome.Util.number import long_to_bytes


def SP800_108_Counter(master, key_len, prf, num_keys=None, label=b"", context=b""):
    """Derive one or more keys from a master secret using
    a pseudorandom function in Counter Mode, as specified in
    `NIST SP 800-108r1 <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf>`_.

    Args:
     master (byte string):
        The secret value used by the KDF to derive the other keys.
        It must not be a password.
        The length on the secret must be consistent with the input expected by
        the :data:`prf` function.
     key_len (integer):
        The length in bytes of each derived key.
     prf (function):
        A pseudorandom function that takes two byte strings as parameters:
        the secret and an input. It returns another byte string.
     num_keys (integer):
        The number of keys to derive. Every key is :data:`key_len` bytes long.
        By default, only 1 key is derived.
     label (byte string):
        Optional description of the purpose of the derived keys.
        It must not contain zero bytes.
     context (byte string):
        Optional information pertaining to
        the protocol that uses the keys, such as the identity of the
        participants, nonces, session IDs, etc.
        It must not contain zero bytes.

    Return:
        - a byte string (if ``num_keys`` is not specified), or
        - a tuple of byte strings (if ``num_key`` is specified).
    """

    if num_keys is None:
        num_keys = 1

    # errors on prf_plus for aes128-sha256/aes256-sha384
    # if context.find(b"\x00") != -1:
    #    raise ValueError("Null byte found in context")

    key_len_enc = long_to_bytes(key_len * num_keys * 8, 4)
    output_len = key_len * num_keys

    i = 1
    dk = b""
    while len(dk) < output_len:
        info = long_to_bytes(i, 4) + label + b"\x00" + context + key_len_enc
        dk += prf(master, info)
        i += 1
        if i > 0xFFFFFFFF:
            raise ValueError("Overflow in SP800 108 counter")

    if num_keys == 1:
        return dk[:key_len]
    else:
        kol = [dk[idx : idx + key_len] for idx in iter_range(0, output_len, key_len)]
        return kol
