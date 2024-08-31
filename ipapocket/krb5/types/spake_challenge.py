from ipapocket.krb5.constants import SpakeGroupType
from ipapocket.krb5.types.spake_second_factors import SpakeSecondFactors
from ipapocket.krb5.asn1 import SpakeChallengeAsn1
from ipapocket.krb5.constants.fields import (
    SPAKE_CHALLENGE_FACTORS,
    SPAKE_CHALLENGE_GROUP,
    SPAKE_CHALLENGE_PUBKEY,
)


class SpakeChallenge:
    _group: SpakeGroupType = None
    _pubkey: str = None
    _factors: SpakeSecondFactors = None

    @property
    def group(self) -> SpakeGroupType:
        return self._group

    @group.setter
    def group(self, value) -> None:
        self._group = value

    @property
    def pubkey(self) -> str:
        return self._pubkey

    @pubkey.setter
    def pubkey(self, value) -> None:
        self._pubkey = value

    @property
    def factors(self) -> SpakeSecondFactors:
        return self._factors

    @factors.setter
    def factors(self, value) -> None:
        self._factors = value

    @classmethod
    def load(cls, data: SpakeChallengeAsn1):
        if isinstance(data, SpakeChallenge):
            data = data.to_asn1()
        if isinstance(data, bytes):
            data = SpakeChallengeAsn1.load(data)
        tmp = cls()
        if SPAKE_CHALLENGE_GROUP in data:
            if data[SPAKE_CHALLENGE_GROUP].native is not None:
                tmp.group = SpakeGroupType(data[SPAKE_CHALLENGE_GROUP].native)
        if SPAKE_CHALLENGE_PUBKEY in data:
            if data[SPAKE_CHALLENGE_PUBKEY].native is not None:
                tmp.pubkey = data[SPAKE_CHALLENGE_PUBKEY].native
        if SPAKE_CHALLENGE_FACTORS in data:
            if data[SPAKE_CHALLENGE_FACTORS].native is not None:
                tmp.factors = SpakeSecondFactors.load(data[SPAKE_CHALLENGE_FACTORS])
        return tmp

    def to_asn1(self) -> SpakeChallengeAsn1:
        tmp = SpakeChallengeAsn1()
        if self.group is not None:
            tmp[SPAKE_CHALLENGE_GROUP] = self.group.value
        if self.pubkey is not None:
            tmp[SPAKE_CHALLENGE_PUBKEY] = self.pubkey
        if self.factors is not None:
            tmp[SPAKE_CHALLENGE_FACTORS] = self.factors.to_asn1()
        return tmp

    def dump(self) -> bytes:
        return self.to_asn1().dump()
