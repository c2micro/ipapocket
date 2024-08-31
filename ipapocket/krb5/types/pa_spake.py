from ipapocket.krb5.types.spake_challenge import SpakeChallenge
from ipapocket.krb5.types.spake_response import SpakeResponse
from ipapocket.krb5.types.encrypted_data import EncryptedData
from ipapocket.krb5.constants.fields import (
    PA_SPAKE_CHALLENGE,
    PA_SPAKE_ENCDATA,
    PA_SPAKE_RESPONSE,
    PA_SPAKE_SUPPORT,
)
from ipapocket.krb5.asn1 import (
    PaSpakeAsn1,
    SpakeResponseAsn1,
    SpakeChallengeAsn1,
    EncryptedDataAsn1,
)


class PaSpake:
    _support = None
    _challenge: SpakeChallenge = None
    _response: SpakeResponse = None
    _encdata: EncryptedData = None

    def is_support(self) -> bool:
        return self.support is not None

    def is_challange(self) -> bool:
        return self.challenge is not None

    def is_response(self) -> bool:
        return self.response is not None

    def is_encdata(self) -> bool:
        return self.encdata is not None

    @property
    def support(self):
        return self._support

    @support.setter
    def support(self, value) -> None:
        self._support = value

    @property
    def challenge(self) -> SpakeChallenge:
        return self._challenge

    @challenge.setter
    def challenge(self, value) -> None:
        self._challenge = value

    @property
    def response(self) -> SpakeResponse:
        return self._response

    @response.setter
    def response(self, value) -> None:
        self._response = value

    @property
    def encdata(self) -> EncryptedData:
        return self._encdata

    @encdata.setter
    def encdata(self, value) -> None:
        self._encdata = value

    @classmethod
    def load(cls, data: PaSpakeAsn1):
        if isinstance(data, bytes):
            data = PaSpakeAsn1.load(data)
        tmp = cls()
        if data.name == PA_SPAKE_SUPPORT:
            # TODO
            tmp.support = None
            return tmp
        elif data.name == PA_SPAKE_CHALLENGE:
            tmp.challenge = SpakeChallenge.load(data.chosen)
            return tmp
        elif data.name == PA_SPAKE_RESPONSE:
            # TODO
            tmp.response = SpakeResponse.load(data.chosen)
            return tmp
        elif data.name == PA_SPAKE_ENCDATA:
            tmp.encdata = EncryptedData.load(data.chosen)
            return tmp
        else:
            raise  # TODO

    # TODO - validate
    def to_asn1(self) -> PaSpakeAsn1:
        if self.is_response:
            return PaSpakeAsn1.load(self.response.dump())

    def dump(self):
        return self.to_asn1().dump()
