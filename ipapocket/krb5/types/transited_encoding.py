from ipapocket.krb5.types.int32 import Int32
from ipapocket.krb5.asn1 import TransitedEncodingAsn1
from ipapocket.krb5.constants.fields import (
    TRANSITED_ENCODING_CONTENTS,
    TRANSITED_ENCODING_TR_TYPE,
)


class TransitedEncoding:
    _tr_type: Int32 = None
    _contents: str = None

    @property
    def tr_type(self) -> Int32:
        return self._tr_type

    @tr_type.setter
    def tr_type(self, value) -> None:
        self._tr_type = value

    @property
    def contents(self) -> str:
        return self._contents

    @contents.setter
    def contents(self, value) -> None:
        self._contents = value

    @classmethod
    def load(cls, data: TransitedEncodingAsn1):
        if isinstance(data, TransitedEncoding):
            data = data.to_asn1()
        tmp = cls()
        if TRANSITED_ENCODING_TR_TYPE in data:
            if data[TRANSITED_ENCODING_TR_TYPE].native is not None:
                tmp.tr_type = Int32.load(data[TRANSITED_ENCODING_TR_TYPE])
        if TRANSITED_ENCODING_CONTENTS in data:
            if data[TRANSITED_ENCODING_CONTENTS].native is not None:
                tmp.contents = data[TRANSITED_ENCODING_CONTENTS].native
        return tmp

    def to_asn1(self) -> TransitedEncodingAsn1:
        transited_encoding = TransitedEncoding()
        if self.tr_type is not None:
            transited_encoding[TRANSITED_ENCODING_TR_TYPE] = self.tr_type.to_asn1()
        if self.contents is not None:
            transited_encoding[TRANSITED_ENCODING_CONTENTS] = self.contents
        return transited_encoding
