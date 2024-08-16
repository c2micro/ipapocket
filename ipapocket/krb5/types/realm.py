from ipapocket.krb5.asn1 import RealmAsn1
from ipapocket.exceptions.krb5 import InvalidRealmValue
from ipapocket.krb5.types.kerberos_string import KerberosString


class Realm:
    _realm: KerberosString = None

    def __init__(self, realm=None):
        self.realm = realm

    @classmethod
    def load(cls, data: RealmAsn1):
        """
        Create object of Realm from ASN1 structure
        """
        if isinstance(data, Realm):
            data = data.to_asn1()
        return cls(realm=data.native)

    def _validate_realm(self, realm) -> KerberosString:
        if realm is None:
            return KerberosString()
        if isinstance(realm, str):
            return KerberosString(realm)
        elif isinstance(realm, KerberosString):
            return realm
        else:
            raise InvalidRealmValue(realm)

    @property
    def realm(self) -> KerberosString:
        return self._realm

    @realm.setter
    def realm(self, realm) -> None:
        self._realm = self._validate_realm(realm)

    def __eq__(self, obj):
        """
        Compare instances of Realm objects
        """
        if isinstance(obj, Realm):
            return self.realm == obj.realm
        else:
            return False

    def to_asn1(self) -> RealmAsn1:
        """
        Convert object to ASN1 structure
        """
        return RealmAsn1(self._realm.to_asn1().native)

    def dump(self) -> bytes:
        """
        Dump object to bytes (with ASN1 structure)
        """
        return self.to_asn1().dump()
