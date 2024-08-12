import unittest
from ipapocket.krb5.objects import *
from ipapocket.krb5.constants import *


class TestPrincipalNameObject(unittest.TestCase):
    def test_none(self):
        pn = PrincipalName()
        self.assertEqual(pn.name_type, None)
        self.assertEqual(pn.name_value, KerberosStrings())

    def test_type(self):
        self.assertEqual(
            PrincipalName(PrincipalType.NT_PRINCIPAL).name_type,
            PrincipalType.NT_PRINCIPAL,
        )

    def test_value(self):
        self.assertEqual(
            PrincipalName(value=["admin", "ipa.test"]).name_value,
            KerberosStrings(["admin", "ipa.test"]),
        )

    def test_eq(self):
        pn01 = PrincipalName(PrincipalType.NT_SRV_HST, "IPA.TEST.LOCAL")
        pn02 = PrincipalName(PrincipalType.NT_PRINCIPAL, "admin@test.local")
        pn03 = PrincipalName(PrincipalType.NT_SRV_HST, "IPA.TEST.LOCAL")
        self.assertNotEqual(pn01, pn02)
        self.assertEqual(pn01, pn03)
        self.assertNotEqual(pn02, pn03)

    def test_asn1_native(self):
        self.assertEqual(
            dict(PrincipalName(PrincipalType.NT_PRINCIPAL, "admin").to_asn1().native),
            {
                PRINCIPAL_NAME_NAME_TYPE: PrincipalType.NT_PRINCIPAL.value,
                PRINCIPAL_NAME_NAME_STRING: ["admin"],
            },
        )
