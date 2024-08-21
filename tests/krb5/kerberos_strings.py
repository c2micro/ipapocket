import unittest
from ipapocket.krb5.types import *
from ipapocket.krb5.constants import *
from ipapocket.exceptions.krb5 import *


class TestKerberosStringsObject(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(KerberosStrings().value, [])

    def test_str_value(self):
        self.assertEqual(KerberosStrings("admin").value, ["admin"])
        self.assertEqual(KerberosStrings("admin").value, [KerberosString("admin")])

    def test_list_value(self):
        self.assertEqual(
            KerberosStrings(["krbtgt", "IPA.TEST"]).value, ["krbtgt", "IPA.TEST"]
        )
        self.assertEqual(
            KerberosStrings(["krbtgt", "IPA.TEST"]).value,
            [KerberosString("krbtgt"), "IPA.TEST"],
        )
        self.assertEqual(
            KerberosStrings(["krbtgt", "IPA.TEST"]).value,
            ["krbtgt", KerberosString("IPA.TEST")],
        )

    def test_kerberos_string_value(self):
        self.assertEqual(KerberosStrings(KerberosString("admin")).value, ["admin"])
        self.assertEqual(
            KerberosStrings(KerberosString("admin")).value, [KerberosString("admin")]
        )

    def test_kerberos_strings_value(self):
        self.assertEqual(KerberosStrings(KerberosStrings("admin")).value, ["admin"])

    def test_asn1_native(self):
        self.assertEqual(
            KerberosStrings(["admin", "ipa.test"]).to_asn1().native,
            ["admin", "ipa.test"],
        )

    def test_eq(self):
        self.assertEqual(KerberosStrings("admin"), ["admin"])
        self.assertEqual(KerberosStrings("admin"), [KerberosString("admin")])
        self.assertEqual(
            KerberosStrings(["admin", "test.local"]),
            [KerberosString("admin"), "test.local"],
        )
