import unittest
from ipapocket.krb5.objects import *


class TestKerberosStringObject(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(KerberosString().value, "")

    def test_str_value(self):
        self.assertEqual(KerberosString("Hello world").value, "Hello world")
        self.assertEqual(KerberosString("Привет мир").value, "Привет мир")

    def test_kerberos_string_value(self):
        self.assertEqual(KerberosString(KerberosString("ipapocket")).value, "ipapocket")

    def test_asn1_native(self):
        self.assertEqual(
            KerberosString("1,2,3,one,two,three").to_asn1().native,
            "1,2,3,one,two,three",
        )

    def test_eq(self):
        self.assertEqual(KerberosString("abc"), KerberosString("abc"))
        self.assertEqual(KerberosString("abc"), "abc")
