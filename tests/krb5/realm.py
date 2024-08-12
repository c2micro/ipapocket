import unittest
from ipapocket.krb5.objects import *


class TestRealmObject(unittest.TestCase):
    def test_none(self):
        self.assertEqual(Realm().realm, "")
        self.assertEqual(Realm().realm.value, "")
        self.assertEqual(Realm().realm, KerberosString())
        self.assertEqual(Realm().realm.value, KerberosString().value)

    def test_str(self):
        self.assertEqual(Realm("IPA.TEST").realm, KerberosString("IPA.TEST"))

    def test_kerberos_string(self):
        self.assertEqual(Realm(KerberosString("IPA.TEST")), Realm("IPA.TEST"))
        self.assertEqual(Realm(KerberosString()).realm, KerberosString())

    def test_eq(self):
        r01 = Realm("IPA01.TEST")
        r02 = Realm("IPA02.TEST")
        r03 = Realm("IPA01.TEST")
        self.assertEqual(r01, r03)
        self.assertNotEqual(r01, r02)
        self.assertNotEqual(r02, r03)
