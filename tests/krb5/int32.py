import unittest
from ipapocket.krb5.objects import *


class TestInt32Object(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(Int32().value, 0)

    def test_int_value(self):
        self.assertEqual(Int32(1).value, 1)
        self.assertEqual(Int32(-1231).value, -1231)

    def test_int32_value(self):
        self.assertEqual(Int32(Int32(228)).value, 228)

    def test_enum_value(self):
        self.assertEqual(
            Int32(MessageTypes.KRB_AP_REP).value, MessageTypes.KRB_AP_REP.value
        )

    def test_min_value(self):
        self.assertEqual(Int32(MIN_INT32).value, MIN_INT32)
        with self.assertRaises(InvalidInt32Value):
            Int32(MIN_INT32 - 1)

    def test_max_value(self):
        self.assertEqual(Int32(MAX_INT32).value, MAX_INT32)
        with self.assertRaises(InvalidInt32Value):
            Int32(MAX_INT32 + 1)

    def test_asn1_native(self):
        self.assertEqual(Int32(-987654).to_asn1().native, -987654)

    def test_eq(self):
        self.assertEqual(Int32(1), Int32(1))
        self.assertEqual(Int32(1337), 1337)
