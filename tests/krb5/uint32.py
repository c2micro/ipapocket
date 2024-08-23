import unittest
from ipapocket.krb5.types import *
from ipapocket.krb5.constants import *
from ipapocket.exceptions.krb5 import *


class TestUInt32Object(unittest.TestCase):
    def test_none_value(self):
        self.assertEqual(UInt32().value, 0)

    def test_int_value(self):
        self.assertEqual(UInt32(1).value, 1)
        self.assertEqual(UInt32(0).value, 0)

    def test_uint32_value(self):
        self.assertEqual(UInt32(UInt32(228)).value, 228)

    def test_enum_value(self):
        self.assertEqual(
            UInt32(MessageType.KRB_AP_REP).value, MessageType.KRB_AP_REP.value
        )

    def test_min_value(self):
        self.assertEqual(Int32(MIN_UINT32).value, MIN_UINT32)
        with self.assertRaises(InvalidUInt32Value):
            UInt32(MIN_UINT32 - 1)

    def test_max_value(self):
        self.assertEqual(UInt32(MAX_UINT32).value, MAX_UINT32)
        with self.assertRaises(InvalidUInt32Value):
            UInt32(MAX_UINT32 + 1)

    def test_asn1_native(self):
        self.assertEqual(UInt32(2281337).to_asn1().native, 2281337)

    def test_eq(self):
        self.assertEqual(UInt32(876), UInt32(876))
        self.assertEqual(UInt32(1234), 1234)
