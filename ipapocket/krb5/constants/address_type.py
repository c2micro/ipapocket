import enum


# https://www.rfc-editor.org/rfc/rfc4120#section-7.5.3
class AddressType(enum.Enum):
    IPv4 = 2
    Directional = 3
    ChaosNet = 5
    XNS = 6
    ISO = 7
    DECNET_Phase_IV = 12
    AppleTalk_DDP = 16
    NetBios = 20
    IPv6 = 24
