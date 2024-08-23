import struct
import socket
from ipapocket.krb5.types import KerberosResponse
from ipapocket.exceptions.network import InvalidPortNumber, InvalidPortType


class Krb5Network:
    """
    Class to handle transport for KRB5
    """

    _target: str = None
    _port: int = None
    _socket: socket.socket = None

    def __init__(self, target, port=88):
        self.target = target
        self.port = port

    @property
    def target(self) -> str:
        return self._target

    @target.setter
    def target(self, value) -> None:
        self._target = value

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, value) -> None:
        if isinstance(value, int):
            if value > 0 and value <= 65535:
                self._port = value
            else:
                raise InvalidPortNumber(value)
        else:
            raise InvalidPortType(value)

    def _open(self):
        """
        Open socket
        """
        self._close()

        af, socktype, proto, _, sa = socket.getaddrinfo(
            self.target, self.port, socket.AF_INET, socket.SOCK_STREAM
        )[0]
        self._socket = socket.socket(af, socktype, proto)
        self._socket.connect(sa)

    def _close(self):
        """
        Close socket if opened
        """
        if self._socket is not None:
            self._socket.close()

    def sendrcv(self, blob) -> KerberosResponse:
        """
        Send blob to KDC and convert response to KerberosResponse object
        """
        self._open()

        # dump object to ASN1 bytes
        data = blob.to_asn1().dump()
        self._socket.sendall(struct.pack("!i", len(data)) + data)
        recv_len = struct.unpack("!i", self._socket.recv(4))[0]
        rep = self._socket.recv(recv_len)
        while len(rep) < recv_len:
            rep += self._socket.recv(recv_len - len(rep))

        self._close()
        return KerberosResponse.load(rep)
