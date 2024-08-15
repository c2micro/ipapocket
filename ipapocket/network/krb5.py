import struct
import socket


class Krb5Client:
    def __init__(self, target, port=88):
        self._target = target
        self._port = port
        self._socket = None

    def _open(self):
        self._close()

        af, socktype, proto, canonname, sa = socket.getaddrinfo(
            self._target, self._port, 0, socket.SOCK_STREAM
        )[0]
        self._socket = socket.socket(af, socktype, proto)
        self._socket.connect(sa)

    def _close(self):
        if self._socket is not None:
            self._socket.close()

    def sendrcv(self, data):
        self._open()

        self._socket.sendall(struct.pack("!i", len(data)) + data)
        recv_len = struct.unpack("!i", self._socket.recv(4))[0]
        rep = self._socket.recv(recv_len)
        while len(rep) < recv_len:
            rep += self._socket.recv(recv_len - len(rep))

        self._close()
        return rep
