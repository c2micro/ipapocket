import struct
import socket
import time

def sendrcv(target, data, port = 88):
    msg_len = struct.pack('!i', len(data))

    af, socktype, proto, canonname, sa = socket.getaddrinfo(target, port, 0, socket.SOCK_STREAM)[0]
    s = socket.socket(af, socktype, proto)
    s.connect(sa)

    s.sendall(msg_len + data)

    recv_data_len = struct.unpack('!i', s.recv(4))[0]

    r = s.recv(recv_data_len)
    while len(r) < recv_data_len:
        r += s.recv(recv_data_len-len(r))
    
    print(r)