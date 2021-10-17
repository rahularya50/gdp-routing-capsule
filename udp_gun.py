import socket

SOURCE_PORT = 27182

TARGET_IP = "10.100.1.255"
TARGET_PORT = 5006
MESSAGE = b"Hello, World!"

s = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", SOURCE_PORT))
s.sendto(MESSAGE, (TARGET_IP, TARGET_PORT))
received = s.recvfrom(1024)
print(received)
