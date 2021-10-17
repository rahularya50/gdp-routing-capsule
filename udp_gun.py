import socket

SOURCE_PORT = 27182

TARGET_IP = "10.100.1.255"
TARGET_PORT = 5006
PAYLOAD = b"Hello, World!"

MAGIC_BYTES = b"\x26\x2a"

def build_message(payload):
    return MAGIC_BYTES + payload


s = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", SOURCE_PORT))
s.sendto(build_message(PAYLOAD), (TARGET_IP, TARGET_PORT))
received_data, origin = s.recvfrom(1024)
assert received_data[:2] == MAGIC_BYTES
print(received_data[2:])
