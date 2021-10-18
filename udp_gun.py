import socket

SOURCE_PORT = 27182

TARGET_IP = "10.100.1.255"
TARGET_PORT = 5006
PAYLOAD = b"Hello, World!"

MAGIC_BYTES = b"\x26\x2a"

PUT = b"\x01"
GET = b"\x02"

KEY = b"\x24" * 32
VALUE = b"\x36" * 32


def build_message(action, key, value):
    return MAGIC_BYTES + action + key + value + PAYLOAD


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", SOURCE_PORT))
s.sendto(build_message(GET, KEY, VALUE), (TARGET_IP, TARGET_PORT))
received_data, origin = s.recvfrom(1024)

magic, action, key, value, payload = (
    received_data[:2],
    received_data[2:3],
    received_data[3:35],
    received_data[35:67],
    received_data[67:],
)

assert magic == MAGIC_BYTES

print(action, key, value, payload.decode("utf-8"))
