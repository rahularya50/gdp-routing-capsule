import socket

SOURCE_PORT = 27182

TARGET_IP = "10.100.1.11"
TARGET_PORT = 5006
DEFAULT_PAYLOAD = b"Hello, World!"
DEFAULT_FORWARD_PING_IP = b''.join([(x).to_bytes(1, byteorder='big') for x in (10,100,1,11)])
MAGIC_BYTES = b"\x26\x2a"

PUT = b"\x01"
GET = b"\x02"
PING = b"\x03"
PONG = b"\x04"
F_PING = b"\x05"

KEY = b"\x24" * 32
VALUE = b"\x36" * 32


def build_message(action, key, value, payload=DEFAULT_PAYLOAD):
    return MAGIC_BYTES + action + key + value + payload


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", SOURCE_PORT))
# s.sendto(build_message(GET, KEY, VALUE), (TARGET_IP, TARGET_PORT))
s.sendto(build_message(F_PING, KEY, VALUE, DEFAULT_FORWARD_PING_IP), (TARGET_IP, TARGET_PORT))
# received_data, origin = s.recvfrom(1024)

# magic, action, key, value, payload = (
#     received_data[:2],
#     received_data[2:3],
#     received_data[3:35],
#     received_data[35:67],
#     received_data[67:],
# )

# assert magic == MAGIC_BYTES

# print(action, key, value, payload.decode("utf-8"))
