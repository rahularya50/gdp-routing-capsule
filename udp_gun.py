import socket

SOURCE_PORT = 27182

TARGET_IP = "128.32.37.41"
TARGET_PORT = 31415
DEFAULT_PAYLOAD = b"Not hello"

MAGIC_BYTES = b"\x26\x2a"

PUT = b"\x01"
GET = b"\x02"
PING = b"\x03"
PONG = b"\x04"
FPING = b"\x05"

KEY = b"7" * 32
VALUE = b"2" * 32


def str_to_mac(s):
    """
    Convert a MAC address string to 6 byte-octets
    >>> str_to_mac("020000FFFF01")
    b'\x02\x00\x00\xff\xff\x01'
    """
    res = []
    for i in range(6):
        first, second = int("0x" + s[i * 2], 16), int("0x" + s[i * 2 + 1], 16)
        res.append(((first << 4) | second).to_bytes(1, byteorder="big"))
    return b"".join(res)


def str_to_ip(s):
    return b"".join([(int(x)).to_bytes(1, byteorder="big") for x in s.split(".")])


def build_message(action, key, value, payload=DEFAULT_PAYLOAD):
    return MAGIC_BYTES + action + key + value + payload


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", SOURCE_PORT))


mac_payload = str_to_mac("020000FFFF00")
ip_payload = str_to_ip("10.100.1.10")
forge_payload = mac_payload + ip_payload
s.sendto(
    build_message(FPING, KEY, VALUE, payload=forge_payload), (TARGET_IP, TARGET_PORT)
)

# s.sendto(build_message(GET, KEY, VALUE), (TARGET_IP, TARGET_PORT))
received_data, origin = s.recvfrom(1024)

magic, action, key, value, payload = (
    received_data[:2],
    received_data[2:3],
    received_data[3:35],
    received_data[35:67],
    received_data[67:],
)

assert magic == MAGIC_BYTES

print(action, key, value, payload)
