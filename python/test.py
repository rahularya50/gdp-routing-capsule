import gdp_client

client = gdp_client.PyGdpClient("172.18.0.255", 27183)
client.send_packet([0] * 32, b"this is some data")
# client.recv_from()
