import gdp_client

client = gdp_client.PyGdpClient("192.168.0.255", 31415)
client.send_packet([0] * 32, b"this is some data")
