import gdp_client

client = gdp_client.GDPClient("192.168.0.255", 31415)
client.send_packet_py([0] * 32, b"this is some data")
