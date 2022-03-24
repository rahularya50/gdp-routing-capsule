import gdp_client

client = gdp_client.GDPClient("10.0.1.0", 31415)
client.send_packet_py([0] * 32, b"data")
