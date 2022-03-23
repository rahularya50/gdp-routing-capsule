import gdp_client

client = gdp_client.GDPClient("127.0.0.2", 31415)
client.send_packet_py([0] * 32, b"data")
