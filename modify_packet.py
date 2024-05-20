from scapy.all import *
from scapy.layers.inet import IP

# Load the packet from the file
with open('packet_modify.bin', 'rb') as f:
    packet_data = f.read()

# Convert the packet data to a Scapy packet
packet = IP(packet_data)

# Modify the ciphertext in the packet
if Raw in packet:
    modified = bytearray(packet[Raw].load)
    modified[0] = (modified[0] + 1) % 256
    packet[Raw].load = bytes(modified)

# Send the modified packet
send(packet, iface='lo0')


