import dpkt
import struct


def trans_ip(ip):
    return '.'.join(map(str, struct.unpack('>BBBB', ip)))


def trans_mac(mac):
    return "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", mac)


file = open("assignment4_my_arp.pcap", 'rb')
pcap = dpkt.pcap.Reader(file)

arp_req = []
arp_res = []
arp_cnt = 0

for ts, buf in pcap:
    if buf[12:14] == b'\x08\x06':
        arp_cnt += 1
        opcode = buf[20:22]
        if opcode == b'\x00\x01':
            arp_req.append(buf)
        if opcode == b'\x00\x02':
            arp_res.append(buf)
res = arp_res[0]
for req in arp_req:
    if req[32:38] == res[22:28] and req[22:28] == res[32:38]:
        break

print("First ARP exchange: ")
print("ARP request: Who has", trans_ip(req[28:32]), end="")
print("? Tell", trans_ip(req[38:42]))
print("Header")
print("Hardware type: ", int.from_bytes(req[14:16], 'big'))
print("Protocol type: ", int.from_bytes(req[16:18], 'big'))
print("Hardware size", req[18])
print("Protocol size:", req[19])
print("Opcode: ", int.from_bytes(req[20:22], 'big'))
print("Sender MAC address: ", trans_mac(req[22:28]))
print("Sender IP address: ", trans_ip(req[28:32]))
print("Target MAC address: ", trans_mac(req[32:38]))
print("Target IP address: ", trans_ip(req[38:42]))
print()

print("ARP response: ", trans_ip(res[28:32]), end="")
print(" is at", trans_mac(res[32:38]))
print("Header")
print("Hardware type: ", int.from_bytes(res[14:16], 'big'))
print("Protocol type: ", int.from_bytes(res[16:18], 'big'))
print("Hardware size", res[18])
print("Protocol size:", res[19])
print("Opcode: ", int.from_bytes(res[20:22], 'big'))
print("Sender MAC address: ", trans_mac(res[22:28]))
print("Sender IP address: ", trans_ip(res[28:32]))
print("Target MAC address: ", trans_mac(res[32:38]))
print("Target IP address: ", trans_ip(res[38:42]))
print()
