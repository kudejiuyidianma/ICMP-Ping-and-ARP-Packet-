LIBRARIES
import dpkt
I use dpkt to read my pcap file which includes the arp packets exchange.
import struct
I use struct to transform the IP address and Mac address into readable format.

How to run
I record the ARP exchanges from my computer and save it as a pcap file. I first open and read this pcap file. Then I divide all ARP record into request and response sets by their different opcode. Then I use their sender Mac address and target Mac address to match the response and request. Then I print all information of the first pair of response and request in the readable format. 