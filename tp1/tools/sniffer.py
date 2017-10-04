import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

pcap = sniff(count=100000)

wrpcap("capturaBuffet.pcap", pcap)