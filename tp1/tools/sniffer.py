import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


if __name__ == "__main__":
    if not len(sys.argv) == 3:
        print "La entrada debe ser:"
        print "python sniffer.py <nombre-red> <cantidad-paquetes-a-tomar>"
    else:
        networkName = sys.argv[1]
        qttyFrames = sys.argv[2]

        pcap = sniff(count=qttyFrames)
        wrpcap("captura" + networkName + ".pcap", pcap)
