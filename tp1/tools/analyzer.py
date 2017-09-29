from scapy.all import *
import math

pcapFile = 'test.pcap'

broadcastMAC = 'ff:ff:ff:ff:ff:ff'

def getLayers(pkt):
    layers = []
    while pkt.payload:
        layers.append(pkt.name)
        pkt = pkt.payload
    layers.append(pkt.name)
    return layers

def getDstType(pkt):
    return 'broadcast' if pkt.dst == broadcastMAC else 'unicast'

def modelSRC1(pkt):
    return getDstType(pkt), getLayers(pkt)[1]

def modelSRC2(pkt):
    pass

model = modelSRC1

pcapInput = rdpcap(pcapFile)

symbolCount = {}
for pkt in pcapInput:
    sym = model(pkt)
    if symbolCount.has_key(sym):
        symbolCount[sym] = symbolCount[sym] + 1
    else:
        symbolCount[sym] = 1

totalPkts = len(pcapInput) * 1.0
symbolData = symbolCount.copy()
entropy = 0
for sym in symbolCount:
    symbolProbability = symbolCount[sym]/totalPkts
    symbolInformation = -math.log(symbolProbability, 2)
    symbolData[sym] = (symbolProbability, symbolInformation)
    entropy = entropy + symbolProbability * symbolInformation

print symbolData, entropy
