import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
import time
import json


def traceroute(host):
    cantRespuestas = 30
    print "Traceroute:", host
    echoReply = False
    ttl=1
    hops = []
    while (not echoReply) or ttl == 20:
        lst = []
        for i in range(cantRespuestas):
            startTime = time.clock()
            ans, unans = sr(IP(dst=host,ttl=ttl)/ICMP(), timeout=1) #verbose=0
            finishTime = time.clock()
            if len(ans) != 0:
                # guardo la info del hop del ICMP error message y el tiempo en milisegundos
                lst.append([ans.res[0][1].src, ans.res[0][1].type, (finishTime - startTime)*1000])
            else:
                lst.append(['null', 11, 0])

        for i in range(len(lst)):
            if len(lst[i]) > 0 and lst[i][1] == 0:
                # recibi ICMP echo-reply
                echoReply = True
                break
            elif i == len(lst)-1:
                ttl+=1
        hops.append(lst)

    return hops



if __name__ == "__main__":
    if sys.argv[1] == '':
        print 'Se debe agregar un host: sudo python traceroute.py <host>'
        sys.exit()
    else:
        hops = traceroute(sys.argv[1])
        print len(hops)
