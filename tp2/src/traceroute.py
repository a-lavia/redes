import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
import time


def traceroute(host):
    print "Traceroute:", host
    notEchoReply = True
    ttl=1
    hops = []
    while notEchoReply:
        startTime = time.clock()
        ans, unans = sr(IP(dst=host,ttl=ttl)/ICMP())
        finishTime = time.clock()
        if ans.res[0][1].type == 0:
            # recibi ICMP echo-reply
            notEchoReply = False
        else:
            # guardo la info del hop del ICMP error message y el tiempo en milisegundos
            ttl +=1        
        hops.append([ans.res[0][1], (finishTime - startTime)*0.001])

    return hops


def printHops(hops):
    print '['
    for i in range(len(hops)):
        print '    {'
        print '        "rtt": ' + str(hops[i][1]) + ','
        print '        "ip_address:" ' + hops[i][0].src  + ','
        print '        "salto_intercontinental:" ' + 'lol'  + ','
        print '        "hop_num:" ' + str(i+1)
        if i != len(hops)-1:
            print '    },'
        else:
            print '    }'
    print ']'


if __name__ == "__main__":
    if sys.argv[1] == '':
        print 'Se debe agregar un host: sudo python traceroute.py <host>'
        sys.exit()
    else:
        hops = traceroute(sys.argv[1])
        printHops(hops)