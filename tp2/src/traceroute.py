import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
from scipy import stats
import time
import json


def allHops(host):
    cantRespuestas = 30
    print "Traceroute:", host
    echoReply = False
    ttl=1
    hops = []
    while (not echoReply) or ttl < 20:
        dicHop = {}
        for i in range(cantRespuestas):
            startTime = time.clock()
            ans, unans = sr(IP(dst=host,ttl=ttl)/ICMP(), timeout=1) #verbose=0
            finishTime = time.clock()
            if len(ans) != 0:
                # guardo la info del hop del ICMP error message y el tiempo en milisegundos
                lst.append({'ip': ans.res[0][1].src, 'type': ans.res[0][1].type, 'rtt': (finishTime - startTime)*1000})
            else:
                lst.append({'ip': 'null', 'type': 11, 'rtt': 0})

        for i in range(len(lst)):
            if lst[i]['type'] == 0:
                # recibi ICMP echo-reply
                echoReply = True
                break
            elif i == len(lst)-1:
                ttl+=1
        hops.append(lst)

    return hops


def buscoIpQueMasAparece(lstIps):
    lstIpCant = [lstIps.count(ip) for ip in lstIps]
    maxCant = max(lstIpCant)
    idx = lstIpCant.index(maxCant)
    return lstIpCant[idx]


def tracerouteHeuristico(hops):
    # Me quedo con el ip que mas aparece en cada hop
    traceroute = []
    for lstHop in hops:
        lstIps = []
        for dh in lstHop:
            if dh['ip'] != 'null':
                lstIps.append(dh['ip'])

        if len(lstIps) == 0:
            # de este hop no hubo respuesta, agrego una respuesta vacia
            traceroute.append(lstHop[0])
        else:
            ip = buscoIpQueMasAparece(lstIps)
            for dh in lstHop:
                if dh['ip'] == ip:
                    traceroute.append(dh)
                    break

    return traceroute


def buscoSaltosIntern(traceroute):
    media = calcMedia(traceroute)
    desvEst = calcDesvioEstandar(traceroute, media)
    lstAbsValDev = calcValorAbsDesv(traceroute, media)
    tau = calcTau(len(traceroute))


def calcMedia(traceroute):
    suma = 0.0
    for dic in traceroute:
        if dic['ip'] != 'null':
            suma += dic['rtt']
    return suma / len(traceroute)


def calcDesvioEstandar(traceroute, media):
    suma = 0.0
    for dic in traceroute:
        if dic['ip'] != 'null':
            suma += (dic['rtt'] - media)**2
    return (suma/(len(traceroute)-1))**(0.5)


def calcValorAbsDesv(traceroute, media):
    return [abs(dic['rtt'] - media) for dic in traceroute if dic['ip'] != 'null']


def calcTau(n):
    #Studnt, p<0.05, 2-tail, alpha=0.05
    t = stats.t.ppf(1-0.025, n-2)
    return (t*(n-1)) / ((n**0.5)*((n-2 + t**2)**0.5))


if __name__ == "__main__":
    if sys.argv[1] == '':
        print 'Se debe agregar un host: sudo python traceroute.py <host>'
        sys.exit()
    else:
        hops = allHops(sys.argv[1])
        traceroute = tracerouteHeuristico(hops)
        buscoSaltosInterc(traceroute)
