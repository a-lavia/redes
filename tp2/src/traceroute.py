import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
from scipy import stats
import time
import json


class Traceroute:
    cantRespuestas = 30

    def __init__(self, host):
        self.host = host


    def obtenerTraceroute(self):
        self.hops = self.allHops()
        self.traceroute = self.tracerouteHeuristico()
        self.buscoSaltosInterc()
        self.tracerouteJson = self.pasarAJson()


    def allHops(self):
        echoReply = False
        ttl=1
        hops = []
        while (not echoReply) and ttl < 30:
            lst = []
            for i in range(self.cantRespuestas):
                startTime = time.clock()
                ans, unans = sr(IP(dst=self.host,ttl=ttl)/ICMP(), timeout=1, verbose=0) #verbose=0
                finishTime = time.clock()
                if len(ans) > 0:
                    # guardo la info del hop del ICMP error message y el tiempo en milisegundos
                    lst.append({'ip_address': ans.res[0][1].src,
                                'type': ans.res[0][1].type,
                                'hop_num': ttl,
                                'rtt': (finishTime - startTime)*1000,
                                'salto_intercontinental': 'false'})
                else:
                    lst.append({'ip_address': 'null',
                                'type': 'null',
                                'hop_num': ttl,
                                'rtt': 'null',
                                'salto_intercontinental': 'null'})

            for i in range(len(lst)):
                if lst[i]['type'] == 0:
                    # recibi ICMP echo-reply
                    echoReply = True
                    break
                elif i == len(lst)-1:
                    ttl+=1
            hops.append(lst)
        return hops


    def tracerouteHeuristico(self):
        # Me quedo con el ip que mas aparece en cada hop pero de rtt menor
        traceroute = []
        for lstHop in self.hops:
            lstIps = []
            for dh in lstHop:
                if dh['ip_address'] != 'null':
                    lstIps.append(dh['ip_address'])

            if len(lstIps) == 0:
                # de este hop no hubo respuesta, agrego una respuesta vacia
                traceroute.append(lstHop[0])
            else:
                ip = self.buscoIpQueMasAparece(lstIps)
                # dic vuelve sin el campo type
                dic = self.menorRTT(lstHop, ip)
                traceroute.append(dic)
        return traceroute


    def menorRTT(self, lstHop, ip):
        dic = {'rtt': 1000.0}
        for dh in lstHop:
            if dh['ip_address'] == ip and dh['rtt'] < dic['rtt']:
                dic['rtt'] = dh['rtt']
                dic['ip_address'] = dh['ip_address']
                dic['hop_num'] = dh['hop_num']
                dic['salto_intercontinental'] = dh['salto_intercontinental']
        return dic


    def buscoIpQueMasAparece(self, lstIps):
        lstIpCant = [lstIps.count(ip) for ip in lstIps]
        maxCant = max(lstIpCant)
        idx = lstIpCant.index(maxCant)
        return lstIps[idx]


    def buscoSaltosInterc(self):
        # dic, idx, absolute value of deviation
        hops = [[self.traceroute[i], i, 0] for i in range(len(self.traceroute))]
        hayOutlier = True
        while(hayOutlier):
            hayOutlier = False
            media = self.calcMedia(hops)
            desvEst = self.calcDesvioEstandar(hops, media)
            self.calcValorAbsDesv(hops, media)
            tau = self.calcTau(len(hops))
            tauS = desvEst*tau
            for i in range(len(hops)):
                if hops[i][0]['ip_address'] != 'null' and hops[i][2] > tauS:
                    hayOutlier = True
                    self.traceroute[hops[i][1]]['salto_intercontinental'] = 'true'
                    hops.pop(i)
                    break


    def calcMedia(self, hops):
        suma = 0.0
        for dic,i,_ in hops:
            if dic['ip_address'] != 'null':
                suma += dic['rtt']
        return suma / len(hops)


    def calcDesvioEstandar(self, hops, media):
        suma = 0.0
        for dic,i,_ in hops:
            if dic['ip_address'] != 'null':
                suma += (dic['rtt'] - media)**2
        return (suma/(len(hops)-1))**(0.5)


    def calcValorAbsDesv(self, hops, media):
        for i in range(len(hops)):
            if hops[i][0]['ip_address'] != 'null':
                hops[i][2] = abs(hops[i][0]['rtt'] - media)


    def calcTau(self, n):
        #Studnt, p<0.05, 2-tail, alpha=0.05
        t = stats.t.ppf(1-0.025, n-2)
        return (t*(n-1)) / ((n**0.5)*((n-2 + t**2)**0.5))


    def pasarAJson(self):
        return [json.dumps(hop, indent=4) for hop in self.traceroute]


    def imprimirListaJson(self):
        print '['
        for j in self.tracerouteJson:
            print j
        print ']'


    def jsonToFile(self):
        file = open(self.host + '-json.csv', 'w')
        file.write('[\n')
        for x in self.tracerouteJson:
            file.write(x)
            file.write('\n')
        file.write(']')
        file.close()


    def ipsToFile(self):
        file = open(self.host + '-ips.csv', 'w')
        for dic in self.traceroute:
            file.write(dic['ip_address'])
            file.write('\n')
        file.close()


    def rttToFile(self):
        file = open(self.host + '-rtt.csv', 'w')
        for dic in self.traceroute:
            file.write(str(dic['rtt']))
            file.write('\n')
        file.close()


    def interJumpToFile(self):
        file = open(self.host + '-salto.csv', 'w')
        for dic in self.traceroute:
            file.write(dic['salto_intercontinental'])
            file.write('\n')
        file.close()


    def allHopsToFile(self):
        file = open(self.host + '-allHops.csv', 'w')
        file.write('ip_address,rtt,salto_intercontinental,type,hop_num')
        file.write('\n')
        for lstHop in self.hops:
            for dic in lstHop:
                file.write(dic['ip_address'] + "," + \
                           str(dic['rtt']) + "," + \
                           dic['salto_intercontinental'] + "," + \
                           str(dic['type']) + "," + \
                           str(dic['hop_num']))
                file.write('\n')
        file.close()


    def allToFile(self):
        self.jsonToFile()
        self.ipsToFile()
        self.rttToFile()
        self.interJumpToFile()
        self.allHopsToFile()


if __name__ == "__main__":
    if sys.argv[1] == '':
        print 'Se debe agregar un host: sudo python traceroute.py <host>'
        sys.exit()
    else:
        traceroute = Traceroute(sys.argv[1])
        traceroute.obtenerTraceroute()
        traceroute.imprimirListaJson()
        # traceroute.allToFile()

