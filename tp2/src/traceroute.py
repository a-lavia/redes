import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
from scipy import stats
import time
import json


class Traceroute:
    cantRespuestas = 100

    def __init__(self, host):
        self.host = host


    def obtenerTraceroute(self):
        self.hops = self.allHops()
        self.traceroute = self.tracerouteHeuristico()
        self.buscoSaltosInterc()
        self.tracerouteJson = self.toJson()


    def allHops(self):
        echoReply = False
        ttl=1
        hops = []
        while (not echoReply) and ttl < 31:
            lstHop = []
            for i in range(self.cantRespuestas):
                startTime = time.clock()
                ans, unans = sr(IP(dst=self.host,ttl=ttl)/ICMP(), timeout=1, verbose=0)
                finishTime = time.clock()
                if len(ans) > 0:
                    # guardo la info del hop del ICMP error message y el tiempo en milisegundos
                    lstHop.append({'ip_address': ans.res[0][1].src,
                                'type': ans.res[0][1].type,
                                'hop_num': ttl,
                                'rtt': (finishTime - startTime)*1000,
                                'salto_intercontinental': 'false'})
                else:
                    lstHop.append({'ip_address': 'null',
                                'type': 'null',
                                'hop_num': ttl,
                                'rtt': 'null',
                                'salto_intercontinental': 'null'})

            # De todos los paquetes que recibi, si hay un echo-reply es porque llego a destino
            # sino aumento el ttl.
            for i in range(len(lstHop)):
                if lstHop[i]['type'] == 0:
                    # recibi ICMP echo-reply
                    echoReply = True
                    break
                elif i == len(lstHop)-1:
                    ttl+=1
            hops.append(lstHop)
        return hops


    def tracerouteHeuristico(self):
        # Me quedo con el ip que mas aparece en cada hop pero con el rtt promedio de todos
        traceroute = []
        for lstHop in self.hops:
            lstIps = []
            for dh in lstHop:
                if dh['ip_address'] != 'null':
                    lstIps.append(dh['ip_address'])

            dic = {}
            if len(lstIps) == 0:
                # de este hop no hubo respuesta, agrego una respuesta vacia
                dic = {
                    'ip_address': 'null',
                    'hop_num': lstHop[0]['hop_num'],
                    'rtt': 'null',
                    'salto_intercontinental': 'null'
                    }
            else:
                ip = self.buscoIpQueMasAparece(lstIps)
                # dic vuelve sin el campo type
                dic = self.dicConRttPromedio(lstHop, ip)
            traceroute.append(dic)
        return traceroute


    def dicConRttPromedio(self, lstHop, ip):
        dic = {}
        sumaRtt = 0
        cantConIp = 0
        levanteValores = False
        for dh in lstHop:
            if dh['ip_address'] == ip:
                if not levanteValores:
                    dic['ip_address'] = dh['ip_address']
                    dic['hop_num'] = dh['hop_num']
                    dic['salto_intercontinental'] = dh['salto_intercontinental']
                    levanteValores = True
                sumaRtt += dh['rtt']
                cantConIp += 1
        dic['rtt'] = sumaRtt/cantConIp
        return dic


    def buscoIpQueMasAparece(self, lstIps):
        lstIpCant = [lstIps.count(ip) for ip in lstIps]
        maxCant = max(lstIpCant)
        idx = lstIpCant.index(maxCant)
        return lstIps[idx]


    def buscoSaltosInterc(self):
        # Me devuelve una lista de los paquetes que no obtuve respuesta
        # y otra con los indices donde se produce el outlier.
        # CUIDADO: outlierIdx tiene el indice de Rtt entre saltos, o sea que el 
        # valor del indice donde esta el salto es el siguiente.
        outlierIdx, lstIdxNull = self.cimbala()
        for idx in outlierIdx:
            if (idx+1) not in lstIdxNull:
                self.traceroute[idx+1]['salto_intercontinental'] = True


    def cimbala(self):
        # rttes, idx, absolute value of deviation
        rttcal, lstIdxNull = self.dameRtts()
        lstRttes = [[abs(rttcal[i] - rttcal[i+1]), i, 0] for i in range(len(rttcal)-1)]
        outlierIdx = []
        hayOutlier = True
        while(hayOutlier):
            hayOutlier = False
            media = self.calcMedia(lstRttes)
            desvEst = self.calcDesvioEstandar(lstRttes, media)
            self.calcValorAbsDesv(lstRttes, media)
            tau = self.calcTau(len(lstRttes))
            tauS = desvEst*tau
            for i in range(len(lstRttes)):
                if lstRttes[i][2] > tauS:
                    hayOutlier = True
                    outlierIdx.append(lstRttes[i][1])
                    lstRttes.pop(i)
                    break
        return (outlierIdx, lstIdxNull)


    def dameRtts(self):
        # si hay un null calcula el promedio del anterior no null y el siguiente no null
        lstIdxNull = []
        for i in range(len(self.traceroute)):
            if self.traceroute[i]['ip_address'] == 'null':
                lstIdxNull.append(i)
        rtt = []
        for i in range(len(self.traceroute)):
            if i not in lstIdxNull:
                rtt.append(self.traceroute[i]['rtt'])
            else:
                idxAnt = self.anteriorNoNull(i)
                idxPost = self.posteriorNoNull(i)
                rtt.append((self.traceroute[idxAnt]['rtt']+self.traceroute[idxPost]['rtt'])/2)
        return rtt, lstIdxNull


    def anteriorNoNull(self, idxNull):
        for i in range(idxNull-1, 0, -1):
            if self.traceroute[i]['ip_address'] != 'null':
                return i


    def posteriorNoNull(self, idxNull):
        for i in range(idxNull+1, len(self.traceroute)):
            if self.traceroute[i]['ip_address'] != 'null':
                return i


    def calcMedia(self, lstRttes):
        suma = 0.0
        for rtt,_,_ in lstRttes:
            suma += rtt
        return suma/len(lstRttes)


    def calcDesvioEstandar(self, lstRttes, media):
        suma = 0.0
        for rtt,_,_ in lstRttes:
            suma += (rtt - media)**2
        return (suma/(len(lstRttes)-1))**(0.5)


    def calcValorAbsDesv(self, lstRttes, media):
        for i in range(len(lstRttes)):
            lstRttes[i][2] = abs(lstRttes[i][0] - media)


    def calcTau(self, n):
        #Studnt, p<0.05, 2-tail, alpha=0.05
        t = stats.t.ppf(1-0.025, n-2)
        return (t*(n-1)) / ((n**0.5)*((n-2 + t**2)**0.5))


    def toJson(self):
        return json.dumps(self.traceroute, indent=4)


    def printJson(self):
        print self.tracerouteJson


    def jsonToFile(self):
        file = open(self.host + '-json.json', 'w')
        file.write(self.tracerouteJson)
        file.close()


    def allHopsToFile(self):
        file = open(self.host + '-allHops.csv', 'w')
        file.write('ip_address,rtt,type,hop_num')
        file.write('\n')
        for lstHop in self.hops:
            for dic in lstHop:
                file.write(dic['ip_address'] + "," + \
                           str(dic['rtt']) + "," + \
                           str(dic['type']) + "," + \
                           str(dic['hop_num']))
                file.write('\n')
        file.close()


    def fromFileToJson(self,path):
        with open(path) as json_data:
            self.traceroute = json.load(json_data)



if __name__ == "__main__":
    if sys.argv[1] == '':
        print 'Se debe agregar un host: sudo python traceroute.py <host>'
        sys.exit()
    else:
        traceroute = Traceroute(sys.argv[1])
        traceroute.obtenerTraceroute()
        traceroute.printJson()
        traceroute.allHopsToFile()
        traceroute.jsonToFile()

