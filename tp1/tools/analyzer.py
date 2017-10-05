from scapy.all import *
import math

class Model:
    broadcastMAC = 'ff:ff:ff:ff:ff:ff'

    def getLayers(self, pkt):
        layers = []
        while pkt.payload:
            layers.append(pkt.name)
            pkt = pkt.payload
        layers.append(pkt.name)
        return layers

    def getDstType(self, pkt):
        return 'broadcast' if pkt.dst == Model.broadcastMAC else 'unicast'

class ModelS1(Model):
    def name(self):
        return 's1'

    def symbol(self, pkt):
        return (self.getDstType(pkt), self.getLayers(pkt)[1])

    def toStr(self, symbol):
        return '<' + symbol[0] + ', ' + symbol[1] + '>'

class ModelS2(Model):
    def name(self):
        return 's2'

    def symbol(self, pkt):
        if self.getLayers(pkt)[1] == 'ARP':
            return (self.getLayers(pkt)[1], pkt.pdst)
        else:
            return None

    def toStr(self, symbol):
        return '<' + symbol[0] + ', ' + str(symbol[1]) + '>'

class Analizer:

    def __init__(self, model):
        self.model = model

    def process(self, fileName):
        frames = rdpcap(fileName)
        symbolCount = self.countSymbols(frames)
        symbolProbability = self.calculateSymbolsProbability(symbolCount)
        self.printTable(symbolProbability, fileName.split('.')[0])

    def countSymbols(self, frames):
        symbolCount = {}
        for pkt in frames:
            symbol = self.model.symbol(pkt)
            if symbol is not None:
                if symbolCount.has_key(symbol):
                    symbolCount[symbol] += 1
                else:
                    symbolCount[symbol] = 1
        return symbolCount

    def calculateSymbolsProbability(self, symbolCount):
        totalPkts = sum(symbolCount.values()) * 1.0
        symbolData = symbolCount.copy()
        for sym in symbolCount:
            symbolProbability = symbolCount[sym]/totalPkts
            symbolInformation = -math.log(symbolProbability, 2)
            symbolData[sym] = (symbolProbability, symbolInformation)
        return symbolData

    def calculateEntropy(self, symbolProbability):
        entropy = 0
        for symbol, probability in symbolProbability.iteritems():
            entropy = entropy + probability[0] * probability[1]
        return entropy

    def calculateMaxEntropy(self, symbolProbability):
        return math.log(len(symbolProbability.values()),2)

    def printTable(self, symbolProbability, fileName):
        f = open(fileName + '_' + self.model.name() + '_table' + '.csv', 'w')
        f.write('symbol;probability;information\n')
        for symbol, probability in symbolProbability.iteritems():
            f.write(self.model.toStr(symbol) + ';' + str(probability[0]) + ';' + str(probability[1]) + '\n')
        f.write('entropy'+ ';' + str(self.calculateEntropy(symbolProbability)) + '\n')
        if len(symbolProbability) > 0:
            f.write('max_entropy' + ';' + str(self.calculateMaxEntropy(symbolProbability)))
        f.close()

if __name__ == "__main__":
    if not len(sys.argv) == 3:
        print 'Uso: python ' + sys.argv[0] + " <pcapfile> <model>"
    else:
        fileName = sys.argv[1]
        if not os.path.exists(fileName):
            print fileName + ' no encontrado.'
            sys.exit()

        sourceModel = None
        if sys.argv[2] == 'S1' or sys.argv[2] == 's1':
            sourceModel = ModelS1()
        elif sys.argv[2] == 'S2' or sys.argv[2] == 's2':
            sourceModel = ModelS2()
        else:
            print 'El modelo de la fuente debe ser S1 o S2.'
            sys.exit()

        analizer = Analizer(sourceModel)
        analizer.process(fileName)
