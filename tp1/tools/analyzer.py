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
        return self.getLayers(pkt)[0]

    def toStr(self, symbol):
        return str(symbol)

class Analizer:

    def __init__(self, file, model):
        self.fileName = file.split('.')[0]
        self.pcapInput = rdpcap(file)
        self.model = model

    def process(self):
        symbolCount = {}
        symbolProbability = {}
        entropy = {}
        frameCount = 0
        for pkt in self.pcapInput:
            symbol = self.model.symbol(pkt)
            if symbolCount.has_key(symbol):
                symbolCount[symbol] += 1
            else:
                symbolCount[symbol] = 1
            frameCount+=1
            symbolProbability = self.calculateSymbolsProbability(symbolCount)
            entropy[frameCount] = self.calculateEntropy(symbolProbability)
        self.printTable(symbolProbability, entropy)
        self.printEntropy(entropy)

    def countSymbols(self):
        symbolCount = {}
        for pkt in self.pcapInput:
            symbol = self.model.symbol(pkt)
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

    def printTable(self, symbolProbability, entropy):
        f = open(self.fileName + '_' + self.model.name() + '_table' + '.csv', 'w')
        f.write('symbol;probability;information\n')
        for symbol, probability in symbolProbability.iteritems():
            f.write(self.model.toStr(symbol) + ';' + str(probability[0]) + ';' + str(probability[1]) + '\n')
        f.write('entropy'+ ';' + str(self.calculateEntropy(symbolProbability)) + '\n')
        f.write('max_entropy' + ';' + str(max(entropy.values())))
        f.close()

    def printEntropy(self, entropy):
        symbolCount = {}
        f = open(self.fileName + '_' + self.model.name() + '_entropy' + '.csv', 'w')
        f.write('frame;entropy\n')
        for n, probability in entropy.iteritems():
            f.write(str(n) + ';' + str(probability) + '\n')
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

        analizer = Analizer(fileName, sourceModel)
        analizer.process()
