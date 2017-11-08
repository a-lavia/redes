import sys
import json
import requests
from lxml import html

inputFilename = sys.argv[1]

f = open(inputFilename, 'r')
inputJson = json.load(f)
f.close()

locations = []
for entry in inputJson:
    if entry['ip_address'] is not 'null':
        request = requests.get('https://geoiptool.com/en/?ip=' + entry['ip_address'])
        if request.status_code == 200:
            parseHtml = html.fromstring(request.content)

            latitude = parseHtml.xpath('/html/body/div[2]/div/div/div/div/div/div[1]/div[5]/div[9]/span[2]/text()')[0]
            longitude = parseHtml.xpath('/html/body/div[2]/div/div/div/div/div/div[1]/div[5]/div[10]/span[2]/text()')[0]
            locations.append({'ip_adress': entry['ip_address'], 'latitude': float(latitude), 'longitude': float(longitude)})


f = open('locations-' + inputFilename, 'w')
f.write(json.dumps(locations, indent=4))
f.close()
