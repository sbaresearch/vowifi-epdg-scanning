'''
mccmnc_scraper.py - Mini python script to export the MCC/MNC list from mcc-mnc.com in CSV format.

Copyright(C) 2017 Yoshiyuki Kurauchi
License: MIT (https://github.com/wmnsk/mccmnc_scraper/blob/master/LICENSE)

Latest version is available on GitHub(https://github.com/wmnsk/mccmnc_scraper).
'''

from sys import argv
from urllib.request import urlopen
from bs4 import BeautifulSoup as bs
import pandas as pd

html = urlopen('http://mcc-mnc.com/')
soup = bs(html, 'html.parser')

headers = [h.string for h in soup.thead.find_all('th')]

bodies = []
w_tag = [t.find_all('td') for t in soup.tbody.find_all('tr')]
for w in w_tag:
    bodies.append([d.string for d in w])

df = pd.DataFrame(columns=headers, data=bodies)
df.set_index('MCC').to_csv(argv[1])
