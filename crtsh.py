# -*- coding: utf-8 -*-
import threading
import time
import re
import requests
import shodan
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()
thread_num = 1
SHODAN_API_KEY = "ssss"
api = shodan.Shodan(SHODAN_API_KEY)


def scan(query):
    try:
        # shodan结果如果不为空，需要进一步手工分析
        maxi = 10
        FACETS = [('ip', maxi)]
        result = api.count(query, facets=FACETS)
        if result['total']:
            print(query, result)
    except Exception as e:
        pass


def getsha1(ids):
    while True:
        try:
            id = next(ids)
        except StopIteration:
            return
        except:
            pass
        try:
            if id.strip():
                time.sleep(1)
                detailurl = "https://crt.sh/?id=" + str(id.strip())
                res = requests.request("get", detailurl, verify=False, timeout=8)
                soup = BeautifulSoup(res.text, 'html.parser')
                # 过滤cdn
                texts = soup.find_all("td", class_='text')
                org = re.search(r'commonName.*.countryName', texts[0].text).group()
                if org.find('CDNetworks') == -1:
                    texts2 = BeautifulSoup(res.text, 'html.parser').select('.options')[-1].select('td')[-1].text
                    scan('ssl:' + texts2.lower())
        except Exception as e:
            print(e,id)


if __name__ == '__main__':
    all_threads = []
    idlist = []
    # crt.sh访问有频率限制，不能并发太高
    try:
        with open('./domain.txt', 'r') as fo:
            for domain in fo.readlines():
                time.sleep(1)
                certurl = "https://crt.sh/?q=" + domain.strip()
                res = requests.request("get", certurl, verify=False, timeout=8)
                soup = BeautifulSoup(res.text, 'html.parser')
                texts = soup.find_all(attrs={'style': 'text-align:center'})
                for i in texts:
                    idlist.append(i.text)
        ids = (i for i in idlist)
        for _ in range(thread_num):
            t = threading.Thread(target=getsha1, args=(ids,))
            all_threads.append(t)
            t.start()
        for t in all_threads:
            t.join()
    except Exception as e:
        print(e)

