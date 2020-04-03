import threading
import requests
import shodan
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()
thread_num = 3
SHODAN_API_KEY = "xxx"
api = shodan.Shodan(SHODAN_API_KEY)


def scan(query):
    try:
        maxi = 1000
        FACETS = [('ip', maxi)]
        result = api.count(query, facets=FACETS)
        if result['total']:
            print query
    except Exception, e:
        pass

def getsha1(ids):
    while True:
        try:
            id = ids.next()
        except StopIteration:
            return
        except:
            pass
        try:
            if id.strip():
                res = requests.request("get", "https://crt.sh/?id=" + str(id.strip()), verify=False)
                soup = BeautifulSoup(res.text, 'lxml')
                texts = soup.find_all("td", class_='outer')
                scan('ssl:'+texts[-1].text.lower())
        except Exception, e:
            print e,id


if __name__ == '__main__':
    all_threads = []
    with open('./id.txt', 'r') as fo:
        ids = (x for x in fo.readlines())
    for _ in range(thread_num):
        t = threading.Thread(target=getsha1, args=(ids,))
        all_threads.append(t)
        t.start()
    for t in all_threads:
        t.join()

        
