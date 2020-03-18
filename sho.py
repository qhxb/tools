# -*- coding: utf-8 -*-
import time
import pymongo
import shodan


class MongoOp(object):
    def __init__(self, host='localhost', port=7777):
        try:
            myclient = pymongo.MongoClient(host, port, connect=False)
            db = myclient['test']
            db.authenticate('test', 'test', mechanism='SCRAM-SHA-1')
            self.__mycol = db['shodan']
        except Exception, e:
            print e
            pass

    def new(self, domain, query, total):
        self.__mycol.insert_one({"domain": domain, 'query': query, 'total': total})

    def updata(self, domain, info):
        try:
            self.__mycol.update_one({'domain': domain},
                                    {"$push": {"info": info}})
        except:
            pass


def num2ip(num):
    return '%s.%s.%s.%s' % ((num >> 24) & 0xff, (num >> 16) & 0xff, (num >> 8) & 0xff, (num & 0xff))


SHODAN_API_KEY = "sss"
api = shodan.Shodan(SHODAN_API_KEY)


def scan(domain, query):
    try:
        db = MongoOp()
        maxi = 1000
        FACETS = [('ip', maxi)]
        result = api.count(query, facets=FACETS)
        db.new(domain, query, result['total'])
        num = 0
        for ipinfo in result['facets']['ip']:
            try:
                num = num + ipinfo['count']
                ip = num2ip(ipinfo['value'])
                host = api.host(ip)
                info = []
                for item in host['data']:
                    try:
                        product = item['product']
                    except:
                        product = ''
                    try:
                        version = item['version']
                    except:
                        version = ''
                    if product or version or item['data']:
                        if item['data'].find('HTTP') == 0:
                            try:
                                if item['_shodan']['module'].find('https') == 0:
                                    origin = 'https://'+ip+':'+str(item['port'])
                                else:
                                    origin = 'http://' + ip + ':' + str(item['port'])
                            except Exception, e:
                                print e
                                origin = ''
                            info.append(
                                {"product": product, "version": version, "origin":origin,"Port": item['port'], "Banner": item['data']})
                        else:
                            info.append(
                                {"product": product, "version": version,"Port": item['port'], "Banner": item['data']})
                infodic = {'ip': ip, 'hostname': host['hostnames'], 'domains': host['domains'], 'info': info}
                db.updata(domain=domain, info=infodic)
                time.sleep(1)  # shodan提供的API有频率限制，具体频率没有说明，这里大概设一个
            except Exception, e:
                print e

        if maxi < result['total']:  # 默认最多查询1000个ip一般不会超过，万一超过就报警重新设置maxi
            print "警告！！！超过1000个ip"
    except Exception, e:
        print e
        pass


if __name__ == '__main__':
    domain = 'ssss'
    query = 'sss'  # shodan的查询语句
    scan(domain, query)
