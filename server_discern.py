# -*- coding: utf-8 -*-
import multiprocessing
import re
import lib.feature as feature
import threading
import lib.discern as discern
from IPy import IP

# 区间ip格式处理，ip2num、num2ip、gen_ip
def ip2num(ip):
    ips = [int(x) for x in ip.split('.')]
    return ips[0] << 24 | ips[1] << 16 | ips[2] << 8 | ips[3]


def num2ip(num):
    return '%s.%s.%s.%s' % ((num >> 24) & 0xff, (num >> 16) & 0xff, (num >> 8) & 0xff, (num & 0xff))


def gen_ip(ip):
    start, end = [ip2num(x) for x in ip.split('-')]
    return [num2ip(num) for num in range(start, end + 1) if num & 0xff]


# 用户输入ip信息转生成器
def getiplist(ipinput):
    ipinput2 = []
    try:
        if ipinput:
            if '-' in ipinput:
                ipinput2 = gen_ip(ipinput)
            else:
                ips = IP(ipinput)  # 掩码ip网段地址格式处理
                ipinput2 = [str(ip) for ip in ips]
    except Exception as e:
        return "输入ip信息{ipinput}不合法，请检查\n详情：{info}".format(ipinput=ipinput, info=str(e))
    return ipinput2


class hostscan(object):
    def __init__(self, ipinput='', blackip=[], tcpportlist=[], threadnum='', process_num=''):
        self.__ip_input = getiplist(ipinput)  # 待扫描ip
        self.__tcpport_list = tcpportlist  # 需要探测的TCP常见端口
        self.__black_ip = blackip  # 黑名单ip池，比如127.0.0.1，如果部署在公网需要屏蔽内网ip
        self.__process_num = process_num  # 进程数，每个进程去ip池顺序取IP扫描
        self.__thread_num = threadnum  # 线程数，每个线程去端口池顺序取端口扫描

        self.__tcp_feature = feature.TCP  # TCP识别特征库
        self.__udp_feature = feature.UDP  # UDP识别特征库
        self.__ping_timeout = 5  # ping超时时间
        self.__ping_count = 1  # ping次数

    # TCP扫描，步骤：TCP握手，握手成功的话识别是否有返回banner，如果有用feature.TCP去识别服务
    def tcpscan(self, ip, hostname, portIterator, result):
        while True:
            try:
                port = portIterator.next()
            except:
                return
            if port:
                tcp = discern.TcpPort(ip, port)  # TCP端口探测（TCP服务被动识别）
                try:
                    if tcp:
                        if tcp['banner']:
                            flag = 1   # 设置标志位，如果有banner但是没有识别出服务应该记住，用来后续更新我们的特征库
                            for featuredetail in feature.TCP:
                                list = featuredetail.split('|')
                                reg = list[3].decode('string_escape')
                                if list[2] == 'banner':
                                    matchObj = re.search(reg, tcp['banner'], re.I | re.M)
                                    if matchObj:
                                        flag = 0
                                        result.put(
                                            "被动式发现TCP服务，IP：{},主机名：{}，端口：{},服务名称：{}，模式：banner".format(ip, hostname, port,
                                                                                                     list[0]))
                                        break
                            if flag:
                                result.put(
                                    "发现TCP端口跟banner但是没有识别出服务，IP：{},主机名：{}，端口：{},banner：{}".format(ip, hostname, port,
                                                                                                  tcp['banner']))

                        else:
                            for featuredetail in feature.TCP:
                                tcpresult = discern.TcpServer(ip, port, featuredetail)
                                try:
                                    if tcpresult[1] == port:
                                        result.put("主动式发现TCP服务，IP：{},主机名：{}，端口：{},服务名称：{}".format(ip, hostname, port,
                                                                                                  tcpresult[2]))
                                        # 默认识别成功时break，在端口复用的情况下，只能扫到其中一个服务，如果想都识别注释掉break
                                        break
                                    else:
                                        list = featuredetail.split('|')
                                        if list[2] == 'default' and list[1] == str(port):
                                            result.put(
                                                "被动式发现TCP服务，IP：{},主机名：{}，端口：{},服务名称：{}，模式：default".format(ip, hostname,
                                                                                                          port,
                                                                                                          list[0]))
                                            break
                                except:
                                    pass
                except Exception as e:
                    # print str(e)
                    pass
    # UDP扫描，步骤：遍历UDP特征库，直接发包识别
    def udpscan(self, ip, hostname, result):
        for featuredetail in feature.UDP:
            udpresult = discern.UdpPort(ip,featuredetail)
            try:
                if len(udpresult) == 3:
                    result.put("主动式发现UDP服务，IP：{},主机名：{}，端口：{},服务名称：{}".format(udpresult[0], hostname, udpresult[1],udpresult[2]))
            except:
                pass

    # 探测一个ip
    def scanip(self, ipque, result):
        while True:
            try:
                ip = ipque.get(False)
            except Exception as e:
                # print str(e)
                return
            if ip in self.__black_ip:  # 如果ip为黑名单ip，不扫描
                pass
            elif ip:
                isip = discern.verbose_ping(ip, timeout=self.__ping_timeout, count=self.__ping_count)
                if len(isip) == 3:
                    try:
                        hostname = discern.ip2hostname(ip)  # 步骤：主机存活探测/获取主机名——TCP端口探测/UDP服务识别——TCP服务识别
                    except:
                        hostname = ''

                    all_threads = []
                    portIterator = (port for port in self.__tcpport_list)  # 用python的生成器保证不重复取完所有端口，也可以用Queue
                    for _ in range(self.__thread_num):  # TCP扫描
                        t = threading.Thread(target=self.tcpscan,
                                             args=(ip, hostname, portIterator, result,))
                        all_threads.append(t)
                        t.start()
                    t2 = threading.Thread(target=self.udpscan,args=(ip, hostname, result,))  # UDP扫描
                    all_threads.append(t2)
                    t2.start()
                    for t in all_threads:
                        t.join()


    def run(self):
        # 多进程通信Queue
        ipque = multiprocessing.Queue()
        result = multiprocessing.Queue()
        if isinstance(self.__ip_input, list) and self.__ip_input:
            for ip in self.__ip_input:
                if not ip in self.__black_ip:  # 如果ip输入合法且不属于黑名单库，添加进队列等待扫描
                    ipque.put(ip)
            all_process = []
            for _ in range(self.__process_num):
                p = multiprocessing.Process(target=self.scanip, args=(ipque, result))
                p.start()
                all_process.append(p)
            while True:
                for p in all_process[:]:
                    if not p.is_alive():
                        all_process.remove(p)
                if not all_process:
                    break
            #  打印结果
            while result.qsize():
                value = result.get(True)
                print value
        else:
            print "输入ip信息不合法，请检查{}".format(self.__ip_input)


if __name__ == '__main__':
    a = hostscan(ipinput='10.25.195.34-10.25.195.44',blackip=feature.blackip,tcpportlist=feature.tcpportlist, threadnum=40, process_num=20)
    a.run()
