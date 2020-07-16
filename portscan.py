import re
import socket
import threading
import time

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
def get_ip_list(ipinput):
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


# TCP端口探测（TCP服务被动识别）
def tcp_scan(ip, port_iter, feature):
    while True:
        try:
            port_index = next(port_iter)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(time_out)
                sock.connect((ip, port_index))
            except Exception as e:
                pass
                # print(e)
            # 被动服务识别
            try:
                data = sock.recv(1024)
                if data:
                    match_obj = re.search(feature, data, re.I | re.M)
                    if match_obj:
                        lock.acquire()  # 加锁
                        print('发现指定服务', ip, ':', port_index, ' banner__', data)
                        lock.release()  # 释放锁
                    else:
                        lock.acquire()  # 加锁
                        print('发现其他服务', ' banner__', data)
                        lock.release()  # 释放锁
            except Exception as e:
                pass
                # print(e)
        except StopIteration:
            return


if __name__ == '__main__':
    thread_num = 50
    re_baner = b"ssh"
    ip_quen = '192.168.0.1-192.168.1.255'

    lock = threading.Lock()
    time_out = 3
    port_list = []
    with open('port_list.txt', 'r') as fi:
        for port in fi.readlines():
            port = port.strip()
            try:
                port_list.append(int(port))
            except:
                pass
    all_threads = []
    for Ip in get_ip_list(ip_quen):
        port_iter_list = iter(port_list)

        for i in range(thread_num):
            t = threading.Thread(target=tcp_scan, args=(Ip, port_iter_list, re_baner,))
            t.setDaemon(True)
            t.start()
            all_threads.append(t)
    while True:
        time.sleep(1)
        for j in all_threads:
            if not j.is_alive():
                all_threads.remove(j)
        if not all_threads:
            print('scan end')
            break

            
