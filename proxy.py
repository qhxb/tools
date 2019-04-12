# cat proxy.py
#coding:utf-8
import socket,datetime,sys,os
import time
import select
import threading

# 设置代理规则
isinterceptrequest='n'
isinterceptresponse,isdropresponse, sleeptime ='y','n',5.00
#表示拦截的主机数组，此示例表示拦截请求的url中包含www.baidu.com跟m.baidu.com字符的数据包
intercepthost=['www.baidu.com','m.baidu.com']    

# 设置代理服务器ip跟端口
host = '0.0.0.0'
port = 8888

dhost = ''
HEADER_SIZE = 4096

pppp=''
if(sys.argv[1]=='start'):
    print(sys.argv[1])
    fi = open('/etc/profile','a+')
    fi.writelines('\n#soketproxy start \n')
    fi.writelines('export proxy="127.0.0.1:'+str(port)+'" #soketproxy \n')
    fi.writelines('export http_proxy=$proxy #soketproxy\n')
    fi.writelines('export https_proxy=$proxy #soketproxy\n')
    fi.writelines('#soketproxy end \n')
    fi.close()
    os.system('source /etc/profile')


    # 子进程进行socket 网络请求
    def http_socket(client, addr):
        pppp = addr[1]
        # 创建 select 检测 fd 列表
        inputs = [client]
        outputs = []
        remote_socket = 0
        while client:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)
            try:
                for s in readable:
                    if s is client:
                        # 读取 http 请求头信息
                        data = s.recv(HEADER_SIZE)
                        if remote_socket is 0:
                            # 拆分头信息
                            host_url = data.split("\r\n")[0].split(" ")
                            method, host_addr, protocol = map(lambda x: x.strip(), host_url)
                            dhost = host_addr
                            print(dhost)
                            # 2019/3/27拦截dhost中包含特定字符的请求包，drop
                            if (isinterceptrequest == 'y'):
                                print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '->' + 'droprequest:' + dhost)
                                for x in intercepthost:
                                    if (dhost.find(x) > -1):
                                        return
                            # 如果 CONNECT 代理方式
                            if method == "CONNECT":
                                host, port = host_addr.split(":")
                            else:
                                for i in data.split("\r\n"):
                                    if(i.find('Host:')>-1):
                                        host_addr=i.split(":")
                               # host_addr = data.split("\r\n")[1].split(":")
                                # 如果未指定端口则为默认 80
                                if 2 == len(host_addr):
                                    host_addr.append("80")
                                name, host, port = map(lambda x: x.strip(), host_addr)
                                # 建立 socket tcp 连接
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((host, int(port)))
                            remote_socket = sock
                            inputs.append(sock)
                            if method == "CONNECT":
                                start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                                s.sendall(
                                    "HTTP/1.1 200 Connection Established\r\nFiddlerGateway: Direct\r\nStartTime: {0}\r\nConnection: close\r\n\r\n".format(
                                        start_time))
                                continue
                        # 发送原始请求头
                        i1=remote_socket.sendall(data)
                        # 2019/3/27拦截dhost包含特定字符返回包，drop或者延迟*秒
                        if (isinterceptresponse == 'y'):
                            for x in intercepthost:
                                if (dhost.find(x) > -1):
                                    if (isdropresponse == 'y'):
                                        print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '->' + 'dropresponse:' + dhost)
                                    else:
                                        print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '->' + dhost + '-sleep:' + str(sleeptime))
                                        time.sleep((sleeptime/3))
                    else:
                        # 接收数据并发送给浏览器
                        resp = s.recv(HEADER_SIZE)
                        if resp:
                            client.sendall(resp)
                jj=os.popen('netstat -ano|grep '+str(pppp))
                #print(jj)
                for i in jj:
                    if(i.find('CLOSE_WAIT')>-1):
            print('proxy end')
                        return
            except Exception as e:
                print("http socket error {0}".format(e))
                return

    # 创建socket对象
    http_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        http_server.bind((host, port))
    except Exception as e:
        # sys.exit("python proxy bind error {0}".format(e))
        pass

    print("python proxy start")

    http_server.listen(5)

    while True:
        client, addr = http_server.accept()
        http_thread = threading.Thread(target=http_socket, args=(client, addr))
        http_thread.start()

    # 关闭所有连接
    http_server.close()
    print("python proxy close")

if(sys.argv[1]=='end'):
    with open('/etc/profile','r') as rf:
        lines = rf.readlines()
    with open('/etc/profile','w') as wf:
        for line in lines:
            if "soketproxy" in line:
                continue
            wf.write(line)
    rf.close()
    wf.close()
    os.system('source /etc/profile')
