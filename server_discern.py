ip = '127.0.0.1'
port = 445

# UDP端口探测、服务识别
def UdpTftp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(binascii.a2b_hex('000131006e6574617363696900'),(ip, port))#发送tftp特征数据
    except Exception as e:
        print e
    while True:
        data,ipport = sock.recvfrom(1024)
        if data:
            if 'File not found' in data:
                print "IP：{ipport}\n发现UDP服务：{name}".format(ipport=ipport[0],port=port,name='TFTP')
            break

#TCP端口探测（TCP服务被动识别）
def TcpPort():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip,port))
        print '发现存活IP端口\nIP:{ip}、端口：{port}'.format(ip=ip,port=port)
    except:
        pass
    #被动服务识别
    try:
        while True:
            banner,ipport = sock.recv(1024)
            print banner,ipport
    except Exception as e:
        print str(e)

#TCP主动服务识别
def TcpServer():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip,port))
        sock.send(binascii.a2b_hex('00000045ff534d4272000000001853c8000000000000000000000000fffffffe00000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00'))#SMB2
    except Exception as e:
        print str(e)
    try:
        while True:
            data = sock.recv(1024)
            if data:
                if 'SMB' in data:
                    print "IP：{ipport}、端口：{port}\n发现TCP服务：{name}".format(ipport=ip,port=port, name='SMB')
                break
    except Exception as e:
        print str(e)

# ICMP
import os, sys, socket, struct, select, time
ICMP_ECHO_REQUEST = 8
def checksum(source_string):
  sum = 0
  countTo = (len(source_string)/2)*2
  count = 0
  while count<countTo:
    thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
    sum = sum + thisVal
    sum = sum & 0xffffffff # Necessary?
    count = count + 2
  if countTo<len(source_string):
    sum = sum + ord(source_string[len(source_string) - 1])
    sum = sum & 0xffffffff # Necessary?
  sum = (sum >> 16) + (sum & 0xffff)
  sum = sum + (sum >> 16)
  answer = ~sum
  answer = answer & 0xffff
  answer = answer >> 8 | (answer << 8 & 0xff00)
  return answer
def receive_one_ping(my_socket, ID, timeout):
  timeLeft = timeout
  while True:
    startedSelect = time.time()
    whatReady = select.select([my_socket], [], [], timeLeft)
    howLongInSelect = (time.time() - startedSelect)
    if whatReady[0] == []: # Timeout
      return
    timeReceived = time.time()
    recPacket, addr = my_socket.recvfrom(1024)
    icmpHeader = recPacket[20:28]
    type, code, checksum, packetID, sequence = struct.unpack(
      "bbHHh", icmpHeader
    )
    if packetID == ID:
      bytesInDouble = struct.calcsize("d")
      timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
      return timeReceived - timeSent
    timeLeft = timeLeft - howLongInSelect
    if timeLeft <= 0:
      return
def send_one_ping(my_socket, dest_addr, ID):
  dest_addr = socket.gethostbyname(dest_addr)
  my_checksum = 0
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1) #压包
  bytesInDouble = struct.calcsize("d")
  data = (192 - bytesInDouble) * "Q"
  data = struct.pack("d", time.time()) + data
  my_checksum = checksum(header + data)
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
  packet = header + data
  my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1
def do_one(dest_addr, timeout):
  icmp = socket.getprotobyname("icmp")
  try:
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
  except socket.error, (errno, msg):
    if errno == 1:
      msg = msg + (
        " - Note that ICMP messages can only be sent from processes"
        " running as root."
      )
      raise socket.error(msg)
    raise # raise the original error
  my_ID = os.getpid() & 0xFFFF
  send_one_ping(my_socket, dest_addr, my_ID)
  delay = receive_one_ping(my_socket, my_ID, timeout)
  my_socket.close()
  return delay
def verbose_ping(dest_addr, timeout = 2, count = 100):
  for i in xrange(count):
    print "ping %s..." % dest_addr,
    try:
      delay = do_one(dest_addr, timeout)
    except socket.gaierror, e:
      print "failed. (socket error: '%s')" % e[1]
      break
    if delay == None:
      print "failed. (timeout within %ssec.)" % timeout
    else:
      delay = delay * 1000
      print "get ping in %0.4fms" % delay

def ping():
    verbose_ping(ip,timeout=3,count=1)
