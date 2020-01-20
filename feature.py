# coding:utf-8

# 黑名单ip池，比如127.0.0.1，如果部署在公网需要屏蔽内网ip
blackip = ['192.168.0.0']

# 需要探测的TCP常见端口
tcpportlist = [21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 389, 443, 445,
               465, 873, 993, 995, 1080, 1311, 1433, 1434, 1521, 1723, 2433,
               3000, 3001, 3002, 3306, 3307, 3389, 3690, 4000, 5432, 5800, 5900,
               6379, 7001, 8000, 8001, 8080, 8081, 8888, 9080, 9090, 9200, 9300,
               9999, 11211, 22022, 22222, 27017, 28017]

# 需要探测的UDP常见端口
udpportlist = [69]

# TCP特征库，格式：服务名|默认端口|匹配模式/payload|''/匹配正则
TCP = [
    'ssh|22|banner|ssh',
    'smtp|25|banner|^220.*?smtp',
    'dns|53|default|',
    'pop3|110|banner|\+OK.*?pop3',
    'netbios|139|default|',
    'imap|143|banner|^\* OK.*?imap',
    'ldap|389|default|',
    'smb|445|default|',
    'smtps|465|default|',
    'imaps|993|default|',
    'pop3|995|banner|\+OK',
    'proxy|1080|\x05\x01\x00\x01|^\x05\x00',
    'pptp|1723|default|',
    'mysql|3306|banner|sql',
    'rdp|3389|\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00|\x03\x00\x00\x13',
    'svn|3690|default|',
    'vnc|5900|banner|^RFB',
    'redis|6379|info\r\n|redis',
    'elasticsearch|9200|GET /_cat HTTP/1.1\r\n\r\n|/_cat/master',
    'memcache|11211|\x80\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|^\x81\x0b',
    'mongodb|27017|\x00\x00\x00\xa7A\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00|ismaster',
    'zookeeper|2181|stat|Zookeeper version',
    'mongodb|27017|+\x01\x00\x00\xca\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04\x01\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x03client\x00\xe9\x00\x00\x00\x03application\x00\x16\x00\x00\x00\x02name\x00\x07\x00\x00\x00robo3t\x00\x00\x03driver\x00I\x00\x00\x00\x02name\x00\x18\x00\x00\x00MongoDB Internal Client\x00\x02version\x00\x15\x00\x00\x004.0.5-17-gd808df2233\x00\x00\x03os\x00l\x00\x00\x00\x02type\x00\x08\x00\x00\x00Windows\x00\x02name\x00\x14\x00\x00\x00Microsoft Windows 8\x00\x02architecture\x00\x07\x00\x00\x00x86_64\x00\x02version\x00\x11\x00\x00\x006.2 (build 9200)\x00\x00\x00\x00|ismaster',
    'smb|445|\x00\x00\x00E\xffSMBr\x00\x00\x00\x00\x18S\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00"\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00|SMB',
]

# UDP特征库
UDP = ['tftp|69|\x00\x01rlsn\x00netascii\x00|File not found']
