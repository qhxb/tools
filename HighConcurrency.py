import datetime
import threading
import requests
requests.packages.urllib3.disable_warnings()


class MyThread(threading.Thread):
    def __init__(self, number, _method, _url, _data, _headers):
        threading.Thread.__init__(self)
        self.number = number
        self.method = _method
        self.url = _url
        self.data = _data
        self.headers = _headers

    def run(self):
        log_list.append([self.number, 'start', self.url, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')])
        res = requests.request(self.method, url=self.url, data=self.data, headers=self.headers, verify=False)
        log_list.append([self.number, 'end', res.status_code,
                         datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'), res.text[:150]])


def main(_thread_num=None):
    with open('request.txt') as fi:
        request = fi.read()
    protocol, request_info, body = request.split('\n\n')
    header_dict = {}
    header_list = request_info.split('\n')
    for header in header_list[1:]:
        try:
            key, val = header.split(':', 1)
            header_dict.update({key.strip(): val.strip()})
        except Exception as e:
            log_list.append(e)
    url = protocol + '://' + header_dict['Host'].strip() + header_list[0].split()[1]
    method = header_list[0].split()[0]
    threads = [MyThread(i, method, url, body, header_dict) for i in range(_thread_num)]  # 修改了等待时间

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # 打印log信息，防止print阻塞线程
    for i in log_list:
        print(i)


if __name__ == '__main__':
    thread_num = 10
    log_list = []
    main(_thread_num=thread_num)
