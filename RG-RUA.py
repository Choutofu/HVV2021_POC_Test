# coding:utf-8
import socket
import requests
import warnings

warnings.filterwarnings('ignore')
vul_info = {
    "id":"10014",
    "name":"锐捷 RG-UAC 密码泄露",
    "detail":"RG-UAC系列是一款统一上网管理与审计系统，是锐捷网络专门解决互联网审计问题设计的网络设备",
    "level":"高危",
    "type":"密码泄露",
    "port":"",
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
        target = 'http://{}:{}'.format(ip,port)
        r1 = requests.get(target,verify=False,timeout=timeout)
        if "password" in r1.text:
            return vul_result(1,'存在')
        else:
            return vul_result(0,'不存在')
    except Exception as e:
        return vul_result(2,e)


print(vul_detect("221.214.32.158",8888))

#http://221.214.32.158:8888/