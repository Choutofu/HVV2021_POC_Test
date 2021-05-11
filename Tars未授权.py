# coding=utf-8
import re
import socket
import requests
import sys  
  
reload(sys)  
sys.setdefaultencoding('utf8')


vul_info = {
    "id":"38104",
    "name":"Tars未授权访问漏洞",
    "detail":"-",
    "level":"高危",
    "type":"信息泄露",
    "port":"3000,8080",
    "solution":"1、针对业务端口使用 iptables 实现网络访问控制，仅仅放行必要来源 IP 的访问。\r\n2、添加身份认证。",
    "reference":"-",
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
        target1 = 'http://{}:{}/pages/server/api/get_locale'.format(ip, port)
        target2 = 'http://{}:{}/pages/tree'.format(ip, port)
        if port == 443:
            target1 = 'https://{}/pages/server/api/get_locale'.format(ip)
            target2 = 'https://{}/pages/tree'.format(ip, port)
        r1 = requests.get(target1, verify=False, timeout=timeout)
        data1 = r1.text
        r2 = requests.get(target2, verify=False, timeout=timeout)
        data2 = r2.text
#        print str(data1)
#        print str(data2)
        if 'TarsNode' in str(data1) or ('tarslog' in str(data2) and 'tarsconfig' in str(data2)):
            return vul_result(1,"发现服务开放")
        else:
            return vul_result(0,"未发现漏洞")
    except Exception as e:
        return vul_result(2,e)