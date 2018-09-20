
import requests
from bs4 import BeautifulSoup
import logging

from external_intelligence import proxy_source as proxy


WEIBU_JUDGMENTS = {
    '远控':         'C2',
    '僵尸网络':     'Botnet',
    '劫持':         'Hijacked',
    '钓鱼':         'Phishing',
    '恶意软件':     'Malware',
    '漏洞利用':     'Exploit',
    '扫描':        'Scanner',
    'P2P节点':      'P2P Node',
    #'僵尸网络':     'Zombie',
    'DNS':          'DNS',
    '垃圾邮件':     'Spam',
    '可疑':         'Suspicious',
    '代理':         'Proxy',
    '失陷主机':     'Compromised',
    '白名单':       'Whitelist',
    '基础信息':     'Info',
    'IDC服务器':    'IDC',
    '动态IP':       'Dynamic IP',
    '保留地址':     'Bogon',
    '未启用IP':     'FullBogon',
    'HTTP代理入口': 'HTTP Proxy In',
    'HTTP代理出口': 'HTTP Proxy Out',
    'Socks代理入口':'Socks Proxy In',
    'Socks代理出口':'Socks Proxy Out',
    'VPN':          'VPN',
    'VPN入口':      'VPN In',
    'VPN出口':		'VPN Out',
}


def access_web(method, url, proxy, param=None):

    methods = {
        'get':requests.get,
        'post':requests.post,
    }

    try:
        res = methods.get(method)(url, proxies=proxy.copy(), timeout=30)
    except:
        logging.error('Exception:Can not access weibu')
    else:
        if res.status_code == 200:
            return res.text

    return ' '


def get_weibu_intel(check_item, proxy):
    rlt = {}
    data = check_item['data']
    tmp_dict = {
        'url': f'https://x.threatbook.cn/nodev4/domain/{data}',
        'ip': f'https://x.threatbook.cn/nodev4/ip/{data}',
    }

    html = access_web('get', tmp_dict.get(check_item['type']), proxy)

    rlt['threat'] = check_item['data']

    def wb_tag(bs):
        bs = bs.find(lambda tag: tag.name == 'div' and tag.get('class') == ['tag-info'])
        if bs:
            return [{'wb_tag':WEIBU_JUDGMENTS.get(t.string.strip())} if t.string
                    else {'wb_info':t.find('a').string.strip()} if t.find('a').string else {}
                    for t in bs.find_all('div', class_='wb-tag')]

    rlt['state'] = 'success'
    bs = BeautifulSoup(html, "lxml")
    if bs.find('div', class_='sp-report__normal'):
        rlt['wb_rlt'] = 'no'

    elif bs.find('div', class_='sp-report__unknown'):
        rlt['wb_rlt'] = 'unknown'
        infos = wb_tag(bs)
        rlt['wb_tag'] = [item['wb_tag'] for item in infos if item.get('wb_tag')]
        rlt['wb_info'] = [item['wb_info'] for item in infos if item.get('wb_info')]
    elif bs.find('div', class_='sp-report__malicious') or bs.find('div', class_='sp-report__community-malicious'):
        rlt['wb_rlt'] = 'yes'
        infos = wb_tag(bs)
        rlt['wb_tag'] = [item['wb_tag'] for item in infos if item.get('wb_tag')]
        rlt['wb_info'] = [item['wb_info'] for item in infos if item.get('wb_info')]
    else:
        rlt['state'] = 'fail'

    return rlt


EXTERNAL_INTEL_SOURCES = [
    {
        'name': 'weibu',
        'func': get_weibu_intel,
    },
]


