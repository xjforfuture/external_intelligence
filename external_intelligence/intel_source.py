
import requests
from bs4 import BeautifulSoup
import logging
import functional


def access_web(method, url, proxy, **params):

    methods = {
        'get':requests.get,
        'post':requests.post,
    }

    try:
        if params:
            res = methods.get(method)(url, proxies=proxy.copy(), timeout=30, params=params)
        else:
            res = methods.get(method)(url, proxies=proxy.copy(), timeout=30)
    except:
        logging.error(f'Exception:Can not access {url}')
    else:
        return res

    return None

######################
# 微步情报源
######################
WEIBU_JUDGMENTS = {
    '远控':         'C2',
    '僵尸网络':     'Botnet',
    '劫持':         'Hijacked',
    '钓鱼':         'Phishing',
    '恶意软件':     'Malware',
    '漏洞利用':     'Exploit',
    '扫描':         'Scanner',
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


def get_weibu_intel(check_item, proxy):
    rlt = {
        'threat': check_item['data'],
        'state': 'fail',
    }

    data = check_item['data']
    tmp_dict = {
        'domain': f'https://x.threatbook.cn/nodev4/domain/{data}',
        'ip': f'https://x.threatbook.cn/nodev4/ip/{data}',
    }

    res = access_web('get', tmp_dict.get(check_item['type']), proxy)
    if res and res.status_code == 200:
        html = res.text

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

    return rlt

############
# 360情报源
############
def get_360_intel(check_item, proxy):
    'https://ti.360.net/ti/query?limit=100&offset=0&page=1&type=ip&value=149.56.106.215'
    rlt = {
        'threat': check_item['data'],
        'state': 'fail',
    }

    fo = open("360_tag.log", "a")

    res = access_web('get', 'https://ti.360.net/ti/query', proxy,
                      limit=100, offset=0, page=1, type=check_item['type'], value=check_item['data'])
    '''
    {
        "status":200,
        "message":"ok",
        "data":{
            "ip_try_connect":"ip_try_connect_048942cb60ea7229",
            "ip_tag":"ip_tag_584956135e10600a",
            'domain_tag'
            "ip_ioc_detect":"ip_ioc_detect_de3fc8dc1588d70a",
            "ip_attribute":"ip_attribute_4ffbb98fa31d4392"
        }
    }
    '''

    if res:
        res_json = res.json()
        if all([res_json.get('status') == 200, res_json.get('message') == 'ok', res_json.get('data')]):
            tmp_dict = {
                'ip': res_json.get('data').get('ip_tag'),
                'domain': res_json.get('data').get('domain_tag'),
            }
            tag = tmp_dict[check_item['type']]

            url = f'https://ti.360.net/ti/task/{tag}'
            if 'tag' in url:
                res = access_web('get', url, proxy)

                if res:
                    res_json = res.json()
                    if all([res_json.get('status') == 200,
                            res_json.get('message') == 'ok',
                            res_json.get('data'),
                            res_json['data'].get(tag),
                            res_json['data'][tag].get('table')]
                           ):
                        '''
                        tags = functional.seq(res_json['data'][tag]['table'])\
                            .map(lambda o: o.get('tag'))\
                            .fileter(lambda o: o).list()
                        '''
                        tags_info = functional.seq(res_json['data'][tag]['table']).list()

                        fo.write(f"threat {check_item['data']}: {tags_info} \n\r")
                        logging.info(f"threat {check_item['data']}: {tags_info} \n\r")

                        rlt['wb_tag'] = 'test'
                        rlt['state'] = 'success'

    fo.close()
    return rlt


EXTERNAL_INTEL_SOURCES = {
    'weibu':{'func': get_weibu_intel},
    '360':{'func': get_360_intel},
}



