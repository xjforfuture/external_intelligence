import threading
import requests
import functional
import time
import os
import logging

from external_intelligence import config as cfg

PROXY_POOL_LOCK = threading.Lock()
PROXY_POOL = []

PROXY_POOL_MAX = 2


def get_proxies(num):
    global PROXY_POOL
    PROXY_POOL_LOCK.acquire()
    proxies = PROXY_POOL[:num]
    PROXY_POOL = PROXY_POOL[num:]
    PROXY_POOL_LOCK.release()

    return proxies


def check_proxy(proxy):
    ip = proxy['http'].split('//')[1].split(':')[0]

    if os.system("ping -c 1 " + ip) == 0:
        # 用百度测试
        try:
            res = requests.get('https://www.baidu.com', proxies=proxy.copy())

        except:
            logging.debug(f'{ip} is not available')
        else:
            if res.status_code == 200:
                return True
    else:
        logging.debug(f'{ip} is down!')

    return False


def update_proxys():
    global PROXY_POOL
    test = [
        '66.70.188.148:3128',
        '110.74.193.1:36127',
        '189.60.48.251:57538',
        '96.225.46.134:46874',
    ]

    '''
    res = requests.get(cfg.PROXY_SOURCE_URL)
    if res.status_code == 200:
        res.json()
    '''
    new_proxis = functional.seq(test)\
        .map(lambda o: {'http':'http://'+o, 'https':'https://'+o}) \
        .filter(check_proxy)\
        .list()

    PROXY_POOL_LOCK.acquire()
    PROXY_POOL.extend(new_proxis)
    PROXY_POOL_LOCK.release()

    logging.debug('sum of proxies %d'%len(PROXY_POOL))


class GetProxyThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, name):
        threading.Thread.__init__(self)
        self.name = name

    def run(self):
        while True:
            time.sleep(1)
            if len(PROXY_POOL) < PROXY_POOL_MAX:
                update_proxys()


def proxy_source_init():
    GetProxyThread('GetProxyThread').start()