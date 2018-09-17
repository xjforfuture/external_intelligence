
import threading
import requests
import re
import random
import time
import datetime
import logging
import functional

from external_intelligence.intel_source import EXTERNAL_INTEL_SOURCES as intel_source
from external_intelligence import config as cfg
from external_intelligence import proxy_source as ps


CHK_THD_EVENT = threading.Event()
CHK_LOCK = threading.Lock()
CHK_CTL_LOCK = threading.Lock()

CHECK_LIST = []
SOURCE_DICT = {}

def checkip(ip):
    if re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$').match(ip):
        return True
    else:
        return False


def active_check(threat: str):
    # 缓存不超过1000个
    if len(CHECK_LIST) > 1000:
        return False

    if threat in CHECK_LIST:
        return True

    item = {}
    if checkip(threat):
        item['type'] = 'ip'
    else:
        item['type'] = 'domain'
    item['data'] = threat

    CHK_LOCK.acquire()
    CHECK_LIST.append(item)
    CHK_LOCK.release()

    CHK_THD_EVENT.set()

    return True


def get_external_intel(check_item: dict):
    for item in SOURCE_DICT:
        if item['active']:
            rlt = item['func'](check_item)
            if rlt.get('state') == 'success':
                rlt['source'] = item['name']
                return rlt

def get_update_time(source):
    timedelta = {
        'd': datetime.timedelta(days=int(source['period'][:-1])),
        'h': datetime.timedelta(hours=int(source['period'][:-1])),
        'm': datetime.timedelta(minutes=int(source['period'][:-1])),
        's': datetime.timedelta(seconds=int(source['period'][:-1])),
    }

    return datetime.datetime.now() + timedelta.get(source['period'][-1], datetime.timedelta(days=1))


def source_proxy_get(source_name, init=False):

    source = SOURCE_DICT.get(source_name)

    def add_proxys(item):
        return {
            'proxy': item,
            'sleep_time': source['time'] + int(random.uniform(5, 10)),  # 随机延时，以防频繁访问而被禁止
            'remain_count': source['count'],
            'update_time': get_update_time(source),
        }

    if init:
        source['proxies'] = functional.seq(ps.get_proxies(cfg.MIN_ACTIVE_PROXIES * 2)).map(add_proxys).list()
        source['unactive_proxies'] = []
    else:
        proxies = ps.get_proxies(cfg.MIN_ACTIVE_PROXIES)
        def not_exist(item):
            return not functional.seq(source['proxies']).exists(lambda o: o['proxy'] == item)

        CHK_CTL_LOCK.acquire()
        source['proxies'].extend(functional.seq(proxies).filter(not_exist).map(add_proxys).list())
        CHK_CTL_LOCK.release()


class CheckControlThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, name, datas, lock):
        threading.Thread.__init__(self)
        self.name = name
        self.datas = datas
        self.lock = lock

    def run(self):
        while True:
            time.sleep(1)

            def update_proxies(s):
                def process_proxies(p):
                    if p['sleep_time']:
                        p['sleep_time'] -= 1
                    if datetime.datetime.now() >= p['update_time']:
                        p['remain_count'] = s['count']
                        p['update_time'] = get_update_time(s)

                self.lock.acquire()
                functional.seq(s['proxies']).for_each(process_proxies)
                self.lock.release()

                def process_unactive_proxies(p):
                    if datetime.datetime.now() >= p['update_time']:
                        p['remain_count'] = s['count']
                        p['update_time'] = get_update_time(s)
                        s['proxies'].append(p)
                    return p

                self.lock.acquire()
                s['unactive_proxies'] = functional.seq(s['unactive_proxies'])\
                    .map(process_unactive_proxies)\
                    .filter(lambda o: o['remain_count']<=0)\
                    .list()
                self.lock.release()

                # 代理池中的代理数量少于MIN_ACTIVE_PROXIES，申请新的代理
                if len(s['proxies']) < cfg.MIN_ACTIVE_PROXIES:
                    print('get proxies')
                    source_proxy_get(s['name'])

            functional.seq(self.datas.values()).for_each(update_proxies)


def pull_source_proxy():
    source = SOURCE_DICT[cfg.DEFAULT_SOURCE]
    source_proxy = None
    CHK_CTL_LOCK.acquire()
    while source['proxies']:
        proxy = source['proxies'].pop(0)
        if proxy['remain_count'] > 0:
            source_proxy =  {
                'name': source['name'],
                'func':source['func'],
                'proxy':proxy,
            }
            break

    # todo 如果还有其他情报源， 继续取可用的情报源

    CHK_CTL_LOCK.release()

    return source_proxy


def push_source_proxy(sp):
    source = SOURCE_DICT[sp['name']]
    sp['proxy']['remain_count'] -= 1
    sp['proxy']['sleep_time'] = source['time'] + int(random.uniform(5, 10))

    CHK_CTL_LOCK.acquire()
    if sp['proxy']['remain_count'] <= 0:
        if len(source['unactive_proxies']) <= cfg.REMAIN_MAX_UNACTIVE_PROXIES:
            source['unactive_proxies'].append(sp['proxy'])
    else:
        source['proxies'].append(sp['proxy'])
    CHK_CTL_LOCK.release()


def get_intel(check_item, try_count=10):
    if try_count <= 0:
        return {'state': 'fail'}

    sp = pull_source_proxy()
    if sp is None:
        return {'state': 'fail'}

    if sp['proxy']['sleep_time']:
        time.sleep(sp['proxy']['sleep_time'])

    rlt = sp['func'](check_item, sp['proxy']['proxy'])
    if rlt['state'] == 'fail':
        rlt = get_intel(check_item, try_count=try_count-1)
    else:
        push_source_proxy(sp)

    return rlt


class CheckThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, name, datas, event, lock):
        threading.Thread.__init__(self)
        self.name = name
        self.datas = datas
        self.event = event
        self.lock = lock

    def run(self):
        while True:
            self.event.wait()
            self.event.clear()

            while self.datas:
                self.lock.acquire()
                item = self.datas.pop(0)
                self.lock.release()

                if item:
                    logging.info(f'check {item}')

                    rlt = get_intel(item, 20)
                    logging.debug(f'rlt: {rlt}')
                    display_currt_info()

                    try:
                        res = requests.post(cfg.INTEL_CENTER_URL, json=rlt)
                    except:
                        logging.error(f'Exception:Post to intelligence center fail')
                    else:
                        logging.info(f'rlt: {rlt}, status:{res.status_code}')


def init_intel_service():
    sources = functional.seq(cfg.EXTERNAL_ACCESS_CTL) \
        .zip(intel_source) \
        .map(lambda o: {**o[0], **o[1]}) \
        .list()

    for s in sources:
        SOURCE_DICT[s['name']] = s
        source_proxy_get(s['name'], init=True)

    logging.info(SOURCE_DICT)

    ps.proxy_source_init()

    CheckThread('CheckThread', CHECK_LIST, CHK_THD_EVENT, CHK_LOCK).start()
    CheckControlThread('CheckControlThread', SOURCE_DICT, CHK_CTL_LOCK).start()

####
# for debug
###
def display_currt_info():
    logging.debug(SOURCE_DICT)
    logging.debug(ps.PROXY_POOL)