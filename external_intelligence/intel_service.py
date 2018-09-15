
import threading
import requests
import re
import random
import time
import datetime
from bs4 import BeautifulSoup
import logging
import functional

from external_intelligence.intel_source import EXTERNAL_INTEL_SOURCES as source
from external_intelligence import config as cfg
from external_intelligence import proxy_pool as pool

# 使用多少个源，目前只使用微步
USE_SOURCE_NUM = 1

CHK_THD_EVENT = threading.Event()
CHK_THD_LOCK = threading.Lock()
CHK_CTL_THD_LOCK = threading.Lock()

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

    CHK_THD_LOCK.acquire()
    CHECK_LIST.append(item)
    CHK_THD_LOCK.release()

    CHK_THD_EVENT.set()

    return True


def get_external_intel(check_item: dict):
    for item in SOURCE_DICT:
        if item['active']:
            rlt = item['func'](check_item)
            if rlt.get('state') == 'success':
                rlt['source'] = item['name']
                return rlt


def update_source_proxy(source_name):
    proxis = pool.get_proxys()

    source = SOURCE_DICT.get(source_name)

    timedelta = {
        'd': datetime.timedelta(days=int(source['period'][:-1])),
        'h': datetime.timedelta(hours=int(source['period'][:-1])),
        'm': datetime.timedelta(minutes=int(source['period'][:-1])),
        's': datetime.timedelta(seconds=int(source['period'][:-1])),
    }
    def add_proxys(item):
        return {
            'proxy':item,
            'sleep_time': source['time'],
            'remain_count': source['count'],
            'update_time': datetime.datetime.now() + timedelta.get(source['period'][-1], datetime.timedelta(days=1)),
            'using': False,
        }

    source['proxis'] = functional.seq(pool.get_proxys()).map(add_proxys).list()





class CheckControlThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, name, datas, lock):
        threading.Thread.__init__(self)
        self.name = name
        self.datas = datas
        self.lock = lock

    def run(self):
        def process(item):
            if item['sleep_time'] and not item['using']:
                item['sleep_time'] -= 1
            if item['remain_count']

        while True:
            time.sleep(1)
            functional.seq(self.datas).for_each(lambda o:o)

def get_sources():
    CHK_CTL_THD_LOCK.acquire()
    source = SOURCE_DICT.pop(0)
    CHK_CTL_THD_LOCK.release()


def get_intel(check_item):
    source = get_sources()
    for s in source['sources']:
        if s['sleep_time']:
            time.sleep(s['sleep_time'])

        rlt = s['func'](check_item, source['proxy'])
        if rlt['state'] == 'fail':
            get_intel(check_item)





class CheckThread(threading.Thread):  # 继承父类threading.Thread
    def __init__(self, name, datas, event, lock):
        threading.Thread.__init__(self)
        self.name = name
        self.datas = datas
        self.event = event
        self.lock = lock
        self.clean_time = datetime.datetime.now() + datetime.timedelta(days=1)
        self.count = 0

    def run(self):
        while True:
            self.event.wait()
            self.event.clear()
            if datetime.datetime.now() >= self.clean_time:
                self.clean_time = datetime.datetime.now() + datetime.timedelta(days=1)
                self.count = 0

            while self.datas:
                # 每天查询不超过10次
                if self.count >= 10:
                    logging.info('more than 10')
                    break
                self.lock.acquire()
                item = self.datas.pop(0)
                self.lock.release()

                if item:
                    logging.info(f'check {item}')
                    rlt = get_intel(item)
                    self.count += 1
                    try:
                        res = requests.post(cfg.INTEL_CENTER_URL, json=rlt)
                    except:
                        logging.error(f'Exception:Post to intelligence center fail')
                    else:
                        logging.info(f'rlt: {rlt}, status:{res.status_code}')
                    # 随机延时，以防频繁访问而被禁止
                    time.sleep(int(random.uniform(10, 20)))


def init_intel_service():
    sources = functional.seq(cfg.EXTERNAL_ACCESS_CTL) \
        .zip(source) \
        .map(lambda o: {**o[0], **o[1]}) \
        .list()

    for s in sources:
        SOURCE_DICT[s['name']] = s
        update_source_proxy(s['name'])

    logging.info(SOURCE_DICT)

    CheckThread('CheckThread', CHECK_LIST, CHK_THD_EVENT, CHK_THD_LOCK).start()
    CheckControlThread('CheckControlThread', SOURCE_DICT, CHK_CTL_THD_LOCK).start()


