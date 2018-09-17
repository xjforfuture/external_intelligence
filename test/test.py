
import functional
import time
import logging

from external_intelligence import proxy_source as ps


logging.basicConfig(level=logging.DEBUG, datefmt="%Y-%m-%d %H:%M:%S", format='%(asctime)s - %(levelname)s  %(message)s')

ps.update_proxys()