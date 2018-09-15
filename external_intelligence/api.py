# -*- coding: utf-8 -*-

import logging
from flask import Flask, request, make_response
from external_intelligence import intel_service as serv

logging.basicConfig(level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S", format='%(asctime)s - %(levelname)s  %(message)s')

app = Flask(__name__)

serv.init_intel_service()

@app.route('/check', methods=['GET'])
def check():
    rlt = serv.active_check(request.args.get('threat'))

    return make_response('<h1>hello</h1>', 200 if rlt else 503)