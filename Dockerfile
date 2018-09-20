FROM tiangolo/uwsgi-nginx-flask:python3.6-alpine3.7

LABEL maintainer="xiongjun <xiongjun@tsinghuanet.com>"

ENV LISTEN_PORT 9999

RUN apk --no-cache add build-base libxslt-dev \
    && pip3 install requests beautifulsoup4 pyfunctional lxml

#COPY requirements.txt ./
#RUN pip3 install --no-cache-dir -r requirements.txt

COPY ./external_intelligence/ /external_intelligence/external_intelligence/
COPY ./uwsgi_app.py /external_intelligence/
COPY ./uwsgi.ini /external_intelligence/
#COPY ./supervisord.ini /etc/supervisor.d/supervisord.ini

ENV PYTHONPATH=/external_intelligence
ENV UWSGI_INI /external_intelligence/uwsgi.ini

WORKDIR /external_intelligence



