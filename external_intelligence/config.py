
INTEL_CENTER_URL = 'http://127.0.0.1:8085/api/v1.0/threat-book/db?type=wb'

PROXY_SOURCE_URL = 'http://122808476807258451.standard.hutoudaili.com/?num=3&area_type=1&anonymity=3'

# 每ip访问控制
EXTERNAL_ACCESS_CTL = [
    {
        'name':'360',     # 外部情报库名称
        'time':20,         # 20秒最多查1次
        'period': '1d',     # 周期为1天,   支持的单位d：天，h：小时，m：分，s秒
        'count': 5,        # 一个周期内最多查10次
    },
    {
        'name':'weibu',     # 外部情报库名称
        'time':20,         # 20秒最多查1次
        'period': '1d',     # 周期为1天,   支持的单位d：天，h：小时，m：分，s秒
        'count': 10,        # 一个周期内最多查10次
    },
]

# 每个情报源中最少的代理数量
MIN_ACTIVE_PROXIES = 50

# 保留的一个周期内查询次数被耗尽的代理数量
REMAIN_MAX_UNACTIVE_PROXIES = 1000
