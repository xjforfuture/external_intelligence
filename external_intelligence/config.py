
INTEL_CENTER_URL = 'http://127.0.0.1:8085/api/v1.0/threat-book/db?type=wb'

# 每ip访问控制
EXTERNAL_ACCESS_CTL = [
    {
        'name':'weibu',     # 外部情报库名称
        'time ':20,         # 20秒最多查1次
        'period': '1d',     # 周期为1天,   支持的单位d：天，h：小时，m：分，s秒
        'count': 10,        # 一个周期内最多查10次
    },
]