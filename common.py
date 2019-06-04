import sys, pexpect, json
from config import *
from tornado_mysql import pools
from urllib import request

mysql_pool = pools.Pool(CONN_PARAMS, max_idle_connections=1, max_recycle_sec=3)


# 系统调用openssl命令
def openssl(*args):
    cmdline = (" ".join([OPENSSL] + list(args))).strip()
    child = pexpect.spawn(command=cmdline, timeout=10)
    return child


# 检查fingerprint
def checkFingerprint(fingerprint):
    result = yield mysql_pool.execute(
        'select * from ' + VERIFY_TABLE + ' where fingerprint = %s',
        (fingerprint))
    if result.rowcount == 0:
        return False
    else:
        return True
3
# 返回json格式信息
# @status = -1 or 0
def jsonMessage(status, msg, extra={}):
    jsonData = {"status": status, "msg": msg}
    # 打印日志
    print(msg)
    jsonData.update(extra)
    return json.dumps(jsonData)