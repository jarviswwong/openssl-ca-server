import sys, pexpect, json
from config import OPENSSL
from urllib import request


# 系统调用openssl命令
def openssl(*args):
    cmdline = (" ".join([OPENSSL] + list(args))).strip()
    child = pexpect.spawn(command=cmdline, timeout=10)
    return child
