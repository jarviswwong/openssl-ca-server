import os
import sys
import pexpect
import json
import base64
import logging
from config import *
from urllib import request
from Crypto.Cipher import AES
from Crypto import Random


# AES-256-CFB工具类
class AESCipher:
    BS = 16

    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + (AESCipher.BS - len(s) %
                    AESCipher.BS) * chr(AESCipher.BS - len(s) % AESCipher.BS)

    def unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    # aes-256-cfb 加密函数
    def encrypt(self, plaintext):
        plaintext = self.pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + cipher.encrypt(plaintext))

    # aes-256-cfb 解密函数
    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return self.unpad(cipher.decrypt(ciphertext[16:]))


# 系统调用openssl命令
def openssl(*args):
    cmdline = (" ".join([OPENSSL] + list(args))).strip()
    child = pexpect.spawn(command=cmdline, timeout=10)
    return child


# 生成吊销证书列表
def gencrl():
    crlpath = os.path.join(CA_ROOT, CRL_FILE)
    child = openssl('ca', '-gencrl', '-out', crlpath)
    ret = child.expect('Using configuration from')
    if ret == 0:
        print("Certificate Revocation List (CRL) updated!")
    else:
        print("Failed to update Certificate Revocation List (CRL)")


# 打印请求者信息到日志
def logRequestInfo(request):
    logging.info("Remote IP: %s, Method: %s, Protocol: %s" %
                 (request.remote_ip, request.method, request.protocol))


# 返回json格式信息
# @status = -1 or 0
def jsonMessage(status, msg, extra={}):
    jsonData = {"status": status, "msg": msg}
    # 打印日志
    print(msg)
    if status < 0:
        logging.error(msg)
    else:
        logging.info(msg)
    jsonData.update(extra)
    return json.dumps(jsonData)


# 去除value头尾空格
def paramFormat(action):
    for key, value in action.items():
        action[key] = value.strip()
    return action


if __name__ == "__main__":
    p = "01"
    aes = AESCipher('damocles_secret_')
    print(aes.encrypt(p))
