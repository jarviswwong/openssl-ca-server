import os
import sys
import pexpect
import json
import base64
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


# 返回json格式信息
# @status = -1 or 0
def jsonMessage(status, msg, extra={}):
    jsonData = {"status": status, "msg": msg}
    # 打印日志
    print(msg)
    jsonData.update(extra)
    return json.dumps(jsonData)


if __name__ == '__main__':
    plaintext = '''-----BEGIN CERTIFICATE-----
MIIE/jCCAuagAwIBAgIBAzANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCQ04x
EDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0hhaWRpYW4xDTALBgNVBAoMBEJV
UFQxDDAKBgNVBAsMA1NTRTEUMBIGA1UEAwwLY2EuZm9vci5vcmcxJjAkBgkqhkiG
9w0BCQEWF3lvdW5nc2hlbmdqaWVAZ21haWwuY29tMB4XDTE5MDYyNTAyMDk0OVoX
DTIwMDYyNDAyMDk0OVowezELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcx
DTALBgNVBAoMBEJVUFQxDDAKBgNVBAsMA1NTRTEYMBYGA1UEAwwPc2VydmVyLmZv
b3Iub3JnMSMwIQYJKoZIhvcNAQkBFhR5eWlqaWFuNjAxQGdtYWlsLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKVjiJTf05KS8YrRlVBdq1E+tHij
Y2YKnFPwjAseenxCpoqW8/+4G3AEdVwomxiy8rq2O2hUMPksd8f7wSaYn/mhCD4T
g+49xbjc139xlHKDVsZplCuYYx3YfpEyR1y0EXZKnsPCv/AeQHTACAPVdAQL/NUi
AqMz00KOc0tBXLWZ9+O5flAr9qDXsqMqmgFy3E8k3JWtkekSlYswDK7WId3YRsRf
fCA2hSXijxOxoLDtjS7ugqBU3j45YcMWqHg2IDoOA415xM7Pa0Rk0IhxHauBUQb+
ynnYEKTcXKbHgVLEqjVEeDV7Al2m83Ag3Z1SqHLJ4/H83re9CMi7fCT+0+8CAwEA
AaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0
ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFLhhmpiH2PfdWeU/VZyCHTgo/RVaMB8G
A1UdIwQYMBaAFKxC5WeI3OSr+3rFsnANWqzl+V37MA0GCSqGSIb3DQEBCwUAA4IC
AQBUg2z4ritMcUEgrYvC3G1tCBBaaXBDcJCOjRJL7kRotO8YswZyREo6IwqZNqqV
VXAgVMBsnwgz2Wipzm0/NdbxZ45UWsfD+ag02Ivs+1zuVXLfPcrDqaX2sEE20r8W
Btt15sK5KX3exYiVNjIOtkZ90+ONUqDFgz1jBq2ldXpX9k3cNrFUIVTeiJY28VqV
cwOwZD3wuB+cCHO6mDH8kvnME/yV4GOmKC/AKjHKsBxwZZkSTX8ZG0fWIKFgO0vP
VgvHcnSOJRl8adjbFn5iV1zvLMNYDh3OuM5l72N9I2FFrGtGo6lkxuZYTzhoD0Z0
nycQVThnX849CUWfuEck/lGR+5C0yCQqLCLPG8XDbrfBKX1sozwCNdouDLSQwEh0
L9iCplajUKfps4oevrjb0B9z9yoQDm2XhVNBbpU4TPX8ixBM99pOuAEAokp7refP
7j0W5Ks55+SSrK26e320eUbHeY8ToyyZW3rnQHPYB+VwSX5eScuFmPoYl8ZGN9xA
HLVuMD1ITkX2Koil3yQARyQI015COguxKbTXh+XAoccHnHAj6Ynk3t4dzooJw16H
kvKyjP2+FugTWMTgQaBKD6/sOsAdGEPbjJ5kO+qjT5flcbrz1XNpyJCXI9LhUweP
yxb2CJ6gncXkbbX12xItSmbibn7xp+woOwoFPyIY6w34GA==
-----END CERTIFICATE-----
'''
    aesCipher = AESCipher("damocles_secret_")
    ciphertext = aesCipher.encrypt(plaintext)
    print(ciphertext)
    plaintext = aesCipher.decrypt(ciphertext)
    print(plaintext)
