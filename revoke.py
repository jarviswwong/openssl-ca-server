import os
import datetime
import hashlib
import pexpect
from config import *
from common import openssl, jsonMessage, gencrl
from OpenSSL import crypto


# 通过证书文件吊销证书
def revokeFromCert(cert):
    # 读取证书数据
    try:
        x509_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        # get_serial_number返回10进制的serial，需转为16进制
        serial = hex(x509_obj.get_serial_number())[2:]
    except crypto.Error:
        return jsonMessage(status=-1,
                           msg="[ERROR]: Wrong certificate (X509) format!")

    # 存到临时文件夹里
    path = os.path.join(
        '/tmp',
        hashlib.md5(str(datetime.datetime.now()).encode('utf-8')).hexdigest() +
        "_revokecert.crt")
    with open(path, "w") as f:
        f.write(cert.decode('utf8'))

    return revoking(path, serial)


# 通过serial吊销证书，方法是去CA/newcerts文件夹下寻找相应证书的备份
# @serial：必须为16进制格式
def revokeFromSerial(serial):
    path = os.path.join(CA_NEWCERTS, serial + ".pem")
    if not os.path.exists(path):
        msg = "[ERROR]: This may be an invalid serial number!"
        return jsonMessage(-1, msg)

    return revoking(path, serial)


def revoking(certfile, serial):
    child = openssl('ca', '-revoke', certfile)
    ret = child.expect(
        ['Already revoked', 'Revoking Certificate', pexpect.EOF])
    if ret == 0:
        msg = "[ERROR]: This certificate is revoked!"
        return jsonMessage(-1, msg)
    elif ret == 1:
        msg = "Revoke Certificate success! Serial number is " + serial
        # 重新生成一遍证书文件
        gencrl()
        return jsonMessage(0, msg, {"Serial Number": serial})
    elif ret == 2:
        msg = "[ERROR]: Revoke failed, unknown error!"
        return jsonMessage(-1, msg)
