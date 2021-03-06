import os
import sys
import pexpect
from common import openssl, jsonMessage
from config import *
from OpenSSL import crypto

ca_cert_path = os.path.join(CA_ROOT, CA_CERT_FILE)
ca_key_path = os.path.join(CA_ROOT, CA_KEY_FILE)


def gencert(days,
            node_name,
            node_csr_data,
            ca_cert=ca_cert_path,
            ca_key=ca_key_path,
            X509_EXTRA_ARGS=()):

    if not os.path.exists(CA_CSR_ROOT):
        os.mkdir(CA_CSR_ROOT)
    if not os.path.exists(CA_CERT_ROOT):
        os.mkdir(CA_CERT_ROOT)
    # 写入csr文件
    csr_file = os.path.join(CA_CSR_ROOT, node_name + '.csr')
    with open(csr_file, "wb") as f:
        f.write(node_csr_data)
    cert_file = os.path.join(CA_CERT_ROOT, node_name + '.crt')
    child = openssl('ca', '-cert', ca_cert, '-keyfile',
                    ca_key, '-in', csr_file, '-out', cert_file, '-days',
                    str(days), *X509_EXTRA_ARGS)
    # 自动签名
    ret = child.expect([pexpect.TIMEOUT, pexpect.EOF, 'Sign the certificate'])
    if ret == 0 or ret == 1:
        return jsonMessage(
            -1, '[ERROR]: Something is error with signing processing!')
    if ret == 2:
        child.sendline('y')
        ret = child.expect([pexpect.EOF, 'certificate requests certified'])
        if ret == 0:
            return jsonMessage(
                -1,
                '[ERROR]: Please do not repeat the application for certificate!'
            )
        if ret == 1:
            child.sendline('y')
            sign_result = child.expect(pexpect.EOF)
            if sign_result == 0:
                msg = 'This Certificate is signed successfully, commonName is %s' % (
                    node_name)
                # 转换证书成PEM格式
                openssl('x509', '-in', cert_file, '-out', cert_file,
                        '-outform PEM')
                with open(cert_file, "r") as f:
                    return jsonMessage(0, msg, {'cert': f.read()})
            else:
                return jsonMessage(-1, '[ERROR]: Signed failure!')
