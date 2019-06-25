import json
import os
import base64
import OpenSSL.crypto
from tornado import web, gen
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM
from tornado_mysql import pools
from config import *
from gencert import gencert
from revoke import revokeFromCert, revokeFromSerial
from common import jsonMessage, gencrl, AESCipher, paramFormat

# 使用aes-256-cfb算法解密csr_body，如果是解密失败（非法请求）则后续验证肯定出错
aesCipher = AESCipher(VALIDATE_SECRET)


class GetCACertHandler(web.RequestHandler):
    def get(self):
        cacert_path = os.path.join(CA_ROOT, CA_CERT_FILE)
        # 校验根证书是否存在
        if not os.path.exists(cacert_path):
            self.set_status(404)
            return

        # 设置http_header为pem格式的证书
        self.set_header("Content-Type", "application/x-pem-file")
        self.set_header('Content-Disposition',
                        'attachment; filename=cacert.pem')
        with open(cacert_path, 'r') as f:
            cacert = f.read()
            self.write(cacert)
        self.finish()


class GetCACrlHandler(web.RequestHandler):
    def get(self):
        crl_path = os.path.join(CA_ROOT, CRL_FILE)
        if not os.path.exists(crl_path):
            gencrl()
            # self.set_status(404)
            # return

        # 设置为pem格式的CRL
        self.set_header("Content-Type", "application/x-pem-file")
        self.set_header('Content-Disposition',
                        'attachment; filename=ca_crl.pem')
        with open(crl_path, 'rb') as f:
            crl = f.read()
            self.write(crl)
        self.finish()


class GencertHandler(web.RequestHandler):
    # gen.coroutine表示异步模式
    @gen.coroutine
    def post(self):
        action = paramFormat(json.loads(self.request.body))
        # check arguments existing
        if 'csr_body' not in action.keys():
            self.write(jsonMessage(-1, "[Request error]: Missing parameters!"))
            return

        try:
            action['csr_body'] = aesCipher.decrypt(action['csr_body'])
            # 如果没有传入csr_name参数，
            # 则将req中的CommonName作为文件名
            if 'csr_name' not in action.keys():
                req = load_certificate_request(FILETYPE_PEM,
                                               action['csr_body'])
                subject = req.get_subject()
                components = dict(subject.get_components())
                action['csr_name'] = components[b'CN'].decode('utf8')
        except base64.binascii.Error:
            self.write(
                jsonMessage(
                    -1,
                    "[Request error]: 'csr_body' field must be base64 type!"))
            self.finish()
            return
        except OpenSSL.crypto.Error:
            self.write(
                jsonMessage(
                    -1,
                    "[ERROR]: Wrong certificate request (X509Req) format!"))
            self.finish()
            return

        # 调用生成证书函数
        ret = gencert(365, action['csr_name'], action['csr_body'])
        self.write(ret)
        self.finish()


class CertRevokeHandler(web.RequestHandler):
    @gen.coroutine
    def delete(self):
        action = paramFormat(json.loads(self.request.body))

        # 优先验证证书
        if 'cert' in action.keys():
            certfile = aesCipher.decrypt(action['cert'])
            result = revokeFromCert(certfile)
        elif 'serial' in action.keys():
            serial = aesCipher.decrypt(action['serial']).decode('utf8')
            result = revokeFromSerial(serial)
        else:
            result = jsonMessage(-1, "[Request error]: Missing parameters!")
        self.write(result)
        self.finish()
