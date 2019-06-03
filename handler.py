import json, os, base64
from tornado import web, gen
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM
from tornado_mysql import pools
from config import *
from gencert import gencert


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
            self.set_status(404)
            return

        # self.set_header("Content-Type", "application/pkix-crl")
        # 设置为pem格式的CRL
        self.set_header("Content-Type", "application/x-pem-file")
        self.set_header('Content-Disposition',
                        'attachment; filename=ca_crl.pem')
        with open(crl_path, 'rb') as f:
            crl = f.read()
            self.write(crl)
        self.finish()


class GencertHandler(web.RequestHandler):
    mysql_pool = pools.Pool(
        CONN_PARAMS, max_idle_connections=1, max_recycle_sec=3)

    # gen.coroutine表示异步模式
    @gen.coroutine
    def post(self):
        action = json.loads(self.request.body)
        # check arguments existing
        if 'csr_name' not in action.keys() or 'csr_body' not in action.keys(
        ) or 'f' not in action.keys():
            self.write({
                "status": -1,
                "msg": "[Request error]: missing parameters!"
            })
            return

        action['csr_body'] = base64.b64decode(action['csr_body'])
        req = load_certificate_request(FILETYPE_PEM, action['csr_body'])
        subject = req.get_subject()
        components = dict(subject.get_components())
        # print(components)

        # 从数据库中检查fingerprint
        result = yield self.mysql_pool.execute(
            'select * from ' + VERIFY_TABLE + ' where fingerprint = %s',
            (action['f']))
        if result.rowcount == 0:
            self.write({
                "status": -1,
                "msg": "[Request error:] verification error!"
            })
            return
        # 调用生成证书函数
        ret = gencert(365, action['csr_name'], action['csr_body'])
        self.write(json.dumps(ret))
        self.finish()
