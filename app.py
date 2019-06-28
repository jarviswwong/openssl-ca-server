import json
import logging
from tornado.web import Application, RequestHandler
from tornado.ioloop import IOLoop
from handler import GetCACertHandler, GetCACrlHandler, GencertHandler, CertRevokeHandler

# 开启日志
logging.basicConfig(filename="ca_server.log",
                    filemode="a+",
                    format="%(asctime)s %(levelname)s:%(message)s",
                    datefmt="%d-%M-%Y %H:%M:%S",
                    level=logging.DEBUG)

routers = [(r'/api/ca/cacert', GetCACertHandler),
           (r'/api/ca/crl', GetCACrlHandler),
           (r'/api/ca/sign', GencertHandler),
           (r'/api/ca/revoke', CertRevokeHandler)]


def make_tornado_server():
    return Application(routers, debug=True)


if __name__ == '__main__':
    server = make_tornado_server()
    server.listen(port=9589)
    IOLoop.instance().start()