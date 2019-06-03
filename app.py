import json
from tornado.web import Application, RequestHandler
from tornado.ioloop import IOLoop
from handler import GetCACertHandler, GetCACrlHandler, GencertHandler


# router
def make_tornado_server():
    urls = [(r'/api/ca/cacert', GetCACertHandler),
            (r'/api/ca/crl', GetCACrlHandler), (r'/api/ca/sign',
                                                GencertHandler)]
    return Application(urls, debug=True)


if __name__ == '__main__':
    server = make_tornado_server()
    server.listen(port=9589)
    IOLoop.instance().start()