import socket
import os, sys
import ssl
import base64
import json
from urllib import request

API_DOMAIN = "http://localhost:9589"


def httpPost(url,
             params,
             header={"Content-Type": "application/json; charset=utf-8"}):
    req = request.Request(url)
    for type, value in header.items():
        req.add_header(type, value)
    data = json.dumps(params)
    jsondataasbytes = data.encode('utf-8')
    req.add_header('Content-Length', len(jsondataasbytes))
    return request.urlopen(req, jsondataasbytes)


def applyForCert(csrpath, certpath):
    with open(csrpath, "rb") as f:
        csrfile = f.read()
    if csrfile:
        params = {
            "csr_name": "server",
            "csr_body": base64.b64encode(csrfile).decode('utf8'),
            "f": "[input your server fingerprint]"  # fingerprint
        }
        response = httpPost(url=API_DOMAIN + "/api/ca/sign", params=params)
        ret = json.loads(response.read())
        if ret['status'] == 0:
            with open(certpath, "w") as f:
                f.write(ret['cert'])
            return True
        elif ret['status'] == -1:
            print("[ERROR]: Apply for Cert error: " + ret['msg'])
            return False
    else:
        return False


class server_ssl:
    def __init__(self):
        self.KEY_FILE = "/etc/ssl/private/server.key"
        self.CERT_FILE = "/etc/ssl/private/server.crt"
        self.CSR_FILE = "/etc/ssl/private/server.csr"
        # 如果找不到server证书文件 则请求证书
        if not os.path.exists(self.CERT_FILE):
            ret = applyForCert(self.CSR_FILE, self.CERT_FILE)
            # 请求失败终止运行
            if not ret:
                sys.exit(0)

        # 获取CA certificate
        self.CA_FILE = "/etc/ssl/private/cacert.pem"
        if not os.path.exists(self.CA_FILE):
            r = request.urlopen(API_DOMAIN + "/api/ca/cacert")
            with open(self.CA_FILE, "wb") as f:
                f.write(r.read())

    def build_listen(self):
        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.CA_FILE)
        context.check_hostname = False
        context.load_cert_chain(certfile=self.CERT_FILE, keyfile=self.KEY_FILE)

        # 监听端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # 将socket打包成SSL socket
            with context.wrap_socket(sock, server_side=True) as ssock:
                ssock.bind(('0.0.0.0', 9054))
                ssock.listen(50)
                while True:
                    # 接收客户端连接
                    client_socket, addr = ssock.accept()
                    # 接收客户端信息
                    msg = client_socket.recv(1024).decode("utf-8")
                    print("receive msg from client {}: {}".format(addr, msg))
                    # 向客户端发送信息
                    msg = "yes , you have client_socketect with server.\r\n".encode(
                        "utf-8")
                    client_socket.send(msg)
                    client_socket.close()


if __name__ == "__main__":
    server = server_ssl()
    server.build_listen()
