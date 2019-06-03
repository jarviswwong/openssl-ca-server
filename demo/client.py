import socket
import os, sys
import ssl
import base64, json
from urllib import request
from OpenSSL import crypto

API_DOMAIN = "http://localhost:9589"

CRL_FILE_NAME = "ca_crl.pem"


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
            "csr_name": "client",
            "csr_body": base64.b64encode(csrfile).decode('utf8'),
            "f": "[input your client fingerprint]"  # fingerprint
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


class client_ssl:
    def __init__(self):
        self.KEY_FILE = "/etc/ssl/private/client.key"
        self.CERT_FILE = "/etc/ssl/private/client.crt"
        self.CSR_FILE = "/etc/ssl/private/client.csr"
        # 如果找不到server证书文件 则请求证书
        if not os.path.exists(self.CERT_FILE):
            ret = applyForCert(self.CSR_FILE, self.CERT_FILE)
            # 请求失败终止运行
            if not ret:
                sys.exit(0)

        # 获取CA的certificate
        self.CA_FILE = "/etc/ssl/private/cacert.pem"
        if not os.path.exists(self.CA_FILE):
            r = request.urlopen(API_DOMAIN + "/api/ca/cacert")
            with open(self.CA_FILE, "wb") as f:
                f.write(r.read())

        # 获取CA的CRL，由于python.ssl库中load_verify_locations的限制，只能保存文件到本地后读取
        r = request.urlopen(API_DOMAIN + "/api/ca/crl")
        # 此处默认将其保存在临时文件夹/tmp中
        os.chdir("/tmp")
        with open(CRL_FILE_NAME, "wb") as f:
            f.write(r.read())
        self.CRL_FILE = os.path.join(os.getcwd(), CRL_FILE_NAME)

    def send_hello(self):

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.CA_FILE)
        context.load_cert_chain(certfile=self.CERT_FILE, keyfile=self.KEY_FILE)
        context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
        # This method can also load certification revocation lists (CRLs) in PEM or DER format.
        context.load_verify_locations(self.CRL_FILE)

        # 与服务端建立socket连接
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # server_hostname必须填写服务端证书的hostname
            with context.wrap_socket(
                    sock, server_hostname="demo.server.org") as ssock:
                ssock.connect(('demo.server.org', 9054))
                # 向服务端发送信息
                msg = "do i connect with server ?".encode("utf-8")
                ssock.send(msg)
                # 接收服务端返回的信息
                msg = ssock.recv(1024).decode("utf-8")
                print("receive msg from server : {}".format(msg))
                ssock.close()


if __name__ == "__main__":
    client = client_ssl()
    client.send_hello()