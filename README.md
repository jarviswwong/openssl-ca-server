# OpenSSL CA Server By Tornado

用于私有网络中自建CA中心并进行证书的签发和认证



------

## API v1.0

| Method | API URL        | Remarks            | Status |
| ------ | -------------- | ------------------ | ------ |
| GET    | /api/ca/cacert | 获取CA中心的根证书 | ✔️      |
| GET    | /api/ca/crl    | 获取CA中心的CRL    | ✔️      |
| POST   | /api/ca/sign   | 签发证书           | ✔️      |
| DELETE | /api/ca/revoke | 吊销证书           |        |



### 获取CA证书

#### URL

`GET      /api/ca/cacert`

#### Response 200:

```http
HTTP/1.1 200 OK
Server: TornadoServer/6.0.2
Content-Type: application/x-pem-file
Date: Mon, 03 Jun 2019 07:11:40 GMT
Content-Disposition: attachment; filename=cacert.pem
Etag: "234847b704fa446e60c766c8e2a4d1225ed3e404"
Content-Length: 2114
Connection: close

-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

#### Response 404:

未找到根证书



### 获取CA的CRL

#### URL

`GET      /api/ca/crl  `

#### Response 200:

```http
HTTP/1.1 200 OK
Server: TornadoServer/6.0.2
Content-Type: application/x-pem-file
Date: Mon, 03 Jun 2019 07:57:27 GMT
Content-Disposition: attachment; filename=ca_crl.pem
Etag: "1a35bbbeff23273b9d435833d443267eca5229fd"
Content-Length: 1060
Connection: close

-----BEGIN X509 CRL-----
...
-----END X509 CRL-----
```

#### Response 404:

未生成CRL文件(**后面会加入自动生成**)



### 签发证书

#### URL

`POST      /api/ca/sign`

#### Parameters

* csr_name: request文件名(可能会删除)
* csr_body: **base64**编码后的request data
* f: fingerprint，用于校验是否为私有网络中的节点

#### Response 200:

此处为了方便，不通过状态码区分返回结果，状态码一律返回200

**签发失败**将返回：

```json
{
  status: -1,
  msg: "ERROR Messages"
}
```

| status | message                                                      | Remarks                  |
| ------ | ------------------------------------------------------------ | ------------------------ |
| -1     | [Request error]: missing parameters!                         | 参数缺失                 |
|        | [Request error:] verification error!                         | fingerprint校验失败      |
|        | [ERROR]:Something is error with signing processing!          | 签发证书超时 \| 签发失败 |
|        | [ERROR]:Please do not repeat the application for certificate! | 重复签发                 |

**签发成功**将返回：

```json
{
  status: 0,
  cert: "[Your Cert Data]"
}
```



### 吊销证书

#### URL

`DELET      /api/ca/revoke`

#### Parameters

#### Response 200: