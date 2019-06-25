# OpenSSL CA Server By Tornado

用于私有网络中自建CA中心并进行证书的签发和认证

* [获取CA根证书](#获取ca根证书)
   * [URL](#url)
   * [Response 200:](#response-200)
   * [Response 404:](#response-404)
* [获取CA的CRL](#获取ca的crl)
   * [URL](#url-1)
   * [Response 200:](#response-200-1)
   * [Response 404:](#response-404-1)
* [签发证书](#签发证书)
   * [URL](#url-2)
   * [Parameters](#parameters)
   * [Response 200:](#response-200-2)
* [吊销证书](#吊销证书)
   * [URL](#url-3)
   * [Parameters](#parameters-1)
   * [Response 200:](#response-200-3)

------

### 更新日志

> 2019-06-25	`v1.1`
>
> * 使用`aes-256-cfb`代替`fingerprint`的验证方式
> * 杀死了部分臭虫
>
> 2019-06-04	`v1.0`
>
> * 初始版本，完成各个接口

| Method | API URL        | Remarks            | Status |
| ------ | -------------- | ------------------ | ------ |
| GET    | /api/ca/cacert | 获取CA中心的根证书 | ✔️      |
| GET    | /api/ca/crl    | 获取CA中心的CRL    | ✔️      |
| POST   | /api/ca/sign   | 签发证书           | ✔️      |
| DELETE | /api/ca/revoke | 吊销证书           | ✔️      |



### 获取CA根证书

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

`v1.1`以后不会返回404，如果CRL找不到会自动生成



### 签发证书

#### URL

`POST      /api/ca/sign`

#### Parameters

* csr_body: 用`aes-256-cfb`加密后的`base64`格式的`X509Req`
* csr_name（可选）: request文件名，不提供则默认将CommonName作为文件名

#### Response 200:

此处为了方便，不通过状态码区分返回结果，状态码一律返回200

**签发失败**将返回：

```json
{
  status: -1,
  msg: "ERROR Message"
}
```
message的具体信息如下表：

| status | message                                                      | Remarks                     |
| ------ | ------------------------------------------------------------ | --------------------------- |
| -1     | [Request error]: Missing parameters!                         | 必要参数缺失                |
|        | [Request error]: 'csr_body' field must be base64 type!       | csr_body不是base64格式      |
|        | [ERROR]: Something is error with signing processing!         | 签发证书超时 \| 签发失败    |
|        | [ERROR]: Please do not repeat the application for certificate! | 重复签发                    |
|        | [ERROR]: Wrong certificate request (X509Req) format!         | csr文件格式不正确，无法加载 |

**签发成功**将返回：

```json
{
  status: 0,
  cert: "[Your Cert Data]"
}
```



### 吊销证书

#### URL

`DELETE      /api/ca/revoke`

#### Parameters

有两种模式：通过序列号（证书丢失）和证书来进行吊销操作

* serial: 需要吊销的证书序列号(与cert二选一)，需为**16进制**格式
* cert: 需要吊销的证书(与serial二选一)

> **注意**：serial和cert都必须为用`aes-256-cfb`加密后的`base64`格式

#### Response 200:

状态码一律返回200

**吊销失败**将返回:

```json
{
  status: -1,
  msg: '[ERROR Message]'
}
```

其中error message具体信息如下表：

| status | message                                        | Remarks            |
| ------ | ---------------------------------------------- | ------------------ |
| -1     | [Request error]: Missing parameters!           | 必要参数缺失       |
|        | [ERROR]: Wrong certificate format!             | 证书格式不正确     |
|        | [ERROR]: This may be an invalid serial number! | 证书序列号无效     |
|        | [ERROR]: This certificate is revoked!          | 该证书已经被吊销   |
|        | [ERROR]: Revoke failed, unknown error!         | 吊销失败，未知错误 |

**吊销成功**则返回：

其中`Serial Number`为已吊销证书的序列号，以16进制表示

```json
{
  "status": 0,
  "msg": "Revoke Certificate success!",
  "Serial Number": "3166306230653066383662636431643b"
}
```

