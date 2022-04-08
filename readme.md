# 一个内网中对 IP 颁发证书的简单 CA 实现

## 需求

Nebula 某些内网服务对外( VPN )暴露时有些安全性的需要,并且也希望浏览器能带上小锁，不会显示不安全。于是尝试在内网中实现自签名证书。做了一些简单的调研之后发现，网上的大部分教程都是自签自用，不符合我们对内网的定位；还有一部分稍微成熟一点的解决方案没有提供签发 IP 证书的支持或者没有 CRL 证书撤销列表。综合考量之后我选择自己实现一个简单的 PKI 体系进行内网自签名 CA 对 IP 证书的签发与撤销。

## 思路

查询了 [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.txt) 和 [pyopenssl](https://www.pyopenssl.org/en/stable/api/) 官方文档之后，我发现思路其实很简单。首先自签名一个证书当作根CA证书，接下来为自己的 IP 签发一个用于 Https 服务的证书并以此接口提供证书签发服务。这里我假定 CA 是可以信任的，为了减轻客户端的压力，公私钥由服务端生成，但是服务端并不保存任何信息。当内网中的主机希望申请证书时，需要向服务端发起请求，服务端进行校验之后代替其生成 CSR 并完成签发过程。当内网中的主机希望撤销证书的时候，需要向服务端发起请求，服务端校验之后将证书有关信息加入 CRL 中并定期更新 CRL 列表。

## 使用方法

一共有三个 branch ，分别是主分支、docker、简单适配的 CAclient，服务端建议使用主分支，因为 docker 的网络架构需要额外做一些工作( IP 和签名 IP 不符合的问题)

```bash
git clone https://github.com/youremailaddress/intranetCA.git
```

记得修改 `utils/config.py` 下的相关项，配置属于你自己的 CA

运行 `app.py` ，在 `CA`目录下可以看到自己的自签名根证书、公私钥，在 `server` 目录下可以看到自己的服务端根证书、公私钥

## 公钥配置

一切就绪后，我们发现浏览器和 curl 等依然无法使用 HTTPS 服务，这是因为本机没有配置信任 CA 。首先要把 CA 证书分发到内网中需要的位置，然后在其电脑上添加至信任的根证书目录

一些添加公钥信任的教程:

[Adding trusted root certificates to the server (gfi.com)](https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html)

[添加与证书颁发机构（CA）的信任 | Enterprise Architect 用户指南 (uml.com.cn)](http://tool.uml.com.cn/ToolsEA/User Guide15.2-cn/model_repository/cloud_server_ca.html)

需要说明的是，一些工具和个别浏览器使用的并不是本地电脑根证书目录，对于这些我们需要额外添加。

- 对 Curl:[ssl - Add self signed certificate to ubuntu for use with curl - Stack Overflow](https://stackoverflow.com/questions/5109661/add-self-signed-certificate-to-ubuntu-for-use-with-curl)

- 对Pip:[python - How to add a custom CA Root certificate to the CA Store used by pip in Windows? - Stack Overflow](https://stackoverflow.com/questions/39356413/how-to-add-a-custom-ca-root-certificate-to-the-ca-store-used-by-pip-in-windows)
- 对 requests 的临时解决方案:在每次 get or post 时添加 `verify=the-verify-path`
- 长期解决方案见[ssl - Python Requests - How to use system ca-certificates (debian/ubuntu)? - Stack Overflow](https://stackoverflow.com/questions/42982143/python-requests-how-to-use-system-ca-certificates-debian-ubuntu)

## 目前存在的一些问题

- 同一个 IP 可以申请若干证书，并且同时有效（当然使用的时候需要证书和 ip 匹配）。这点在信任内网的前提下不会出现什么问题。
- CRL 的 下次更新时间不会被设置，从而本地 CRL 的更新时间完全取决于不同操作系统的策略而不取决于服务端更新的频率。这是`pyopenssl`库本身的问题，详见[issues-794](https://github.com/pyca/pyopenssl/issues/794#issuecomment-1091179432)