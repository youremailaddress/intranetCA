# 一个内网中对 IP 颁发证书的简单 CA 实现

## 公钥配置

一切就绪后，我们发现浏览器和 curl 等依然无法使用 HTTPS 服务，这是因为本机没有配置信任CA。把CA证书分发到内网中需要的位置，在其计算机上把CA添加入受信任的根证书颁发机构即可在浏览器里正常访问。使用 python 的，需要查询本机 `{Python_Installation_Location}\\lib\\site-packages\\certifi\\cacert.pem` 文件，在其后追加 CA 即可