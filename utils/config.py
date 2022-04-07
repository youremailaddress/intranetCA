import os
from OpenSSL.crypto import *
class CAIssuer():
    '''
    设置CA的签署方信息 不需要的项设为None
    '''
    def __init__(self):
        self.countryName = None #最多两个字符
        self.C = "CN" #上一个的缩写
        self.stateOrProvinceName = None 
        self.ST = "AH"
        self.localityName = None
        self.L = "HF"
        self.organizationName = "USTCCyberSec"
        self.O = "USTCCyberSec"
        self.organizationalUnitName = "USTCCyberSec Network Group"
        self.OU = "UCNG"
        self.commonName = "Nebula Certificate Authority Center"
        self.CN = "NCAC"
        self.emailAddress = "certificate@nebula.ustc.edu.cn"

class CAConfig():
    '''
    CA相关的配置
    '''
    def __init__(self):
        self.version = 2 #证书版本 0-2对应 v1-v3
        self.serial_number = 0 #自签名证书的序列号
        self.type = TYPE_RSA # 自签名证书的密钥算法
        self.bits = 8192 #自签名证书的密钥长度
        self.expire = 60*60*24*365*20 #CA过期时间
        self.CAIssuer = CAIssuer() #CA签署者信息
        self.crl = "bad.crl" #CA的CRL在访问时相对于CA站点根目录的位置(有别于存储位置)
        self.digest = "sha256" #签名CA时的摘要算法
        self.CAPath = "CA/MyCA.crt" #CA存储位置
        self.privateKeyPath = "CA/MyCAPrivateKey.pem" #CA私钥存储位置
        self.publicKeyPath = "CA/MyCAPublicKey.pem" #CA公钥存储位置

class DefaultSubject():
    '''
    subject模板
    '''
    def __init__(self):
        self.countryName = None
        self.C = None
        self.stateOrProvinceName = None
        self.ST = None
        self.localityName = None
        self.L = None
        self.organizationName = None
        self.O = None
        self.organizationalUnitName = None
        self.OU = None
        # self.commonName = "Nebula Certificate Authority Center"
        # self.CN = "NCAC"
        self.emailAddress = None

class Subject(DefaultSubject):
    '''SSL Subject，需要的项从DefaultSubject复用'''
    def __init__(self):
        DefaultSubject.__init__(self)
        self.C = "CN"
        self.stateOrProvinceName = "Anhui"
        self.ST = "AH"
        self.localityName = "Hefei"
        self.L = "HF"
        self.organizationName = "USTCCyberSec"
        self.O = "USTCCyberSec"
        self.emailAddress = "youremailaddress@github.com"

class CSRDefaultSubject(DefaultSubject):
    '''
    CSR的默认配置，优先级低于CSR自带
    '''
    def __init__(self):
        DefaultSubject.__init__(self)
        self.expire = 60*60*24
        self.version = 2
        self.digest = "sha256"
        self.type = TYPE_RSA
        self.bits = 2048

class ServerSSLConfig():
    def __init__(self):
        self.subject = Subject()
        self.version = 2
        self.expire = 60*60*24*365*5
        self.digest = "sha256"
        self.certPath = "Server/Server.crt"
        self.privateKeyPath = "Server/ServerPrivateKey.pem"
        self.publicKeyPath = "Server/ServerPublicKey.pem"

class ServerConfig():
    def __init__(self):
        self.ca = CAConfig()
        self.server = ServerSSLConfig()
        self.csr = CSRDefaultSubject()
        self.bindIP = "10.2.9.5"
        self.filetype = FILETYPE_PEM

class CRLConfig():
    def __init__(self):
        self.crlpath = "CRL/bad.crl"
        self.updatetime = 60*10
        self.dbpath = "crl.db"
        self.digest = "sha256"

class Config():
    def __init__(self):
        self.root = os.path.dirname(os.path.realpath(__file__))+"/../"
        self.x509 = ServerConfig()
        self.crl = CRLConfig()
