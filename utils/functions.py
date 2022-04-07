from utils.config import Config
import OpenSSL
from OpenSSL.crypto import *
from os.path import *
from utils.error import *
from utils.model import *
import random
from datetime import datetime,timedelta
import time
import base64

def createKeyPair(type,bits):
    '''
    生成密钥对
    type:OpenSSL.crypto:TYPE
    bits:INT
    '''
    key = PKey()
    key.generate_key(type, bits)
    return key

def readFromFile(path,filetype,mode):
    '''
    从文件读取密钥
    path:Str
    Filetype:crypto.FILETYPE
    mode:INT
    1:私钥
    2:公钥
    3:证书
    4:CSR
    '''
    assert filetype in [FILETYPE_ASN1,FILETYPE_PEM,FILETYPE_TEXT] and mode in [1,2,3,4]
    with open(path,"rb") as f:
        buffer = f.read()
    try:
        if mode == 1:
            return load_privatekey(filetype, buffer)
        if mode == 2:
            return load_publickey(filetype, buffer)
        if mode == 3:
            return load_certificate(filetype, buffer)
        if mode == 4:
            return load_certificate_request(filetype, buffer)
    except:
        raise readFromFileError(mode)

def dumpToFile(path,filetype,mode,pkey):
    '''
    写入密钥到文件
    path:Str
    Filetype:crypto.FILETYPE
    mode:INT
    1:私钥
    2:公钥
    3:证书
    4:CSR
    5:CRL
    pkey:密钥&证书&CSR&CRL
    '''
    assert filetype in [FILETYPE_ASN1,FILETYPE_PEM,FILETYPE_TEXT] and mode in [1,2,3,4,5]
    try:
        if mode == 1:
            buffer = dump_privatekey(filetype, pkey)
        if mode == 2:
            buffer = dump_publickey(filetype, pkey)
        if mode == 3:
            buffer = dump_certificate(filetype, pkey)
        if mode == 4:
            buffer = dump_certificate_request(filetype, pkey)
        if mode == 5:
            buffer = dump_crl(filetype, pkey)
    except:
        raise dumpToFileError(mode)
    with open(path,"wb") as f:
        f.write(buffer)

class CRLHandler():
    '''和证书撤销列表相关的操作集合'''
    def __init__(self,config,kwargs,ip,verify):
        self.config = config
        self.root = config.root
        self.ca = config.x509.ca
        self.kwargs = self.handleKwargs(kwargs)
        self.ip = ip
        self.verify = verify
        self.serial = self.checkAbility()
        self.checkCA()
        self.checkOwn()
        self.addToDB()

    def handleKwargs(self,kwargs):
        returndic = {}
        if kwargs.get("cert") == None or kwargs.get("verify") == None:
            raise CRAComponentsNotComplete()
        if kwargs.get("reason") == None:
            returndic['reason'] = ""
        elif kwargs.get("reason") not in ["unspecified","keyCompromise","CACompromise","affiliationChanged","superseded","cessationOfOperation","certificateHold"]:
            raise reasonNotAvailable()
        try:
            returndic["cert"] = load_certificate(FILETYPE_PEM, kwargs.get("cert").encode("UTF8"))
        except:
            raise certDamagedError()
        returndic["verify"] = kwargs.get("verify")
        return returndic

    def checkAbility(self):
        '''验证cert与IP一致性/是否过期/是否被撤销'''
        crldb = HandleCRL(self.config)
        cert = self.kwargs["cert"]
        if cert.has_expired():
            raise certHasExpiredError()
        elif crldb.checkInDatabase(str(cert.get_serial_number())):
            raise certAlreadyRevokedError()
        elif cert.get_subject().CN != self.ip:
            raise IPNotMatchError()
        crldb.closeConnect()
        return str(cert.get_serial_number())

    def checkCA(self):
        """验证证书是否是自己签发"""
        cert = self.kwargs["cert"]
        certificate = readFromFile(self.root+self.ca.CAPath, self.config.x509.filetype, 3)
        store = X509Store()
        store.add_cert(certificate)
        ctx = X509StoreContext(store, cert)
        try:
            ctx.verify_certificate()
        except:
            raise VerifyError()
        return True

    def checkOwn(self):
        """验证发起人对证书的所有权"""
        cert = self.kwargs["cert"]
        _verify = self.kwargs["verify"]
        _verify = base64.b64decode(_verify.encode("UTF8"))
        taskverify = self.verify.encode("UTF8")
        try:
            verify(cert, _verify, taskverify, "sha256")
            return True
        except:
            raise VerifyError()
        
    def addToDB(self):
        crldb = HandleCRL(self.config)
        if crldb.checkInDatabase(self.serial):
            raise certAlreadyRevokedError()
        else:
            crldb.addToDataBase((self.serial,int(time.time()),self.kwargs["reason"]))

class CSRHandler():
    '''
    自动生成CSR
    config:utils.config.Config 配置文件
    kwargs:Dict 申请者可能上传的一些参数 包括 subject 里的参数 也包括 expire 等
    ip:str 申请者的ip
    初始化后 可通过 self.pkey 访问将被签发证书的公私钥 self.req 访问将被签发证书的签发请求 self.kwargs 访问将被签发证书的参数列表
    '''
    def __init__(self,config,kwargs,ip):
        self.config = config
        self.kwargs = {}
        if ip != self.config.x509.bindIP:
            self.checkArgs(kwargs) #如果不是给 自己网页服务签发的 就需要验证 kwargs 的正确性
        result = self.createCSR(ip, kwargs)
        if result == None:
            raise generateSSLFailedError()
        self.pkey , self.req = result

    def checkArgs(self,kwargs):
        '''
        验证 kwargs 的正确性
        rtype:bool
        '''
        for i in kwargs.keys():
            if i not in ['expire','version','digest','type','bits','countryName','C','stateOrProvinceName','ST','localityName','L','organizationName','O','organizationalUnitName','OU','emailAddress']:
                raise keyNotAvailable(i)
            if i in ['C','countryName'] and len(kwargs[i])>2:
                raise countryNameTooLong(len(kwargs[i]))
            if i == 'expire' and kwargs[i] > 60*60*24*365*4:
                raise expireTimeLongerThanExcept(kwargs[i])
            if i == 'version' and kwargs[i] not in [1,2,3]:
                raise versionError()
            if i == 'digest' and kwargs[i] not in ["md5","sha256","sha1"]:
                raise digestError()
            if i == 'type' and kwargs[i] not in ["RSA","DSA","EC","DH"]:
                raise typeError()
            if i == 'bits' and kwargs[i] not in [1024,2048,4096,8192]:
                raise bitsError()
        return True

    def handleTypes(self,types):
        '''
        把 str type 转换为 OpenSSL.crypto.TYPE 
        '''
        if types == "RSA":
            return TYPE_RSA
        elif types == "DSA":
            return TYPE_DSA
        elif types == "DH":
            return TYPE_DH
        elif types == "EC":
            return TYPE_EC

    def clearilizeArgs(self,kwargs):
        '''
        处理得到最终版本的 kwargs (因为要考虑到默认 CSR 配置的问题)
        '''
        csr = self.config.x509.csr
        returndic = {}
        returndic['expire'] = csr.expire if kwargs.get('expire') == None else kwargs.get('expire') #如果 kwargs 没有指定 expire，就使用默认 expire
        returndic['version'] = csr.version if kwargs.get('version') == None else kwargs.get('version')
        returndic['digest'] = csr.digest if kwargs.get('digest') == None else kwargs.get('digest')
        returndic['type'] = csr.type if kwargs.get('type') == None else self.handleTypes(kwargs.get('type'))
        returndic['bits'] = csr.bits if kwargs.get('bits') == None else kwargs.get('bits')

        if kwargs.get('countryName') != None or csr.countryName != None:
            returndic['countryName'] = csr.countryName if kwargs.get('countryName') == None else kwargs.get('countryName')
        if kwargs.get('C') != None or csr.C != None:
            returndic['C'] = csr.C if kwargs.get('C') == None else kwargs.get('C')
        if kwargs.get('stateOrProvinceName') != None or csr.stateOrProvinceName != None:
            returndic['stateOrProvinceName'] = csr.stateOrProvinceName if kwargs.get('stateOrProvinceName') == None else kwargs.get('stateOrProvinceName')
        if kwargs.get('ST') != None or csr.ST != None:
            returndic['ST'] = csr.ST if kwargs.get('ST') == None else kwargs.get('ST')
        if kwargs.get('localityName') != None or csr.localityName != None:
            returndic['localityName'] = csr.localityName if kwargs.get('localityName') == None else kwargs.get('localityName')
        if kwargs.get('L') != None or csr.L != None:
            returndic['L'] = csr.L if kwargs.get('L') == None else kwargs.get('L')
        if kwargs.get('organizationName') != None or csr.organizationName != None:
            returndic['organizationName'] = csr.organizationName if kwargs.get('organizationName') == None else kwargs.get('organizationName')
        if kwargs.get('O') != None or csr.O != None:
            returndic['O'] = csr.O if kwargs.get('O') == None else kwargs.get('O')
        if kwargs.get('organizationalUnitName') != None or csr.organizationalUnitName != None:
            returndic['organizationalUnitName'] = csr.organizationalUnitName if kwargs.get('organizationalUnitName') == None else kwargs.get('organizationalUnitName')
        if kwargs.get('OU') != None or csr.OU != None:
            returndic['OU'] = csr.OU if kwargs.get('OU') == None else kwargs.get('OU')
        if kwargs.get('emailAddress') != None or csr.emailAddress != None:
            returndic['emailAddress'] = csr.emailAddress if kwargs.get('emailAddress') == None else kwargs.get('emailAddress')
        return returndic

    def _createCSR(self,ip,kwargs):
        '''
        内调的生成CSR函数 只涉及到 kwargs subject相关内容
        ip:str
        kwargs:dict
        rtype:
            pkey:PKCS7
            req:X509Req
        or:
            None:Nonetype
        '''
        pkey = createKeyPair(kwargs['type'], kwargs['bits'])
        req = X509Req()
        subject = req.get_subject()
        if kwargs.get('countryName') != None:
            subject.countryName = kwargs.get('countryName')
        if kwargs.get('C') != None:
            subject.C = kwargs.get('C')
        if kwargs.get('stateOrProvinceName') != None:
            subject.stateOrProvinceName = kwargs.get('stateOrProvinceName')
        if kwargs.get('ST') != None:
            subject.ST = kwargs.get('ST')
        if kwargs.get('localityName') != None:
            subject.localityName = kwargs.get('localityName')
        if kwargs.get('L') != None:
            subject.L = kwargs.get('L')
        if kwargs.get('organizationName') != None:
            subject.organizationName = kwargs.get('organizationName')
        if kwargs.get('O') != None:
            subject.O = kwargs.get('O')
        if kwargs.get('organizationalUnitName') != None:
            subject.organizationalUnitName = kwargs.get('organizationalUnitName')
        if kwargs.get('OU') != None:
            subject.OU = kwargs.get('OU')
        if kwargs.get('emailAddress') != None:
            subject.emailAddress = kwargs.get('emailAddress')
        subject.CN = ip #使用 ip 当 commonname
        subject.commonName = ip
        req.set_pubkey(pkey)
        req.sign(pkey, kwargs['digest'])
        if req.verify(pkey) == 0:#未通过校验
            raise CSRNotVertified()
        else:
            return pkey,req

    def createCSR(self,ip,kwargs):
        '''
        集成生成CSR
        ip:str
        kwargs:dict
        '''
        kwargs = self.clearilizeArgs(kwargs)
        self.kwargs = kwargs
        return self._createCSR(ip, kwargs)

class CAHandler():
    '''和CA相关操作的集合'''
    def __init__(self,config):
        self.root = config.root
        self.ca = config.x509.ca
        self.config = config
        self.sslcfg = config.x509.server
        self.csrcfg = config.x509.csr

    def checkHasCA(self):
        '''判断是否存在CA文件'''
        return isfile(self.root+self.ca.CAPath) and isfile(self.root+self.ca.privateKeyPath) and isfile(self.root+self.ca.publicKeyPath)

    def checkCAAbility(self):
        '''判断CA文件完整性和可用性'''
        certificate = readFromFile(self.root+self.ca.CAPath, self.config.x509.filetype, 3)
        privatekey = readFromFile(self.root+self.ca.privateKeyPath, self.config.x509.filetype, 1)
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        context.use_privatekey(privatekey)
        context.use_certificate(certificate)
        try:
            context.check_privatekey()
            return True
        except:
            return False

    def GenerateCA(self):
        '''生成CA并且按照config把文件dump到指定位置'''
        key = createKeyPair(self.ca.type,self.ca.bits)
        dumpToFile(self.config.root+self.ca.privateKeyPath, self.config.x509.filetype, 1, key)
        dumpToFile(self.config.root+self.ca.publicKeyPath, self.config.x509.filetype, 2, key)
        CA = X509()
        CA.set_version(self.config.x509.ca.version)
        CA.set_serial_number(self.config.x509.ca.serial_number)
        if self.config.x509.ca.CAIssuer.countryName != None:
            CA.get_subject().countryName = self.config.x509.ca.CAIssuer.countryName
        if self.config.x509.ca.CAIssuer.C != None:
            CA.get_subject().C = self.config.x509.ca.CAIssuer.C
        if self.config.x509.ca.CAIssuer.stateOrProvinceName != None:
            CA.get_subject().stateOrProvinceName = self.config.x509.ca.CAIssuer.stateOrProvinceName
        if self.config.x509.ca.CAIssuer.ST != None:
            CA.get_subject().ST = self.config.x509.ca.CAIssuer.ST
        if self.config.x509.ca.CAIssuer.localityName != None:
            CA.get_subject().localityName = self.config.x509.ca.CAIssuer.localityName
        if self.config.x509.ca.CAIssuer.L != None:
            CA.get_subject().L = self.config.x509.ca.CAIssuer.L
        if self.config.x509.ca.CAIssuer.organizationName != None:
            CA.get_subject().organizationName = self.config.x509.ca.CAIssuer.organizationName
        if self.config.x509.ca.CAIssuer.O != None:
            CA.get_subject().O = self.config.x509.ca.CAIssuer.O
        if self.config.x509.ca.CAIssuer.organizationalUnitName != None:
            CA.get_subject().organizationalUnitName = self.config.x509.ca.CAIssuer.organizationalUnitName
        if self.config.x509.ca.CAIssuer.OU != None:
            CA.get_subject().OU = self.config.x509.ca.CAIssuer.OU
        if self.config.x509.ca.CAIssuer.commonName != None:
            CA.get_subject().commonName = self.config.x509.ca.CAIssuer.commonName
        if self.config.x509.ca.CAIssuer.CN != None:
            CA.get_subject().CN = self.config.x509.ca.CAIssuer.CN
        if self.config.x509.ca.CAIssuer.emailAddress != None:
            CA.get_subject().emailAddress = self.config.x509.ca.CAIssuer.emailAddress
        CA.gmtime_adj_notBefore(0)
        CA.gmtime_adj_notAfter(self.config.x509.ca.expire)
        CA.set_issuer(CA.get_subject())
        CA.set_pubkey(key)
        CA.add_extensions([
        X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:5"),#CA证书，每个路径上最多5个非终端子CA
        X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),#Key使用:用于签证书&签Crl
        X509Extension(b"crlDistributionPoints", True, b"URI:https://"+self.config.x509.bindIP.encode("UTF8")+b"/"+self.config.x509.ca.crl.encode("UTF8")),#设置Crl分发点
                        ])
        CA.sign(key,self.config.x509.ca.digest)
        dumpToFile(self.config.root+self.ca.CAPath, self.config.x509.filetype, 3, CA)
        return CA
        
    def ensureCA(self):
        '''整合操作，保证CA正确性和可用性'''
        if not self.checkHasCA() or not self.checkCAAbility():
            self.GenerateCA()

    def SignwithCSR(self,req,ppkey,dic,ip):
        '''
        对指定的CSR文件签名生成证书 需要处理本地 cert 和其他 cert 的区别
        req:X509req
        ppkey:X509req CSR的密钥
        dic:dict 已经处理好的配置
        ip:str 需要签名的IP
        rtype:
            None:Nonetype
        or
            pbk:buffer 公钥
            pvk:buffer 私钥
            signed:buffer 证书
        '''
        if ip == self.config.x509.bindIP: # 本地 cert 用本地的配置
            version = self.sslcfg.version# if dic.get("version") == None else dic.get("version")
            expire = self.sslcfg.expire# if dic.get("expire") == None else dic.get("expire")
            digest = self.sslcfg.digest# if dic.get("digest") == None else dic.get("digest")
        else:
            version = self.csrcfg.version if dic.get("version") == None else dic.get("version")
            expire = self.csrcfg.expire if dic.get("expire") == None else dic.get("expire")
            digest = self.csrcfg.digest if dic.get("digest") == None else dic.get("digest")

        crt = readFromFile(self.config.root+self.ca.CAPath, self.config.x509.filetype, 3)
        pkey = readFromFile(self.config.root+self.ca.privateKeyPath, self.config.x509.filetype, 1)
        cert = X509()
        cert.set_serial_number(random.randint(0, 1e64))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expire)
        cert.set_issuer(crt.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.set_version(version)
        cert.add_extensions([
            X509Extension(b"basicConstraints", True, b"CA:FALSE"),
            X509Extension(b"keyUsage", True, b"Digital Signature, Key Encipherment"),
            X509Extension(b"subjectAltName", True, b'IP:'+ip.encode("UTF8"))
                            ])
        cert.sign(pkey, digest)
        if ip == self.config.x509.bindIP:
            dumpToFile(self.root+self.sslcfg.certPath, self.config.x509.filetype, 3, cert)
            dumpToFile(self.root+self.sslcfg.publicKeyPath, self.config.x509.filetype, 2, ppkey)
            dumpToFile(self.root+self.sslcfg.privateKeyPath, self.config.x509.filetype, 1, ppkey)
            return None
        else:
            pbk = dump_publickey(self.config.x509.filetype, ppkey)
            pvk = dump_privatekey(self.config.x509.filetype, ppkey)
            signed = dump_certificate(self.config.x509.filetype, cert)
            return pbk,pvk,signed

class ServerSSLHandler():
    """和CA服务器SSL证书密钥相关的操作"""
    def __init__(self,config):
        self.config = config
        self.root = config.root
        self.server = config.x509.server

    def checkHasSSL(self):
        '''判断是否存在SSL证书密钥文件'''
        return isfile(self.root+self.server.certPath) and isfile(self.root+self.server.privateKeyPath) and isfile(self.root+self.server.publicKeyPath)
    
    def checkSSLMatch(self):
        '''判断SSL证书和私钥是否匹配'''
        certificate = readFromFile(self.root+self.server.certPath, self.config.x509.filetype, 3)
        privatekey = readFromFile(self.root+self.server.privateKeyPath, self.config.x509.filetype, 1)
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        context.use_privatekey(privatekey)
        context.use_certificate(certificate)
        try:
            context.check_privatekey()
            return True
        except:
            return False
    
    def checkSSLAbility(self):
        '''判断是否是CA签署的证书'''
        CA = readFromFile(self.root+self.config.x509.ca.CAPath, self.config.x509.filetype, 3)
        SSL = readFromFile(self.root+self.server.certPath, self.config.x509.filetype, 3)
        store = X509Store()
        store.add_cert(CA)
        store_ctx = X509StoreContext(store, SSL)
        try:
            store_ctx.verify_certificate()
            return True
        except:
            return False

    def generateSSL(self):
        '''生成SSL证书和密钥'''
        sbj = self.config.x509.server.subject
        dic = sbj.__dict__
        for key in list(dic.keys()):
            if not dic.get(key):
                del dic[key]
        csr = CSRHandler(self.config,dic,self.config.x509.bindIP)
        ca = CAHandler(self.config)
        ca.SignwithCSR(csr.req, csr.pkey,csr.kwargs, self.config.x509.bindIP)

    def ensureSSL(self):
        """保证SSL证书和密钥的存在和合法性"""
        if not self.checkHasSSL() or not self.checkSSLMatch() or not self.checkSSLAbility():
            self.generateSSL()

def transferTime(time):
    d = datetime.fromtimestamp(time)
    return d.strftime("%Y%m%d%H%M%SZ").encode("UTF8")

def CRLGenerate(config):
    fullpath = config.root+config.crl.crlpath
    time = config.crl.updatetime
    certpath = config.x509.ca.CAPath
    privpath = config.x509.ca.privateKeyPath
    filetype = config.x509.filetype
    crl = CRL()
    crl.set_version(2)
    crl.set_lastUpdate(datetime.now().strftime("%Y%m%d%H%M%SZ").encode("UTF8"))
    crl.set_nextUpdate((datetime.now()+timedelta(seconds=time)).strftime("%Y%m%d%H%M%SZ").encode("UTF8"))
    cert = readFromFile(certpath, filetype, 3)
    prvkey = readFromFile(privpath, filetype, 1)
    crlist = HandleCRL(config)
    for revoke in crlist.dumpAll():
        rvk = Revoked()
        rvk.set_serial(revoke[0].encode("UTF8"))
        rvk.set_rev_date(transferTime(revoke[1]))
        if revoke[2] != "":
            rvk.set_reason(revoke[2].encode("UTF8"))
        else:
            rvk.set_reason(None)
        crl.add_revoked(rvk)
    crl.sign(cert, prvkey, config.crl.digest.encode("UTF8"))
    crlist.closeConnect()
    dumpToFile(fullpath, filetype, 5, crl)

def runCRL(config):
    while True:
        try:
            CRLGenerate(config)
            time.sleep(config.crl.updatetime)
        except:
            pass