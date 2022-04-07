import requests
from OpenSSL.crypto import *
import base64
url = "https://10.2.9.5"
verify = "MyCA.crt"
def hello():
    print("-------------------------------------")
    print("|       CertBot For intranetCA      |")
    print("|           Time:2022/04/07         |")
    print("|       Author:youremailaddress     |")
    print("-------------------------------------")

class readFromFileError(Exception):
    def __init__(self,mode):
        self.mode = mode
    
    def __str__(self):
        if self.mode == 1:
            return "Error loading private key file."
        elif self.mode == 2:
            return "Error loading public key file."
        elif self.mode == 3:
            return "Error loading certificate file."
        else:
            return "Error loading CSR file."

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

class keyNotAvailable(Exception):
    def __init__(self,key):
        self.key = key
    def __str__(self):
        return """Key {} not in available key list.""".format(self.key)

class countryNameTooLong(Exception):
    def __init__(self,length):
        self.length = length
    def __str__(self):
        return """CountryName(C) length is {},which is too long.""".format(self.length)

class expireTimeLongerThanExcept(Exception):
    def __init__(self,time):
        self.time = time
    
    def __str__(self):
        return """Expire time is {},which is too long.""".format(self.time)

class versionError(Exception):
    def __str__(self):
        return """Invaild version."""

class digestError(Exception):
    def __str__(self):
        return """No such digest method."""

class typeError(Exception):
    def __str__(self):
        return """Unsupport encrypt type."""

class bitsError(Exception):
    def __str__(self):
        return """Unsupport bits value."""

def content():
    print("-------------------------------------")
    print("|       1.Request for new cert      |")
    print("|     2.Request for revoke cert     |")
    print("|                3.exit             |")
    print("-------------------------------------")
    a = input("Please choose your action:")
    return a

def checkArgs(kwargs):
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

def doCSR():
    print("Get cert by filling the following form:(type enter to set default)")
    print("Here is an example suplied by CA:")
    a = requests.get(url,verify=verify)
    print(a.json()['CSR']['data'])
    data = {}
    C = input("C:")
    L = input("L:")
    O = input("O:")
    OU = input("OU:")
    ST = input("ST:")
    bits = input("bits:")
    countryName = input('countryName:')
    digest = input("digest:")
    emailAddress = input("emailAddress:")
    expire = input("expire:")
    localityName = input("localityName:")
    organizationName = input("organizationName:")
    organizationalUnitName = input("organizationalUnitName:")
    stateOrProvinceName = input("stateOrProvinceName:")
    type = input("type:")
    version = input("version:")
    data['C'] = C
    data['L'] = L
    data['O'] = O
    data['OU'] = OU
    data['ST'] = ST
    data['bits'] = bits
    data['countryName'] = countryName
    data['digest'] = digest
    data['emailAddress'] = emailAddress
    data['expire'] = expire
    data['localityName'] = localityName
    data['organizationName'] = organizationName
    data['organizationalUnitName'] = organizationalUnitName
    data['stateOrProvinceName'] = stateOrProvinceName
    data['type'] = type
    data['version'] = version
    try:
        data['bits'] = int(data['bits']) if data['bits']!="" else ""
        data['expire'] = int(data['expire']) if data['expire']!="" else ""
        data['version'] = int(data['version']) if data['version']!="" else ""
        for key in list(data.keys()):
            if data[key] == "":
                del data[key]
        checkArgs(data)
    except Exception as e:
        print("error!")
        print(str(e))
        return
    print(data)
    ipt = input("This is your data,do you really want to post?(y/n)")
    if ipt.lower() == "y":
        try:
            a = requests.post(url+"/csr",verify=verify,json=data)
        except Exception as e:
            print("error!")
            print(str(e))
            return
        if a.json()["Status"] == 1:
            print("error!")
            print(a.json()["Msg"])
            return
        else:
            with open("./certificate.crt","wb") as f:
                f.write(a.json()["cert"].encode("UTF8"))
            with open("./privatekey.pem","wb") as f:
                f.write(a.json()["privatekey"].encode("UTF8"))
            with open("./publickey.pem","wb") as f:
                f.write(a.json()["publickey"].encode("UTF8"))
            print("OK Files have been dumped to ./certificate.crt ./privatekey.pem ./publickey.pem")
            return

def doCSA():
    a = input("This action can't be rolled back,are you sure to revoke your certificate?(y/n)")
    if a.lower() != 'y':
        return
    b = input("Make sure there exists ./certificate.crt ./privatekey.pem (./publickey.pem) which you want to revoke.(y/n)")
    reason = input("input revoke reason(optional,press enter to skip),must be one of unspecified/keyCompromise/CACompromise/affiliationChanged/superseded/cessationOfOperation/certificateHold:")
    if reason not in ["","unspecified","keyCompromise","CACompromise","affiliationChanged","superseded","cessationOfOperation","certificateHold"]:
        print("reason error!")
        return
    if b.lower() != 'y':
        return
    try:
        cert = readFromFile("./certificate.crt", FILETYPE_PEM, 3)
        prvk = readFromFile("./privatekey.pem", FILETYPE_PEM, 1)
    except Exception as e:
        print("error!")
        print(str(e))
        return
    s=requests.session()
    m = s.get(url+"/cra",verify=verify)
    v = m.json()['verify'].encode("UTF8")
    ver = sign(prvk, v, "sha256")
    ver = base64.b64encode(ver).decode("UTF8")
    strcert = open("./certificate.crt","r",encoding="UTF8").read()
    if reason == "":
        data = {"verify":ver,"cert":strcert}
    else:
        data = {"verify":ver,"cert":strcert,"reason":reason}
    n = s.post(url+"/cra",verify=verify,json=data)
    if n.json()["status"] == 0:
        print("Cert has been successfully revoked.")
        return
    if n.json()["status"] == 1:
        print("error!")
        print(n.json()["Msg"])
        return
    

    
        
    
    
hello()
while True:
    m = content()
    if m == "3":
        exit()
    elif m == "1":
        doCSR()
    elif m == "2":
        doCSA()
    else:
        continue

