from flask import Flask,request,session,send_from_directory,make_response
import OpenSSL
from OpenSSL.crypto import *
from utils.config import Config
from utils.functions import *
import base64,os
from multiprocessing import Process

conf = Config()
CA = CAHandler(conf)
CA.ensureCA()
ServerSSL = ServerSSLHandler(conf)
ServerSSL.ensureSSL()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=15)

@app.route('/',methods=['GET'])
def usage():
    return {
        "CSR":
        {
            "point":"/csr",
            "data":
                {
                "expire":"INT Optional",
                "version":"INT Optional",
                "digest":"Str Optional",
                "type":"Str Optional",
                "bits":"INT Optional",
                "countryName":"Str but at most 2 chars Optional",
                "C":"Str but at most 2 chars Optional",
                "stateOrProvinceName":"Str Optional",
                "ST":"Str Optional",
                "localityName":"Str Optional",
                "L":"Str Optional",
                "organizationName":"Str Optional",
                "O":"Str Optional",
                "organizationalUnitName":"Str Optional",
                "OU":"Str Optional",
                "emailAddress":"Str Optional"
                },
            "return":
                {
                "Status":"0 # 0 if OK else 1",
                "Msg":"Str if not OK",
                'publickey':"Str if OK",
                'privatekey':"Str if OK",
                'cert':"Str if OK"
                }
        },
        "CRA":
        {
            "point":"/cra",
            "first-time":
                {
                "method":"GET",
                "return":
                    {
                    "verify":"str"
                    }
                },
            "second-time":
                {
                "data":
                    {
                    "cert":"str",
                    "verify":"base64 signed uuid",
                    "reason":"str optional in[unspecified/keyCompromise/CACompromise/affiliationChanged/superseded/cessationOfOperation/certificateHold]"
                    },
                "return":
                    {
                    "status":"0 or 1",
                    "Msg":"OK or Errors"
                    }
                }
        },
        "CRL":
        {
            "point":"/"+conf.x509.ca.crl,
            "return":"CRL"
        }
    }

@app.route('/csr',methods=['POST'])
def req():
    dic = request.json
    ip = request.remote_addr
    try:
        csr = CSRHandler(conf, dic, ip)
        pbk,pvk,signed = CA.SignwithCSR(csr.req, csr.pkey, csr.kwargs, ip)
    except Exception as e:
        return {
            "Status":1,
            "Msg":str(e)
        }
    return {
        "Status":0,
        "publickey":pbk.decode("UTF8"),
        "privatekey":pvk.decode("UTF8"),
        "cert":signed.decode("UTF8")
    }

@app.route('/cra',methods=['GET','POST'])
def remove():
    if request.method == "GET":
        session["verify"] = base64.b64encode(os.urandom(46)).decode("UTF8")
        session.permanent = True
        return {
            "verify":session["verify"]
        }
    else:
        try:
            if session.get("verify") == None:
                raise NoVerifySupplyError()
            dic = request.json
            ip = request.remote_addr
            CRLHandler(conf, dic, ip, session['verify'])
        except Exception as e:
            return {
            "status": 1,
            "Msg": "{}".format(str(e))
            }
        return {
            "status":0
        }

@app.route("/"+conf.x509.ca.crl,methods=['GET'])
def fetch():
    fullpath = conf.root+conf.crl.crlpath
    try:
        response = make_response(
            send_from_directory(fullpath.rsplit("/",1)[0], fullpath.rsplit("/",1)[1], as_attachment=True))
        return response
    except Exception as e:
        return {
            "status": "1",
            "Msg": "{}".format(str(e))
            }

if __name__ == '__main__':
    p = Process(target=runCRL, args=(conf,))
    p.start()
    app.run(conf.x509.bindIP, debug=True,port=443,threaded=True,ssl_context=(conf.x509.server.certPath, conf.x509.server.privateKeyPath))
    p.join()