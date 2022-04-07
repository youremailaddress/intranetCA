from utils.config import Config
import sqlite3
from os.path import *
from utils.error import *

class HandleCRL():
    def __init__(self,config):
        self.root = config.root
        self.path = config.crl.dbpath
        self.connect,self.cursor = self.ensureDataBase()
    
    def ensureDataBase(self):
        connect = sqlite3.connect(self.root+self.path)
        cursor = connect.cursor()
        try:
            cursor.execute('''select count(*) from CRL;''')
        except:
            cursor.execute('''CREATE TABLE CRL
                (serial       TEXT     UNIQUE NOT NULL,
                revoketime    int       NOT NULL,
                reason        TEXT    );''')
            connect.commit()
        return connect,cursor
    
    def checkInDatabase(self,serial):
        self.cursor.execute("select count(*) from CRL where serial=?",(serial,))
        if self.cursor.fetchone() == (1,):
            return True
        else:
            return False

    def addToDataBase(self,data):
        try:
            self.cursor.execute("insert into CRL (serial,revoketime,reason) values (?,?,?)",data)
            self.connect.commit()
        except:
            self.connect.rollback()
            raise InsertError()
    
    def dumpAll(self):
        self.cursor.execute("select * from CRL;")
        return self.cursor.fetchall()

    def closeConnect(self):
        self.connect.commit()
        self.connect.close()