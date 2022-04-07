class generateSSLFailedError(Exception):
    def __str__(self):
        return "Failed to generate SSLCert"

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

class dumpToFileError(Exception):
    def __init__(self,mode):
        self.mode = mode
    
    def __str__(self):
        if self.mode == 1:
            return "Error dumping private key file."
        elif self.mode == 2:
            return "Error dumping public key file."
        elif self.mode == 3:
            return "Error dumping certificate file."
        elif self.mode == 4:
            return "Error dumping CSR file."
        else:
            return "Error dumping CRL file."

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

class CSRNotVertified(Exception):
    def __str__(self):
        return """CSR not vertified,perhaps it's not your fault."""

class NoVerifySupplyError(Exception):
    def __str__(self):
        return """No verify is offered."""

class CRAComponentsNotComplete(Exception):
    def __str__(self):
        return """Your request's component is not complete."""

class reasonNotAvailable(Exception):
    def __str__(self):
        return """The reason you supplied is not available."""
    
class certDamagedError(Exception):
    def __str__(self):
        return """The cert you supplied is damaged."""

class certHasExpiredError(Exception):
    def __str__(self):
        return """The cert you supplied has already expired."""

class certAlreadyRevokedError(Exception):
    def __str__(self):
        return """The cert you supplied has already revoked."""

class IPNotMatchError(Exception):
    def __str__(self):
        return """The IP you supplied is not match with which in cert."""

class VerifyError(Exception):
    def __str__(self):
        return """The cert you supplied is not signed by this CA or you have no access to this cert."""

class InsertError(Exception):
    def __str__(self):
        return """Error when add to Database,perhaps it's not your fault.Please contact CA manager."""

