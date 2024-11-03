
from ecdsa import SigningKey
from ecdsa import VerifyingKey



private_key = SigningKey.generate()

public_key = private_key.verifying_key

with open("pub_key.pem", "wb") as f:
    f.write(public_key.to_pem())
    
with open("pub_key.pem") as f:
    public_key = VerifyingKey.from_pem(f.read())    

print(public_key)
    
#---------------------------------------------
from hashlib import sha256
from ecdsa.util import sigencode_der

#message='bfdefc'

message = bytearray([2, 118, 145, 101, 166, 249, 149, 13, 2, 58, 65, 94, 230, 104, 184, 11, 185, 107, 92, 154, 226, 3, 93, 151, 189, 251, 68, 243, 86, 23, 90, 68, 255, 111, 3, 0, 0, 0, 0, 0, 0, 187, 226, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 84, 101, 115, 116, 105, 0, 0, 0, 0, 0, 0, 0])

sig = private_key.sign_deterministic(
    message,
    hashfunc=sha256,
    sigencode=sigencode_der
)

with open("message.sig", "wb") as f:
    f.write(sig)
    
#--------------------------------------------------------------------
#from hashlib import sha256
from ecdsa import BadSignatureError
from ecdsa.util import sigdecode_der

with open("message.sig", "rb") as f:
    sig = f.read()

try:
    ret = public_key.verify(sig, message, sha256, sigdecode=sigdecode_der)
    assert ret
    print("Valid signature")
except BadSignatureError:
    print("Incorrect signature")




