from json import dumps
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey


# Generate privateKey from PEM string
privateKey = PrivateKey.fromPem("""
-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIS+XYQmfPFIAQ89W2C0KibWkHN4RCJajuiVOVNTnNSToAcGBSuBBAAK
oUQDQgAEfDWvjeAYzBOjomTTFqEsatfCf+l2BkuY6PrH3IszscCTJNVRr/x1yeIf
+CpQEMHTizQn5iITdeLeTx+VeAzFYg==
-----END EC PRIVATE KEY-----
""")

message = "helloworld"

signature = Ecdsa.sign(message, privateKey)

# Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
print(signature.toBase64())

# To double check if the message matches the signature, do this:
publicKey = privateKey.publicKey()
print(publicKey)

print(Ecdsa.verify(message, signature, publicKey))