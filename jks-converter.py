from __future__ import print_function
import sys, base64, textwrap
import jks


def print_pem(der_bytes, type):
    print("-----BEGIN %s-----" % type)
    print("\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)))
    print("-----END %s-----" % type)


ks = jks.KeyStore.load("<JKS_PATH_FILE_HERE>", "<PASSWORD_HERE>")

for alias, pk in ks.private_keys.items():
    print("Private key: %s" % pk.alias)
    if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
        print_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        print_pem(pk.pkey_pkcs8, "PRIVATE KEY")

    for c in pk.cert_chain:
        print_pem(c[1], "CERTIFICATE")
    print()

for alias, c in ks.certs.items():
    print("Certificate: %s" % c.alias)
    print_pem(c.cert, "CERTIFICATE")
    print()

for alias, sk in ks.secret_keys.items():
    print("Secret key: %s" % sk.alias)
    print("  Algorithm: %s" % sk.algorithm)
    print("  Key size: %d bits" % sk.key_size)
    print("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key)))
    print("")
