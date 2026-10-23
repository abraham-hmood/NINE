import os, zipfile, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer_check import read_tlv, top_level_tlvs
from cryptography import x509

apk = os.path.join(os.environ["TEMP"], "nine-validate", "signed-replica.apk")
p7 = zipfile.ZipFile(apk).read("META-INF/CERT.RSA")

def fields(tlv):
    """TLV entries inside a *full TLV* (peels one level)."""
    length, off = read_tlv(tlv, 0)
    return top_level_tlvs(tlv[off : off + length])

p7_fields = fields(p7)                        # peel outer SEQ: [OID, A0]
print("p7 field tags:", [t[0] for t in p7_fields])
sd_fields = fields(p7_fields[1])              # A0 content stream -> one SEQ TLV
sd_fields = fields(sd_fields[0])              # SignedData SEQ TLV fields
print("sd field tags:", [t[0] for t in sd_fields])
certs_tlv = sd_fields[3]                     # [0] IMPLICIT SET OF Certificate
cert_list = fields(certs_tlv)
cert = cert_list[0]
print("cert bytes:", len(cert), cert[:8].hex())
try:
    c = x509.load_der_x509_certificate(cert)
    print("parsed:", c.subject.rfc4514_string())
except Exception as e:
    print("CERT PARSE FAIL:", type(e).__name__, e)
    print(cert[:80].hex())
