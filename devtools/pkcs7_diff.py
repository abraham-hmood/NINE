import os, zipfile, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from signer_check import read_tlv
from cryptography import x509

def fields(tlv):
    length, off = read_tlv(tlv, 0)
    return top_level_tlvs(tlv[off : off + length])

from signer_check import top_level_tlvs

def walk_p7(p7):
    p7f = fields(p7)                     # [OID, A0]
    sdf = fields(p7f[1])                 # A0 -> one SEQ
    sdf = fields(sdf[0])                 # SignedData fields
    certs_tlv = sdf[3]
    certs = fields(certs_tlv)
    signers = fields(sdf[4])             # SET OF SignerInfo -> list of SI TLVs
    si = signers[0]
    sif = fields(si)
    print("SignerInfo fields:", [f"0x{t[0]:02x} len={len(t)}" for t in sif])
    # field3 = authenticated attributes
    attr_tlv = sif[3]
    print("signedAttrs outer:", f"tag=0x{attr_tlv[0]:02x} len={len(attr_tlv)}")
    _, aoff = read_tlv(attr_tlv, 0)
    attrs = top_level_tlvs(attr_tlv[aoff:])
    print("attr count:", len(attrs))
    for a in attrs:
        af = fields(a)
        oid = af[0][2:].hex()
        vals = fields(af[1])
        print(f"  attr oid {oid} values={[f'0x{v[0]:02x} len={len(v)}' for v in vals]}")
    return attr_tlv, sif

d = os.path.join(os.environ["TEMP"], "nine-validate")
jar = zipfile.ZipFile(os.path.join(d, "unsigned-zip.apk")).read("META-INF/NINE.RSA")
mine = zipfile.ZipFile(os.path.join(d, "signed-replica.apk")).read("META-INF/CERT.RSA")

print("=== jarsigner ==="); jar_attrs, jar_sif = walk_p7(jar)
print("=== replica ==="); my_attrs, my_sif = walk_p7(mine)

print("jarsigner signedAttrs hex:", jar_attrs.hex())
print("replica  signedAttrs hex:", my_attrs.hex())
