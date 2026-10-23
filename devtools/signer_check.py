"""Offline replica of com.nine.dbt.ApkV1Signer (Kotlin) for v1-signature validation.

Builds an APK whose ZIP entries match app/src/main/assets/shell-template.apk,
signs it v1 exactly the way the Kotlin signer does (after the nesting fix),
and leaves the result for `apksigner verify`.

Also demonstrates the bug we hit on device: certContent() returns the
tbsCertificate *TLV* (tag+len+content), so topLevelTlvs() walking that stream
yields exactly 3 TLVs ([tbs, sigAlg, sig]) and attrs[3] throws
"Index 3 out of bounds for length 3".

Usage:
    python devtools/signer_check.py [path-to-template-apk]
"""
import base64
import hashlib
import io
import os
import sys
import zipfile
from datetime import datetime, timezone
from collections import deque

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as cpad
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(os.environ.get("TEMP", HERE), "nine-validate")
os.makedirs(OUT, exist_ok=True)

# ---------- Kotlin-identical DER primitives ----------


def _der_tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n <= 0xFF:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([tag]) + ln + content


def der_seq(*parts: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(parts))


def der_set(*parts: bytes) -> bytes:
    return _der_tlv(0x31, b"".join(parts))


def der_ctx0(content: bytes) -> bytes:
    return _der_tlv(0xA0, content)


def der_oid(dotted: str) -> bytes:
    p = [int(x) for x in dotted.split(".")]
    body = bytearray([p[0] * 40 + p[1]])
    for v in p[2:]:
        # Kotlin: ArrayDeque addLast LSB..MSB, removeLast pops MSB-first
        stack = []
        if v == 0:
            stack.append(0)
        while v > 0:
            stack.append(v & 0x7F)
            v >>= 7
        while stack:
            b = stack.pop()
            body.append(b | 0x80 if stack else b)
    return _der_tlv(0x06, bytes(body))


def der_octet(c: bytes) -> bytes:
    return _der_tlv(0x04, c)


def der_bitstring(c: bytes) -> bytes:
    return _der_tlv(0x03, b"\x00" + c)


def der_int_bytes(v: int) -> bytes:
    # BigInteger.toByteArray() equivalent: minimal two's complement, sign bit
    n = max(1, (v.bit_length() + 7) // 8)
    b = v.to_bytes(n, "big")
    if v < 0x80:  # matches BigInteger only when positive and < 0x80 stays 1 byte
        pass
    return b


def der_int(v: int) -> bytes:
    return _der_tlv(0x02, int_le_bytes(v))


def der_utf8(s: str) -> bytes:
    return _der_tlv(0x0C, s.encode("utf-8"))


def der_utctime(s: str) -> bytes:
    return _der_tlv(0x17, s.encode("ascii"))


OID_RSA = "1.2.840.113549.1.1.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_DATA = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_CN = "2.5.4.3"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_PKCS9_CONTENT_TYPE = "1.2.840.113549.1.9.3"


def alg_rsa_only(oid: str) -> bytes:
    return der_seq(der_oid(oid), _der_tlv(0x05, b""))


def sha256_alg_id() -> bytes:
    return alg_rsa_only(OID_SHA256_RSA)


def sha256_digest_alg() -> bytes:
    """Plain SHA-256 AlgorithmIdentifier (digest algorithm, no RSA wrapper)."""
    return der_seq(der_oid(OID_SHA256))


def null_alg() -> bytes:
    return alg_rsa_only(OID_RSA)


# ---------- readTlv / certContent / topLevelTlvs (Kotlin, verbatim) ----------


def read_tlv(b: bytes, at: int):
    """Kotlin: returns (contentLen, contentOff)."""
    len_byte = b[at + 1]
    length, off = len_byte, at + 2
    if len_byte == 0x81:
        length, off = b[at + 2], at + 3
    elif len_byte == 0x82:
        length, off = (b[at + 2] << 8) | b[at + 3], at + 4
    return length, off


def cert_content(cert: bytes) -> bytes:
    length, off = read_tlv(cert, 0)
    return cert[off : off + length]


def top_level_tlvs(tbs_content: bytes):
    at, out = 0, []
    while at + 2 <= len(tbs_content):
        length, off = read_tlv(tbs_content, at)
        out.append(tbs_content[at : off + length])
        at = off + length
    return out


def cert_tbs_tlvs(cert: bytes):
    """The FIXED chain: outer SEQ content -> tbs TLV -> tbs content walked."""
    tbs_tlv = cert_content(cert)
    length, off = read_tlv(tbs_tlv, 0)
    return top_level_tlvs(tbs_tlv[off : off + length])


# ---------- certificate builder (Kotlin-identical) ----------


def int_le_bytes(v: int) -> bytes:  # BigInteger(v).toByteArray()
    n = max(1, (v.bit_length() + 7) // 8)
    return v.to_bytes(n, "big")


def rsa_sign(key, data: bytes) -> bytes:
    return key.sign(data, cpad.PKCS1v15(), hashes.SHA256())


def self_signed_cert(key, cn: str = "NINE Shell") -> bytes:
    serial = int.from_bytes(os.urandom(8), "big") >> 4  # 60-bit
    name = der_seq(der_set(der_seq(der_oid(OID_CN), der_utf8(cn))))
    spki = der_seq(
        null_alg(),
        der_bitstring(
            der_seq(
                _der_tlv(0x02, int_le_bytes(key.public_key().public_numbers().n)),
                _der_tlv(0x02, int_le_bytes(key.public_key().public_numbers().e)),
            )
        ),
    )
    tbs = der_seq(
        der_ctx0(_der_tlv(0x02, b"\x02")),
        _der_tlv(0x02, int_le_bytes(serial)),
        alg_rsa_only(OID_SHA256_RSA),
        name,
        der_seq(der_utctime("200101000000Z"), der_utctime("491231235959Z")),
        name,
        spki,
    )
    return der_seq(tbs, alg_rsa_only(OID_SHA256_RSA), der_bitstring(rsa_sign(key, tbs)))


# ---------- PKCS#7 (Kotlin-identical, fixed IssuerAndSerialNumber) ----------


def pkcs7_signed_data(content: bytes, cert: bytes, key) -> bytes:
    utc = datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ")
    digest = hashlib.sha256(content).digest()
    # Attribute ::= SEQ { type OID, values SET OF ANY } — concatenated in
    # ascending DER order; the [0] IMPLICIT SET wraps them directly.
    attr_contentype = der_seq(der_oid(OID_PKCS9_CONTENT_TYPE), der_set(der_oid(OID_DATA)))
    attr_signing_time = der_seq(der_oid(OID_SIGNING_TIME), der_set(der_utctime(utc)))
    attr_digest = der_seq(der_oid(OID_MESSAGE_DIGEST), der_set(der_octet(digest)))
    attr_body = attr_contentype + attr_signing_time + attr_digest
    # RFC 5652 §11.1: the signature covers the SET-OF encoding (tag 0x31); the
    # SignerInfo stores the same content under the IMPLICIT [0] tag (0xA0).
    attr_tlv = der_ctx0(attr_body)
    attr_sig = rsa_sign(key, _der_tlv(0x31, attr_body))

    tbs_tlv = cert_content(cert)
    _, tbs_off = read_tlv(tbs_tlv, 0)
    _, tbs_len = None, None
    length, off = read_tlv(tbs_tlv, 0)
    tbs_content = tbs_tlv[off : off + length]
    tlvs = top_level_tlvs(tbs_content)
    print(f"tbs TLV len={len(tbs_tlv)}, tbs content={length}B, top-level TLVs={len(tlvs)} "
          f"tags={[t[0] for t in tlvs]}")
    serial_tlv = tlvs[1]
    issuer_name_tlv = tlvs[3]

    signer_info = der_seq(
        _der_tlv(0x02, b"\x01"),
        der_seq(issuer_name_tlv, serial_tlv),
        sha256_digest_alg(),
        attr_tlv,
        null_alg(),
        der_octet(attr_sig),
    )
    signed_data = der_seq(
        _der_tlv(0x02, b"\x01"),
        der_set(sha256_digest_alg()),
        der_seq(der_oid(OID_DATA)),
        der_ctx0(cert),
        der_set(signer_info),
    )
    return der_seq(der_oid(OID_SIGNED_DATA), der_ctx0(signed_data))


# ---------- v1 JAR sig ----------


def write_v1(entries, cert, key):
    mf = io.StringIO()
    mf.write("Manifest-Version: 1.0\r\n")
    mf.write("Created-By: 1.0 (NINE)\r\n\r\n")
    for name, data in entries:
        mf.write(f"Name: {name}\r\n")
        mf.write(f"SHA-256-Digest: {base64.b64encode(hashlib.sha256(data).digest()).decode()}\r\n\r\n")
    manifest = mf.getvalue().encode("ascii")

    sf = io.StringIO()
    sf.write("Signature-Version: 1.0\r\n")
    sf.write("Created-By: 1.0 (NINE)\r\n")
    sf.write(f"SHA-256-Digest-Manifest: {base64.b64encode(hashlib.sha256(manifest).digest()).decode()}\r\n")
    sf.write("\r\n")
    # apksig requires per-entry sections in the SF to consider entries covered
    for name, data in entries:
        sf.write(f"Name: {name}\r\n")
        sf.write(f"SHA-256-Digest: {base64.b64encode(hashlib.sha256(data).digest()).decode()}\r\n\r\n")
    sf_bytes = sf.getvalue().encode("ascii")

    p7 = pkcs7_signed_data(sf_bytes, cert, key)
    return {
        "META-INF/MANIFEST.MF": manifest,
        "META-INF/CERT.SF": sf_bytes,
        "META-INF/CERT.RSA": p7,
    }


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "app/src/main/assets/shell-template.apk")
    with zipfile.ZipFile(src) as z:
        entries = [(i.filename, z.read(i.filename)) for i in z.infolist() if not i.filename.endswith("/")]
    print(f"template entries: {[n for n, _ in entries]}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = self_signed_cert(key)

    # 1) reproduce the on-device crash: walking the outer-SEQ *TLV* stream
    walked_wrong = top_level_tlvs(cert_content(cert))
    print(f"buggy walk  -> {len(walked_wrong)} TLVs (attrs[3] -> IndexError) tags={[t[0] for t in walked_wrong]}")
    walked_fixed = cert_tbs_tlvs(cert)
    print(f"fixed walk  -> {len(walked_fixed)} TLVs tags={[t[0] for t in walked_fixed]}")
    assert len(walked_fixed) >= 4, "fixed walk must expose >=4 tbs fields"
    assert walked_fixed[1][0] == 0x02 and walked_fixed[3][0] == 0x30, "index1 serial INT, index3 issuer Name"

    sig = write_v1(entries, cert, key)
    out = os.path.join(OUT, "signed-replica.apk")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", sig["META-INF/MANIFEST.MF"])
        for name, data in entries:
            z.writestr(name, data)
        z.writestr("META-INF/CERT.SF", sig["META-INF/CERT.SF"])
        z.writestr("META-INF/CERT.RSA", sig["META-INF/CERT.RSA"])
    print("wrote", out)


if __name__ == "__main__":
    main()
