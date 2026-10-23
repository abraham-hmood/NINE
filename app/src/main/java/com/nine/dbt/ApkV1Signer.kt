package com.nine.dbt

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Calendar
import java.util.zip.ZipFile

/**
 * Minimal v1 (JAR) APK signer for the runtime-built light shells.
 *
 * Light-shell templates declare targetSdk < 30, where v1-only signatures are
 * still accepted by PackageInstaller; that keeps the runtime signer small
 * (no APK Signing Block, no external crypto library). Verification on the
 * device uses the platform's CertificateFactory to parse the DER we emit, so
 * the PKCS#7 and X.509 constructions below must stay faithful.
 *
 * Implemented in raw ASN.1 DER:
 *   - SHA-256/RSA self-signed X.509 v3 certificate (CN=NINE Shell)
 *   - PKCS#7 SignedData with authenticatedAttributes
 *     (contentType=data, signingTime, messageDigest)
 */
object ApkV1Signer {

    private val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
    private val OID_SHA256_RSA = "1.2.840.113549.1.1.11"
    private val OID_DASHED_DATA = "1.2.840.113549.1.7.1"   // data content type
    private val OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
    private val OID_SHA256 = "2.16.840.1.101.3.4.2.1"
    private val OID_COMMON_NAME = "2.5.4.3"
    private val OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
    private val OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
    /** PKCS#9 `content-type` signed-attribute identifier. */
    private val OID_PKCS9_CONTENT_TYPE = "1.2.840.113549.1.9.3"

    // ---------- DER primitives ----------

    private object Der {
        fun tlv(tag: Int, content: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(tag)
            val len = content.size
            if (len < 0x80) out.write(len)
            else if (len <= 0xFF) { out.write(0x81); out.write(len) }
            else { out.write(0x82); out.write(len shr 8); out.write(len and 0xFF) }
            out.write(content)
            return out.toByteArray()
        }

        fun seq(vararg parts: ByteArray) = tlv(0x30, concat(parts))
        fun set(vararg parts: ByteArray) = tlv(0x31, concat(parts))
        fun context0(content: ByteArray) = tlv(0xA0, content)

        fun oid(dotted: String): ByteArray {
            val p = dotted.split(".")
            val body = ByteArrayOutputStream()
            body.write(p[0].toInt() * 40 + p[1].toInt())
            for (i in 2 until p.size) {
                var v = p[i].toInt()
                val stack = ArrayDeque<Int>()
                if (v == 0) stack.addLast(0)
                while (v > 0) { stack.addLast(v and 0x7F); v = v ushr 7 }
                while (stack.isNotEmpty()) {
                    val b = stack.removeLast()
                    body.write(if (stack.isNotEmpty()) b or 0x80 else b)
                }
            }
            return tlv(0x06, body.toByteArray())
        }

        fun octet(content: ByteArray) = tlv(0x04, content)
        fun bitString(content: ByteArray): ByteArray {
            val body = ByteArray(content.size + 1)
            body[0] = 0
            content.copyInto(body, 1)
            return tlv(0x03, body)
        }

        fun int(v: Long) = tlv(0x02, BigInteger.valueOf(v).toByteArray())
        fun int(v: BigInteger) = tlv(0x02, v.toByteArray())
        fun utf8(s: String) = tlv(0x0C, s.toByteArray(Charsets.UTF_8))
        fun utctime(s: String) = tlv(0x17, s.toByteArray(Charsets.US_ASCII))
        fun algRsaOnly(oid: String) = seq(oid(oid), tlv(0x05, ByteArray(0)))
        fun sha256AlgId() = seq(oid(OID_SHA256_RSA))
        /** Plain SHA-256 digest AlgorithmIdentifier (no RSA wrapper). */
        fun sha256DigestAlg() = seq(oid(OID_SHA256))
        fun nullAlg() = algRsaOnly(OID_RSA_ENCRYPTION)

        /** Raw byte concatenation, used to build the authenticated-attribute stream. */
        fun concat(parts: Array<out ByteArray>): ByteArray {
            val out = ByteArrayOutputStream()
            parts.forEach { out.write(it) }
            return out.toByteArray()
        }
    }

    // ---------- self-signed certificate (DER bytes) ----------

    fun generateKeyPair(): KeyPair =
        java.security.KeyPairGenerator.getInstance("RSA").run {
            initialize(2048, SecureRandom())
            generateKeyPair()
        }

    fun selfSignedCertificateDer(kp: KeyPair, cn: String = "NINE Shell"): ByteArray {
        val name = Der.seq(Der.set(Der.seq(Der.oid(OID_COMMON_NAME), Der.utf8(cn))))
        // UTCTime = YYMMDDhhmmssZ (two-digit year, seconds mandatory)
        fun utc(c: Calendar): String = "%02d".format(c.get(Calendar.YEAR) % 100) +
            "%02d".format(c.get(Calendar.MONTH) + 1) +
            "%02d".format(c.get(Calendar.DAY_OF_MONTH)) +
            "%02d".format(c.get(Calendar.HOUR_OF_DAY)) +
            "%02d".format(c.get(Calendar.MINUTE)) +
            "%02d".format(c.get(Calendar.SECOND)) + "Z"
        val notBefore = Calendar.getInstance().apply {
            clear(); set(2020, Calendar.JANUARY, 1, 0, 0, 0)
        }
        val notAfter = Calendar.getInstance().apply {
            clear(); set(2049, Calendar.DECEMBER, 31, 23, 59, 59)
        }

        val pub = kp.public as RSAPublicKey
        val spki = Der.seq(
            Der.nullAlg(),
            Der.bitString(Der.seq(Der.int(pub.modulus), Der.int(pub.publicExponent)))
        )
        val serial = BigInteger(60, SecureRandom())

        val tbs = Der.seq(
            Der.context0(Der.int(2)), // version v3
            Der.int(serial),
            Der.algRsaOnly(OID_SHA256_RSA),
            name,                     // issuer (self-signed: == subject)
            Der.seq(Der.utctime(utc(notBefore)), Der.utctime(utc(notAfter))),
            name,                     // subject
            spki
        )
        val sigBytes = Signature.getInstance("SHA256withRSA").run {
            initSign(kp.private)
            update(tbs)
            sign()
        }
        return Der.seq(tbs, Der.algRsaOnly(OID_SHA256_RSA), Der.bitString(sigBytes))
    }

    // ---------- PKCS#7 SignedData over [content] ----------

    fun pkcs7SignedData(content: ByteArray, certDer: ByteArray, kp: KeyPair): ByteArray {
        // authenticated attributes: contentType, signingTime, messageDigest
        val cal = Calendar.getInstance()
        // UTCTime = YYMMDDhhmmssZ (two-digit year, seconds mandatory)
        val utc = "%02d".format(cal.get(Calendar.YEAR) % 100) +
            "%02d".format(cal.get(Calendar.MONTH) + 1) +
            "%02d".format(cal.get(Calendar.DAY_OF_MONTH)) +
            "%02d".format(cal.get(Calendar.HOUR_OF_DAY)) +
            "%02d".format(cal.get(Calendar.MINUTE)) +
            "%02d".format(cal.get(Calendar.SECOND)) + "Z"

        val digest = MessageDigest.getInstance("SHA-256").digest(content)
        // Attribute ::= SEQ { type OID, values SET OF ANY }. The three
        // attributes are concatenated (in ascending DER order) and carried in
        // one SET: the [0] IMPLICIT tag wraps their SEQUENCEs directly — the
        // verifier re-tags 0xA0 back to 0x31 before checking the signature.
        val attrContent = Der.seq(Der.oid(OID_PKCS9_CONTENT_TYPE), Der.set(Der.oid(OID_DASHED_DATA))) +
            Der.seq(Der.oid(OID_SIGNING_TIME), Der.set(Der.utctime(utc))) +
            Der.seq(Der.oid(OID_MESSAGE_DIGEST), Der.set(Der.octet(digest)))
        val attrTlv = Der.context0(attrContent)
        val attrSig = Signature.getInstance("SHA256withRSA").run {
            initSign(kp.private)
            update(Der.set(attrContent)) // RFC 5652 §11.1: sign the SET-OF encoding
            sign()
        }

        // IssuerAndSerialNumber from the certificate DER:
        // outer SEQ content = tbsCertificate TLV; peel ITS TLV too, then walk
        // the tbs fields: [0] version | INTEGER serial | AlgId | Name(issuer) |
        // validity | Name(subject) | SPKI
        val tbsTlv = certContent(certDer)
        val (tbsLen, tbsOff) = readTlv(tbsTlv, 0)
        val attrs = topLevelTlvs(tbsTlv.copyOfRange(tbsOff, tbsOff + tbsLen))
        android.util.Log.i(
            "NINE",
            "sign: cert=${certDer.size}B tbsTlv=${tbsTlv.size}B tlvCount=${attrs.size} " +
                "tlvLens=${attrs.joinToString { it.size.toString() }}"
        )
        val serialTlv = attrs[1]
        val issuerNameTlv = attrs[3]

        val signerInfo = Der.seq(
            Der.int(1),
            Der.seq(issuerNameTlv, serialTlv),
            Der.sha256DigestAlg(),
            attrTlv,
            Der.nullAlg(),
            Der.octet(attrSig)
        )

        val signedData = Der.seq(
            Der.int(1),
            Der.set(Der.sha256DigestAlg()),
            Der.seq(Der.oid(OID_DASHED_DATA)),
            Der.context0(certDer), // [0] IMPLICIT certificates
            Der.set(signerInfo)
        )
        return Der.seq(Der.oid(OID_SIGNED_DATA), Der.context0(signedData))
    }

    // ---------- X.509 DER helpers ----------

    /** Reads `Cert.tbsCertificate` bytes: the outer SEQUENCE TLV's content. */
    private fun certContent(cert: ByteArray): ByteArray {
        // readTlv returns (contentLen, contentOffset)
        val (contentLen, contentOff) = readTlv(cert, 0)
        return cert.copyOfRange(contentOff, contentOff + contentLen)
    }

    /** Returns the content (not TLV!) of the tbs SEQUENCE. */
    private fun topLevelTlvs(tbsContent: ByteArray): List<ByteArray> {
        var at = 0
        val out = ArrayList<ByteArray>()
        while (at + 2 <= tbsContent.size) {
            val (contentLen, contentOff) = readTlv(tbsContent, at)
            out.add(tbsContent.copyOfRange(at, contentOff + contentLen))
            at = contentOff + contentLen
        }
        return out.toList()
    }

    private fun readTlv(b: ByteArray, at: Int): Pair<Int, Int> {
        // (contentLen, contentOffset)
        val lenByte = b[at + 1].toInt() and 0xFF
        var len = lenByte
        var contentOff = at + 2
        if (lenByte == 0x81) { len = b[at + 2].toInt() and 0xFF; contentOff = at + 3 }
        else if (lenByte == 0x82) {
            len = ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)
            contentOff = at + 4
        }
        return Pair(len, contentOff)
    }

    // ---------- JAR manifest + SF + PKCS#7 block ----------

    /**
     * build MANIFEST.MF digests over every entry's uncompressed data, then
     * CERT.SF (whole-manifest digest, single-file shortcut is not used) and
     * CERT.RSA (PKCS#7 over the SF bytes).
     */
    fun writeV1Signature(
        entries: List<Pair<String, ByteArray>>, // (name, uncompressed data)
        certDer: ByteArray,
        kp: KeyPair
    ): Map<String, ByteArray> {
        val md = MessageDigest.getInstance("SHA-256")
        val mf = StringBuilder()
        mf.append("Manifest-Version: 1.0\r\n")
        mf.append("Created-By: 1.0 (NINE)\r\n")
        mf.append("\r\n")
        entries.forEach { (name, data) ->
            mf.append("Name: $name\r\n")
            mf.append("SHA-256-Digest: ${b64(md.digest(data))}\r\n")
            mf.append("\r\n")
        }
        val manifest = mf.toString().toByteArray(Charsets.US_ASCII)

        val sf = StringBuilder()
        sf.append("Signature-Version: 1.0\r\n")
        sf.append("Created-By: 1.0 (NINE)\r\n")
        sf.append("SHA-256-Digest-Manifest: ${b64(md.digest(manifest))}\r\n")
        sf.append("\r\n")
        // Per-entry sections in the .SF are REQUIRED by the platform's v1
        // verifier (apksig ignores entries not named in a signer's .SF even
        // when the whole-manifest digest verifies).
        entries.forEach { (name, data) ->
            sf.append("Name: $name\r\n")
            sf.append("SHA-256-Digest: ${b64(md.digest(data))}\r\n")
            sf.append("\r\n")
        }
        val sfBytes = sf.toString().toByteArray(Charsets.US_ASCII)

        val p7 = pkcs7SignedData(sfBytes, certDer, kp)
        return mapOf(
            "META-INF/MANIFEST.MF" to manifest,
            "META-INF/CERT.SF" to sfBytes,
            "META-INF/CERT.RSA" to p7
        )
    }

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)
}
