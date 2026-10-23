package com.nine.dbt

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Runtime patcher for binary Android XML (AXML). Used to rewrite a light-shell
 * template manifest's `package` attribute value and inline `android:label`
 * strings without shipping an aapt toolchain.
 *
 * AXML structure we rely on (stable since API 1):
 *   RES_XML_TYPE (0x0003) wrapper
 *     ├─ RES_STRING_POOL_TYPE (0x0001) — strings referenced by index
 *     ├─ RES_XML_RESOURCE_MAP (0x0180)
 *     └─ RES_XML_START/END_ELEMENT nodes (reference pool strings by index)
 *
 * Element values are pool indexes, so rebuilding the string pool with the same
 * entry count keeps the tree valid. Only the pool blob is rebuilt (always in
 * UTF-8); everything after it shifts, and the wrapper `size` is recomputed.
 */
object AxmlPatcher {

    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val POOL_HEADER_SIZE = 28 // 8 chunk hdr + count/styles/flags/stringsStart/stylesStart
    private const val UTF8_FLAG = 1 shl 8

    data class Patch(val old: String, val new: String, val alsoPrefixes: Boolean = false)

    /**
     * Replaces every string pool entry equal to [old] with [new]. With
     * [Patch.alsoPrefixes], entries *derived* from [old] are renamed too —
     * manifest package renames must also rewrite the class references and
     * permission/authority names that aapt2 derived from the old package
     * (com.nine.shell.ShellMainActivity → com.nine.shell.<prog>.ShellMainActivity).
     */
    fun patchStrings(axml: ByteArray, vararg patches: Patch): ByteArray {
        val buf = ByteBuffer.wrap(axml).order(ByteOrder.LITTLE_ENDIAN)

        val wrapperType = buf.getShort(0).toInt() and 0xFFFF
        require(wrapperType == 0x0003) { "not an AXML document (type=$wrapperType)" }
        val wrapperHeaderSize = buf.getShort(2).toInt() and 0xFFFF

        var off = wrapperHeaderSize
        var poolOff = -1
        var poolSize = 0
        while (off + 8 <= axml.size) {
            val type = buf.getShort(off).toInt() and 0xFFFF
            val hsize = buf.getShort(off + 2).toInt() and 0xFFFF
            val size = buf.getInt(off + 4)
            if (type == RES_STRING_POOL_TYPE) { poolOff = off; poolSize = size; break }
            if (size <= 0) break
            off += size
        }
        require(poolOff >= 0) { "AXML string pool not found" }

        val stringCount = buf.getInt(poolOff + 8)
        val flags = buf.getInt(poolOff + 16)
        val stringsStart = buf.getInt(poolOff + 20)
        val isUtf8 = (flags and UTF8_FLAG) != 0

        val strings = ArrayList<String>(stringCount)
        val absoluteDataStart = poolOff + stringsStart
        for (i in 0 until stringCount) {
            val entryOff = buf.getInt(poolOff + 28 + i * 4)
            strings.add(if (isUtf8) readUtf8(buf, absoluteDataStart + entryOff)
            else readUtf16(buf, absoluteDataStart + entryOff))
        }

        var changed = false
        val patched = strings.map { s ->
            var v = s
            for (p in patches) {
                if (v == p.old) { v = p.new; changed = true }
                else if (p.alsoPrefixes && v.startsWith(p.old + ".")) {
                    v = p.new + v.substring(p.old.length)
                    changed = true
                }
            }
            v
        }
        if (!changed) return axml

        val newPool = buildStringPoolChunk(patched)

        val head = axml.copyOfRange(0, poolOff)
        val tail = axml.copyOfRange(poolOff + poolSize, axml.size)
        val out = ByteArray(head.size + newPool.size + tail.size)
        head.copyInto(out)
        newPool.copyInto(out, head.size)
        tail.copyInto(out, head.size + newPool.size)
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putInt(4, out.size)
        return out
    }

    /**
     * Rebuilds the pool chunk in UTF-8, same entry count → every index
     * referenced from the XML tree keeps pointing at the right string.
     */
    private fun buildStringPoolChunk(entries: List<String>): ByteArray {
        val enc = ArrayList<ByteArray>(entries.size)
        for (e in entries) enc.add(encodeUtf8Entry(e))

        val offsetsSize = entries.size * 4
        var stringsStart = POOL_HEADER_SIZE + offsetsSize
        while (stringsStart % 4 != 0) stringsStart++ // string data 4-byte aligned

        var chunkSize = stringsStart
        for (b in enc) chunkSize += b.size
        while (chunkSize % 4 != 0) chunkSize++ // pad the chunk itself

        val out = ByteArray(chunkSize)
        val bb = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        bb.putShort(0, RES_STRING_POOL_TYPE.toShort())
        bb.putShort(2, POOL_HEADER_SIZE.toShort())
        bb.putInt(4, chunkSize)
        bb.putInt(8, entries.size)
        bb.putInt(12, 0)              // styleCount
        bb.putInt(16, UTF8_FLAG)      // flags: UTF-8
        bb.putInt(20, stringsStart)
        bb.putInt(24, 0)              // stylesStart

        var dataAt = stringsStart
        for (i in entries.indices) {
            bb.putInt(POOL_HEADER_SIZE + i * 4, dataAt - stringsStart)
            enc[i].copyInto(out, dataAt)
            dataAt += enc[i].size
        }
        return out
    }

    /** utf16CharCount varint + utf8ByteCount varint + bytes + NUL + zero pad. */
    private fun encodeUtf8Entry(s: String): ByteArray {
        val utf8 = s.toByteArray(Charsets.UTF_8)
        val lenBytes = ArrayList<Byte>(4)
        writeVarLen(lenBytes, s.length)
        writeVarLen(lenBytes, utf8.size)
        var total = lenBytes.size + utf8.size + 1
        while (total % 4 != 0) total++
        val out = ByteArray(total)
        var at = 0
        for (b in lenBytes) out[at++] = b
        utf8.copyInto(out, at)
        at += utf8.size
        out[at] = 0
        return out
    }

    private fun writeVarLen(out: ArrayList<Byte>, len: Int) {
        if (len < 0x80) {
            out.add(len.toByte())
        } else {
            out.add(((len ushr 8) or 0x80).toByte())
            out.add((len and 0xFF).toByte())
        }
    }

    // ---- decoding (used for equality checks before patching) ----

    private fun readUtf8(buf: ByteBuffer, at: Int): String {
        // utf16 char count then utf8 byte count; each 1 or (0x80-prefixed) 2 bytes
        val (firstPos, _) = readVarLen(buf, at)
        val pos0 = at + firstPos
        val (_, u8len) = readVarLen(buf, pos0)
        val pos = pos0 + readVarLen(buf, pos0).first
        val bytes = ByteArray(u8len)
        buf.get(bytes, pos, u8len)
        return String(bytes, Charsets.UTF_8)
    }

    private fun readUtf16(buf: ByteBuffer, at: Int): String {
        // utf16 length: 1 byte (<0x8000) or 2 bytes ((len>>16)<<1 | 0x8000) then 2
        var len = buf.getShort(at).toInt() and 0xFFFF
        var pos = at + 2
        if (len and 0x8000 != 0) {
            len = ((len and 0x7FFF) shl 16) or (buf.getShort(pos).toInt() and 0xFFFF)
            pos += 2
        }
        val bytes = ByteArray(len * 2)
        buf.get(bytes, pos, len * 2)
        val chars = CharArray(len)
        for (i in 0 until len) chars[i] = ((bytes[i * 2].toInt() and 0xFF) or
                ((bytes[i * 2 + 1].toInt() and 0xFF) shl 8)).toChar()
        return String(chars)
    }

    private fun readVarLen(buf: ByteBuffer, at: Int): Pair<Int, Int> {
        val b0 = buf.get(at).toInt() and 0xFF
        if (b0 and 0x80 == 0) return Pair(1, b0)
        return Pair(2, ((b0 and 0x7F) shl 8) or (buf.get(at + 1).toInt() and 0xFF))
    }
}
