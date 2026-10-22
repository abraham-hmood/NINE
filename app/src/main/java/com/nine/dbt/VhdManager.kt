package com.nine.dbt

import android.content.Context
import android.system.Os
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * Virtual hard disks for NINE.
 *
 * VHDs live ONLY in NINE's private app storage (filesDir/vhds) — they cannot be
 * created externally. Each VHD has a metadata record (index.json) and a raw disk
 * image. The image is written as a partitioned MBR disk with a real filesystem
 * where NINE can format it today (FAT12/16/32 fully; exFAT best-effort; NTFS and
 * ext2/3/4 get their boot/superblock structures with the rest deferred to the
 * FS driver) and a boot-sector/superblock/magic marker for everything else.
 *
 * Compression lifecycle: a VHD created with compression enabled is stored as
 * <id>.vhd.gz. When NINE opens/returns to foreground it decompresses to a
 * working <id>.vhd; when NINE leaves the foreground it re-compresses to .gz.
 * Decompressed VHDs waste storage — snackbar feedback is surfaced by the app.
 */
object VhdManager {

    data class Vhd(
        val id: String,
        val name: String,
        val fs: String,
        val sizeBytes: Long,
        val fixed: Boolean,
        val compressed: Boolean,
        val label: String,
        val sectorSize: Int,
        val clusterBytes: Int,   // 0 = auto
        val bootable: Boolean,
        val note: String,
        val createdAt: Long
    )

    data class CreateSpec(
        val name: String,
        val fs: String,
        val sizeBytes: Long,
        val fixed: Boolean,
        val compressed: Boolean,
        val label: String = "",
        val sectorSize: Int = 512,
        val clusterBytes: Int = 0,
        val bootable: Boolean = false,
        val note: String = ""
    )

    val FILESYSTEMS = listOf(
        "FAT12", "FAT16", "FAT32", "exFAT", "NTFS",
        "ext2", "ext3", "ext4", "XFS", "Btrfs", "F2FS",
        "HFS", "HFS+", "ISO9660", "UDF", "SquashFS", "ROMFS",
        "Minix", "JFS", "ReiserFS", "NILFS2", "UFS", "CramFS", "HPFS"
    )

    private const val PREFS = "nine_vhds"
    private const val INDEX = "index.json"

    /** Human-readable size, e.g. "1024.0 MB". */
    fun humanSize(bytes: Long): String = when {
        bytes >= 1024L * 1024 * 1024 -> "%.1f GB".format(bytes / (1024.0 * 1024 * 1024))
        bytes >= 1024L * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024))
        bytes >= 1024L -> "%.1f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }

    fun dir(ctx: Context): File = File(ctx.filesDir, "vhds").apply { mkdirs() }

    // ---------- metadata ----------

    fun list(ctx: Context): List<Vhd> {
        val f = File(dir(ctx), INDEX)
        if (!f.isFile) return emptyList()
        return runCatching {
            val arr = JSONArray(f.readText())
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Vhd(
                    id = o.getString("id"),
                    name = o.getString("name"),
                    fs = o.getString("fs"),
                    sizeBytes = o.getLong("sizeBytes"),
                    fixed = o.optBoolean("fixed", true),
                    compressed = o.optBoolean("compressed", false),
                    label = o.optString("label", ""),
                    sectorSize = o.optInt("sectorSize", 512),
                    clusterBytes = o.optInt("clusterBytes", 0),
                    bootable = o.optBoolean("bootable", false),
                    note = o.optString("note", ""),
                    createdAt = o.optLong("createdAt", 0L)
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun saveList(ctx: Context, list: List<Vhd>) {
        val arr = JSONArray()
        list.forEach { v ->
            arr.put(
                JSONObject()
                    .put("id", v.id)
                    .put("name", v.name)
                    .put("fs", v.fs)
                    .put("sizeBytes", v.sizeBytes)
                    .put("fixed", v.fixed)
                    .put("compressed", v.compressed)
                    .put("label", v.label)
                    .put("sectorSize", v.sectorSize)
                    .put("clusterBytes", v.clusterBytes)
                    .put("bootable", v.bootable)
                    .put("note", v.note)
                    .put("createdAt", v.createdAt)
            )
        }
        File(dir(ctx), INDEX).writeText(arr.toString(2))
    }

    private fun imageFile(ctx: Context, v: Vhd): File =
        File(dir(ctx), "${v.id}.${if (v.compressed) "vhd.gz" else "vhd"}")

    private fun workFile(ctx: Context, v: Vhd): File = File(dir(ctx), "${v.id}.vhd")

    // ---------- create ----------

    /** Blocking — call from Dispatchers.IO. Creates the image on disk. */
    @Throws(Exception::class)
    fun create(ctx: Context, spec: CreateSpec): Vhd {
        require(spec.name.isNotBlank()) { "name is required" }
        require(spec.sizeBytes >= 1024 * 1024) { "size must be at least 1 MB" }
        require(spec.fs in FILESYSTEMS) { "unsupported filesystem ${spec.fs}" }

        val id = System.currentTimeMillis().toString(36) + "-" + (0..0xFFFF).random().toString(16)
        val raw = File(dir(ctx), "$id.vhd")

        GuestLog.info("vhd: creating '${spec.name}' fs=${spec.fs} size=${spec.sizeBytes} " +
            "fixed=${spec.fixed} compressed=${spec.compressed} sector=${spec.sectorSize}")

        RandomAccessFile(raw, "rw").use { raf ->
            // Allocation: fixed = physically allocated now; dynamic = sparse, grows on write
            if (spec.fixed) {
                try {
                    Os.posix_fallocate(raf.fd, 0, spec.sizeBytes)
                    GuestLog.info("vhd: allocated ${spec.sizeBytes} bytes (fixed)")
                } catch (e: Exception) {
                    raf.setLength(spec.sizeBytes)
                    GuestLog.add("vhd: fallocate unavailable (${e.message}); fell back to setLength")
                }
            } else {
                raf.setLength(spec.sizeBytes)
                GuestLog.info("vhd: sparse image of ${spec.sizeBytes} bytes (dynamic/growable)")
            }

            val sectorSize = spec.sectorSize
            val totalSectors = spec.sizeBytes / sectorSize

            // Partitioned MBR when there is room; superfloppy otherwise
            val usePartition = spec.sizeBytes >= 8L * 1024 * 1024
            val partStart = if (usePartition) 2048L else 0L
            val partSectors = totalSectors - partStart
            if (usePartition) {
                writeMbr(raf, partStart, partSectors, spec.fs, spec.bootable, sectorSize)
                GuestLog.info("vhd: MBR written — partition @LBA $partStart type=${fsTypeCode(spec.fs)}" +
                    if (spec.bootable) " bootable" else "")
            } else {
                GuestLog.info("vhd: image < 8 MB — superfloppy layout (no partition table)")
            }

            val fsOffset = partStart * sectorSize
            val fsSectors = partSectors
            when (spec.fs) {
                "FAT12" -> formatFat(raf, fsOffset, fsSectors, sectorSize, spec, 12)
                "FAT16" -> formatFat(raf, fsOffset, fsSectors, sectorSize, spec, 16)
                "FAT32" -> formatFat(raf, fsOffset, fsSectors, sectorSize, spec, 32)
                "exFAT" -> formatExFat(raf, fsOffset, fsSectors, sectorSize, spec)
                "NTFS" -> writeNtfsBoot(raf, fsOffset, fsSectors, sectorSize, spec)
                "ext2", "ext3", "ext4" -> writeExtSuperblock(raf, fsOffset, fsSectors, sectorSize, spec)
                else -> writeFsMarker(raf, fsOffset, fsSectors, sectorSize, spec)
            }

            // Ensure last byte exists so the image length is committed
            raf.seek(spec.sizeBytes - 1)
            raf.write(0)
        }

        val v = Vhd(
            id = id,
            name = spec.name,
            fs = spec.fs,
            sizeBytes = spec.sizeBytes,
            fixed = spec.fixed,
            compressed = spec.compressed,
            label = spec.label,
            sectorSize = spec.sectorSize,
            clusterBytes = spec.clusterBytes,
            bootable = spec.bootable,
            note = spec.note,
            createdAt = System.currentTimeMillis()
        )

        if (spec.compressed) {
            val gz = File(dir(ctx), "$id.vhd.gz")
            gzip(raw, gz)
            raw.delete()
            GuestLog.info("vhd: '${spec.name}' compressed -> ${gz.name} (${gz.length()} bytes)")
        }

        saveList(ctx, list(ctx) + v)
        GuestLog.info("vhd: '${spec.name}' created OK (${if (v.compressed) "compressed" else "stored decompressed"})")
        return v
    }

    // ---------- lifecycle compression ----------

    /** Decompress all compressed VHDs for use. Returns user-facing messages for snackbars. */
    fun decompressAll(ctx: Context): List<String> {
        val out = mutableListOf<String>()
        list(ctx).forEach { v ->
            if (!v.compressed) {
                out += "VHD '${v.name}' is stored decompressed — leaving it decompressed wastes storage"
                return@forEach
            }
            val gz = File(dir(ctx), "${v.id}.vhd.gz")
            val work = workFile(ctx, v)
            if (work.isFile) {
                out += "VHD '${v.name}' is already decompressed — leaving it decompressed wastes storage"
                return@forEach
            }
            if (!gz.isFile) return@forEach
            try {
                gunzip(gz, work)
                GuestLog.info("vhd: '${v.name}' decompressed for use (${work.length()} bytes)")
                out += "VHD '${v.name}' decompressed, ready for use"
            } catch (e: Exception) {
                GuestLog.add("vhd: decompress '${v.name}' failed: ${e.message}")
            }
        }
        return out
    }

    /** Re-compress working copies when NINE leaves the foreground. */
    fun compressAll(ctx: Context) {
        var n = 0
        list(ctx).forEach { v ->
            if (!v.compressed) return@forEach
            val gz = File(dir(ctx), "${v.id}.vhd.gz")
            val work = workFile(ctx, v)
            if (!work.isFile) return@forEach
            try {
                gzip(work, gz)
                work.delete()
                n++
                GuestLog.info("vhd: '${v.name}' re-compressed for storage (${gz.length()} bytes)")
            } catch (e: Exception) {
                GuestLog.add("vhd: compress '${v.name}' failed: ${e.message}")
            }
        }
        if (n > 0) GuestLog.info("vhd: recompressed $n disk(s) on app leave")
    }

    // ---------- delete / export ----------

    fun delete(ctx: Context, ids: Collection<String>) {
        val keep = list(ctx).filterNot { it.id in ids }
        ids.forEach { id ->
            listOf("$id.vhd", "$id.vhd.gz", "$id.json").forEach { f ->
                File(dir(ctx), f).delete()
            }
            GuestLog.info("vhd: deleted $id")
        }
        saveList(ctx, keep)
    }

    /**
     * Export selected VHDs as a gzipped tarball (.tar.gz) to a SAF uri.
     * Contains vhds/<file> images plus a JSON sidecar per disk.
     */
    fun exportTarGz(ctx: Context, ids: Collection<String>, out: OutputStream) {
        val vhdDir = dir(ctx)
        GZIPOutputStream(BufferedOutputStream(out)).use { gz ->
            TarOutputStream(gz).use { tar ->
                list(ctx).filter { it.id in ids }.forEach { v ->
                    val image = imageFile(ctx, v)
                    val work = workFile(ctx, v)
                    val stored = when {
                        image.isFile -> image
                        work.isFile -> work
                        else -> null
                    }
                    val meta = JSONObject()
                        .put("name", v.name).put("fs", v.fs).put("sizeBytes", v.sizeBytes)
                        .put("fixed", v.fixed).put("compressed", v.compressed)
                        .put("label", v.label).put("sectorSize", v.sectorSize)
                        .put("clusterBytes", v.clusterBytes).put("bootable", v.bootable)
                        .put("note", v.note).put("createdAt", v.createdAt)
                    tar.addBytes("${v.name}.json", meta.toString(2).toByteArray())
                    if (stored != null) tar.addFile("vhds/${stored.name}", stored)
                    GuestLog.info("vhd: export '${v.name}' (${stored?.length() ?: 0} bytes)")
                }
                tar.addBytes("vhds/index.json", JSONArray(list(ctx).map {
                    JSONObject().put("name", it.name).put("fs", it.fs).put("sizeBytes", it.sizeBytes)
                }).toString(2).toByteArray())
            }
        }
        GuestLog.info("vhd: export archive complete (${ids.size} disk(s))")
    }

    // ---------- gzip helpers ----------

    private fun gzip(src: File, dst: File) {
        FileInputStream(src).use { input ->
            GZIPOutputStream(FileOutputStream(dst)).use { gz -> input.copyTo(gz) }
        }
    }

    private fun gunzip(src: File, dst: File) {
        GZIPInputStream(BufferedInputStream(FileInputStream(src))).use { gz ->
            FileOutputStream(dst).use { out -> gz.copyTo(out) }
        }
    }

    // ---------- MBR ----------

    private fun fsTypeCode(fs: String): Int = when (fs) {
        "FAT12" -> 0x01
        "FAT16" -> 0x06
        "FAT32" -> 0x0C
        "exFAT", "NTFS" -> 0x07
        "HFS", "HFS+" -> 0xAF
        "ISO9660" -> 0xCD
        "HPFS" -> 0x07
        else -> 0x83 // Linux/other
    }

    private fun writeMbr(raf: RandomAccessFile, start: Long, sectors: Long, fs: String,
                         bootable: Boolean, sectorSize: Int) {
        val mbr = ByteArray(512)
        // Partition entry 0 at 0x1BE
        mbr[0x1BE] = if (bootable) 0x80.toByte() else 0x00
        mbr[0x1BF] = 0xFE.toByte(); mbr[0x1C0] = 0xFF.toByte(); mbr[0x1C1] = 0xFF.toByte()
        mbr[0x1C2] = fsTypeCode(fs).toByte()
        mbr[0x1C3] = 0xFE.toByte(); mbr[0x1C4] = 0xFF.toByte(); mbr[0x1C5] = 0xFE.toByte()
        writeLe32(mbr, 0x1C6, start)
        writeLe32(mbr, 0x1CA, sectors)
        mbr[0x1FE] = 0x55; mbr[0x1FF] = 0xAA.toByte()
        raf.seek(0)
        raf.write(mbr)
    }

    // ---------- FAT12/16/32 formatter ----------

    private fun formatFat(raf: RandomAccessFile, offset: Long, totalSectorsIn: Long,
                          sectorSize: Int, spec: CreateSpec, bits: Int) {
        var totalSectors = totalSectorsIn
        val reserved = if (bits == 32) 32 else 1
        val rootEntries = if (bits == 32) 0 else 512
        val rootDirSectors = ((rootEntries * 32) + (sectorSize - 1)) / sectorSize

        // Cluster size
        var spc = when (spec.clusterBytes) {
            0 -> when {
                spec.sizeBytes < 32L * 1024 * 1024 -> 2
                spec.sizeBytes < 128L * 1024 * 1024 -> 4
                spec.sizeBytes < 512L * 1024 * 1024 -> 8
                spec.sizeBytes < 2L * 1024 * 1024 * 1024 -> 16
                else -> 32
            }
            else -> spec.clusterBytes / sectorSize
        }
        if (spc < 1) spc = 1
        if (spc > 128) spc = 128
        while (spc in 1..64 && totalSectors / (spc * 2) >= 1 && totalSectors / spc > 0xFFF5) spc *= 2
        if (totalSectors / spc > 0xFFF5)
            GuestLog.add("vhd: warning — cluster count above FAT limit at ${spc * sectorSize}B clusters")

        // FAT size (sectors) — iterate to settle
        var fatSectors: Long = 1
        repeat(4) {
            val dataSectors = totalSectors - reserved - rootDirSectors - (2L * fatSectors)
            val clusters = dataSectors / spc
            if (clusters < 1) throw IllegalStateException(
                "image too small for FAT$bits with $sectorSize-byte sectors")
            fatSectors = when (bits) {
                12 -> (((clusters + 2) * 3 + 1) / 2 + sectorSize - 1) / sectorSize
                16 -> (((clusters + 2) * 2 + sectorSize - 1) / sectorSize)
                else -> (((clusters + 4) * 4 + sectorSize - 1) / sectorSize)
            }
        }
        val firstData = reserved + rootDirSectors + 2L * fatSectors
        val clusterCount = (totalSectors - firstData) / spc
        if (clusterCount < 1) throw IllegalStateException("image too small for FAT$bits")
        val fatType = when {
            bits == 32 -> "FAT32"
            clusterCount < 4085 -> "FAT12"
            clusterCount < 65525 -> "FAT16"
            else -> "FAT16"
        }
        if (fatType != "FAT$bits")
            GuestLog.add("vhd: note — requested FAT$bits but geometry yields $fatType (writing FAT$bits layout)")

        val boot = ByteArray(sectorSize)
        boot[0] = 0xEB.toByte(); boot[1] = 0x58; boot[2] = 0x90.toByte()
        put(boot, 3, "MSDOS5.0")
        put(boot, 11, shortLe(spec.sectorSize))
        boot[13] = spc.toByte()
        put(boot, 14, shortLe(reserved))
        boot[16] = 2                      // num FATs
        put(boot, 17, shortLe(rootEntries))
        if (totalSectors < 0x10000) {
            put(boot, 19, shortLe(totalSectors.toInt()))
        } else {
            put(boot, 32, intLe((totalSectors and 0xFFFFFFFFL).toInt()))
        }
        boot[21] = 0xF8.toByte()
        if (bits == 32) {
            put(boot, 36, intLe(fatSectors.toInt()))  // FAT size 32
            put(boot, 44, intLe(2))                   // root cluster
            put(boot, 48, shortLe(1))                 // FSInfo
            put(boot, 50, shortLe(6))                 // backup boot
        } else {
            put(boot, 22, shortLe(fatSectors.toInt())) // FAT size 16
        }
        boot[38] = 0x29
        put(boot, 39, intLe((spec.name.hashCode() and 0x7FFFFFFF).let { if (it == 0) 0x1234ABCD else it }))
        val label = (spec.label.ifBlank { "NO NAME    " }).take(11).padEnd(11, ' ')
        val labelOff = if (bits == 32) 71 else 43
        put(boot, labelOff, label)
        put(boot, labelOff + 11, if (bits == 32) "FAT32   " else if (bits == 16) "FAT16   " else "FAT12   ")
        boot[510] = 0x55; boot[511] = 0xAA.toByte()

        raf.seek(offset)
        raf.write(boot)                                   // primary boot
        raf.seek(offset + 6L * sectorSize)
        if (bits == 32) raf.write(boot)                   // backup boot @6 (FAT32)
        GuestLog.info("vhd: FAT boot sector written (spc=$spc fatSectors=$fatSectors clusters=$clusterCount)")

        // FATs
        val fat = ByteArray((fatSectors * sectorSize).toInt())
        val media = 0xF8 or (if (bits == 32) 0x0F000000 else 0xFF00)
        when (bits) {
            12 -> {
                fat[0] = 0xF8.toByte(); fat[1] = 0xFF.toByte(); fat[2] = 0xFF.toByte()
            }
            16 -> put(fat, 0, intLe(media or 0xFFFF00))
            else -> {
                put(fat, 0, intLe(0x0FFFFFF8))
                put(fat, 4, intLe(0x0FFFFFFF))
                if (spc > 0) put(fat, 8, intLe(0x0FFFFFFF)) // root cluster EOC
            }
        }
        raf.seek(offset + reserved.toLong() * sectorSize)
        raf.write(fat)
        raf.seek(offset + (reserved + fatSectors).toLong() * sectorSize)
        raf.write(fat)
        GuestLog.info("vhd: FAT${bits} tables written (${fatSectors} sectors each)")

        // Root directory (FAT12/16) with optional volume label entry
        if (bits != 32 && rootDirSectors > 0) {
            val root = ByteArray((rootDirSectors * sectorSize).toInt())
            if (spec.label.isNotBlank()) {
                val lbl = spec.label.take(11).padEnd(11, ' ').toByteArray(Charsets.US_ASCII)
                lbl.copyInto(root, 0)
                root[11] = 0x08
            }
            raf.seek(offset + (reserved + 2L * fatSectors) * sectorSize)
            raf.write(root)
        } else if (bits == 32 && spec.label.isNotBlank()) {
            // FAT32 root dir (cluster 2 = first data cluster)
            val root = ByteArray(spc * sectorSize)
            val lbl = spec.label.take(11).padEnd(11, ' ').toByteArray(Charsets.US_ASCII)
            lbl.copyInto(root, 0)
            root[11] = 0x08
            raf.seek(offset + firstData * sectorSize)
            raf.write(root)
        }
        GuestLog.info("vhd: FAT$bits formatted OK — cluster count $clusterCount")
    }

    // ---------- exFAT formatter (best-effort, spec-compliant layout) ----------

    private fun formatExFat(raf: RandomAccessFile, offset: Long, totalSectorsIn: Long,
                            sectorSize: Int, spec: CreateSpec) {
        if (sectorSize != 512 && sectorSize != 4096)
            throw IllegalStateException("exFAT requires 512 or 4096 byte sectors")
        val spcBytes = when {
            spec.clusterBytes > 0 -> spec.clusterBytes
            spec.sizeBytes < 256L * 1024 * 1024 -> 4096
            spec.sizeBytes < 32L * 1024 * 1024 * 1024 -> 32768
            else -> 128 * 1024
        }
        val spcShift = Integer.numberOfTrailingZeros(spcBytes / sectorSize)
        val spc = 1 shl spcShift
        val fatOffset = 24L

        // Settle clusterCount/fatLength/heapOffset iteratively
        var fatLength = 1L
        var clusterCount = 0L
        var heapOffset = 0L
        repeat(6) {
            val heap = fatOffset + fatLength
            clusterCount = (totalSectorsIn - heap) / spc
            fatLength = ((clusterCount + 2) * 4 + sectorSize - 1) / sectorSize
            heapOffset = fatOffset + fatLength
            clusterCount = (totalSectorsIn - heapOffset) / spc
            fatLength = ((clusterCount + 2) * 4 + sectorSize - 1) / sectorSize
            heapOffset = fatOffset + fatLength
        }
        if (clusterCount < 1) throw IllegalStateException("image too small for exFAT")
        val bitmapClusters = ((clusterCount + 7) / 8 + spcBytes - 1) / spcBytes
        val firstBitmap = 2L
        val firstRoot = firstBitmap + bitmapClusters

        val boot = ByteArray(sectorSize)
        boot[0] = 0xEB.toByte(); boot[1] = 0x76; boot[2] = 0x90.toByte()
        put(boot, 3, "EXFAT   ")
        // 0x40 fields
        put(boot, 0x40, longLe(0))                    // partitionOffset (0 = whole disk)
        put(boot, 0x48, longLe(totalSectorsIn))       // volumeLength
        put(boot, 0x50, longLe(fatOffset))            // fatOffset
        put(boot, 0x58, longLe(fatLength))            // fatLength
        put(boot, 0x60, longLe(heapOffset))           // clusterHeapOffset
        put(boot, 0x68, longLe(clusterCount))         // clusterCount
        put(boot, 0x70, intLe(firstBitmap.toInt()))   // firstClusterOfBitmap
        put(boot, 0x74, intLe(firstRoot.toInt()))     // firstClusterOfRoot
        put(boot, 0x78, intLe((System.currentTimeMillis() and 0xFFFFFFFFL).toInt()))
        put(boot, 0x7C, shortLe(0x0100))              // fsRevision 1.0
        put(boot, 0x7E, shortLe(0))                   // volumeFlags
        boot[0x80] = Integer.numberOfTrailingZeros(sectorSize).toByte()
        boot[0x81] = spcShift.toByte()
        boot[0x82] = 1                                // numFats
        boot[0x83] = 0x80.toByte()                    // driveSelect
        boot[0x84] = 0xFF.toByte()                    // percentInUse unknown
        boot[510] = 0x55; boot[511] = 0xAA.toByte()

        val checksum = exfatChecksum(boot, sectorSize)
        raf.seek(offset); raf.write(boot)                     // sector 0
        val zeros = ByteArray(sectorSize)
        for (s in 1L until 11L) { raf.seek(offset + s * sectorSize); raf.write(zeros) }
        val ck = ByteArray(sectorSize); put(ck, 0, intLe(checksum))
        raf.seek(offset + 11L * sectorSize); raf.write(ck)
        // Backup boot region 12..23
        raf.seek(offset + 12L * sectorSize); raf.write(boot)
        for (s in 13L until 23L) { raf.seek(offset + s * sectorSize); raf.write(zeros) }
        raf.seek(offset + 23L * sectorSize); raf.write(ck)
        GuestLog.info("vhd: exFAT boot regions written (checksum=0x${checksum.toString(16)})")

        // FAT
        val fat = ByteArray((fatLength * sectorSize).toInt())
        put(fat, 0, intLe(0xFFFFFFF8.toInt()))
        put(fat, 4, intLe(0xFFFFFFFF.toInt()))
        // bitmap chain
        for (i in 0 until bitmapClusters) {
            val cl = firstBitmap + i
            val next = if (i == bitmapClusters - 1) 0x0FFFFFFF else (cl + 1)
            put(fat, (cl * 4).toInt(), intLe(next.toInt()))
        }
        // root chain (1 cluster)
        put(fat, (firstRoot * 4).toInt(), intLe(0x0FFFFFFF))
        raf.seek(offset + fatOffset * sectorSize)
        raf.write(fat)

        // Allocation bitmap
        val bitmap = ByteArray((bitmapClusters * spcBytes).toInt())
        for (c in 0 until bitmapClusters + 1) {          // clusters 2..(2+bitmapClusters-1) + root
            val idx = (firstBitmap + c).toInt()
            bitmap[idx / 8] = (bitmap[idx / 8].toInt() or (1 shl (idx % 8))).toByte()
        }
        raf.seek(offset + heapOffset * sectorSize)
        raf.write(bitmap)

        // Root directory: volume label entry
        val root = ByteArray(spc * sectorSize)
        if (spec.label.isNotBlank()) {
            spec.label.take(11).toByteArray(Charsets.US_ASCII).copyInto(root, 0)
            root[11] = 0x83.toByte()
        }
        raf.seek(offset + (heapOffset + (firstRoot - 2) * spc) * sectorSize)
        raf.write(root)

        GuestLog.info("vhd: exFAT formatted — clusters=$clusterCount bitmap=$bitmapClusters clusterSize=${spcBytes}B")
    }

    private fun exfatChecksum(boot: ByteArray, sectorSize: Int): Int {
        var sum = 0
        // 11 sectors of 512-byte units per spec (even for 4096: checksum covers boot region units)
        val total = if (sectorSize == 512) 512 * 11 else sectorSize * 11
        val data = ByteArray(total)
        boot.copyInto(data, 0, 0, minOf(boot.size, total))
        for (i in data.indices) {
            if (sectorSize == 512 && (i == 106 || i == 107 || i == 112)) continue
            sum = ((sum and 1) != 0).let { if (it) 0x80000000.toInt() else 0 } + (sum ushr 1) + (data[i].toInt() and 0xFF)
        }
        return sum
    }

    // ---------- NTFS / ext / markers ----------

    private fun writeNtfsBoot(raf: RandomAccessFile, offset: Long, sectors: Long,
                              sectorSize: Int, spec: CreateSpec) {
        val b = ByteArray(512)
        b[0] = 0xEB.toByte(); b[1] = 0x52; b[2] = 0x90.toByte()
        put(b, 3, "NTFS    ")
        put(b, 11, shortLe(sectorSize))
        b[13] = 0x40 // sectors per cluster heuristic (adjusted below if cluster set)
        b[21] = 0xF8.toByte()
        b[24] = 0x80.toByte(); b[26] = 0x80.toByte()
        put(b, 40, longLe(sectors))
        put(b, 48, longLe(sectors))       // MFT cluster (placeholder)
        put(b, 56, longLe(sectors))       // MFTMirr cluster (placeholder)
        b[64] = 0xF6.toByte()
        b[66] = 0x01                                // clusters per MFT record = 1
        b[510] = 0x55; b[511] = 0xAA.toByte()
        raf.seek(offset); raf.write(b)
        GuestLog.info("vhd: NTFS boot sector written (OEM 'NTFS    ') — full format deferred to NINE's NTFS driver at mount")
    }

    private fun writeExtSuperblock(raf: RandomAccessFile, offset: Long, sectors: Long,
                                   sectorSize: Int, spec: CreateSpec) {
        val blockLog = when {
            sectorSize >= 4096 -> 2  // 4K blocks
            else -> 0                // 1K blocks
        }
        val blockSize = 1024 shl blockLog
        val totalBlocks = (sectors * sectorSize) / blockSize
        if (totalBlocks < 16) throw IllegalStateException("image too small for ext superblock")
        val sb = ByteArray(1024)
        put(sb, 0, intLe(1024))                      // s_inodes_count (placeholder)
        put(sb, 4, intLe(totalBlocks.toInt()))
        put(sb, 12, intLe(0))                        // s_r_blocks_count
        put(sb, 16, intLe((totalBlocks * 3 / 100).toInt().coerceAtLeast(16))) // s_free_blocks_count
        put(sb, 24, intLe(64))                       // s_inodes_count-ish free
        put(sb, 32, intLe(0))                        // s_first_data_block
        put(sb, 36, intLe(blockLog))
        put(sb, 40, intLe(blockLog))
        put(sb, 48, intLe(32768))                    // s_blocks_per_group
        put(sb, 56, intLe(0xEF53))                   // s_magic
        put(sb, 60, shortLe(1))                      // s_state = clean
        put(sb, 64, shortLe(1))                      // s_errors = continue
        put(sb, 76, shortLe(0))                      // s_rev_level = dynamic (0)
        put(sb, 80, shortLe(0)); put(sb, 82, shortLe(0))
        put(sb, 84, intLe((System.currentTimeMillis() / 1000).toInt())) // s_wtime
        put(sb, 88, intLe(0))
        put(sb, 92, intLe(0x1))                      // s_creator_os = Linux
        put(sb, 96, intLe(0))                        // s_rev_level field for ext2 (dyn)
        // volume name at 0x78 (128 bytes) for rev1; write anyway
        if (spec.label.isNotBlank())
            spec.label.take(16).toByteArray().copyInto(sb, 0x78)
        raf.seek(offset + 1024)
        raf.write(sb)
        GuestLog.info("vhd: ext superblock written at +1024 (magic 0xEF53, ${blockSize}B blocks, $totalBlocks blocks) —" +
            " block groups/bitmap initialized by NINE's ext driver at mount")
    }

    private fun writeFsMarker(raf: RandomAccessFile, offset: Long, sectors: Long,
                              sectorSize: Int, spec: CreateSpec) {
        // Boot-sector/superblock magic markers where they are cheap and stable
        val marker: ByteArray? = when (spec.fs) {
            "XFS" -> ByteArray(4).also { put(it, 0, "XFSB".toByteArray()) }
            "Btrfs" -> ByteArray(0x10040).also { put(it, 0x10040, "_BHRfS_M".toByteArray()) }
            "F2FS" -> ByteArray(0x410).also {
                put(it, 0x400, intLe(0xF2F52010.toInt()))
                put(it, 0x404, intLe(1)) // major version
            }
            "HFS+" -> ByteArray(2048).also { it[1024] = 0x2B; it[1025] = 0x48; it[1026] = 0x58; it[1027] = 0x00 } // 'H+'
            "HFS" -> ByteArray(1024).also { put(it, 1024 - 0, "BD".toByteArray()) } // HFS MDB is at 1024; write below instead
            "ISO9660" -> ByteArray(16 * 2048 + 2048).also {
                it[16 * 2048 + 1] = 0x43 // PVD type 1
                put(it, 16 * 2048 + 6, "CD001".toByteArray())
            }
            "SquashFS" -> ByteArray(4).also { put(it, 0, intLe(0x73717368)) } // 'hsqs' LE
            "ROMFS" -> ByteArray(16).also { put(it, 0, "-rom1fs-".toByteArray()) }
            "CramFS" -> ByteArray(16).also { put(it, 0, intLe(0x28CD3D45.toInt())) }
            "NILFS2" -> ByteArray(0x408).also { put(it, 0x400, intLe(0x3434)) }
            "JFS" -> ByteArray(0x8010).also { put(it, 0x8000, "JFS1".toByteArray()) }
            "ReiserFS" -> ByteArray(0x10040).also { put(it, 0x10034, "ReIsEr2Fs".toByteArray()) }
            "Minix" -> ByteArray(1030).also { put(it, 1026, shortLe(0x137F)) }
            "UDF" -> ByteArray(17 * 2048 + 512).also { put(it, 17 * 2048 + 1, "BEA01NSR02".take(5).toByteArray()) }
            else -> null
        }
        if (marker != null) {
            raf.seek(offset)
            raf.write(marker)
            GuestLog.info("vhd: ${spec.fs} boot/superblock marker written — full format handled by NINE's ${spec.fs} layer at mount")
        } else {
            GuestLog.info("vhd: raw ${spec.fs} image created — filesystem structures written on first mount")
        }
        if (spec.fs == "HFS") {
            val mdb = ByteArray(162)
            mdb[0] = 0x42; mdb[1] = 0x44 // 'BD'
            raf.seek(offset + 1024); raf.write(mdb)
            GuestLog.info("vhd: HFS MDB written at +1024")
        }
    }

    // ---------- small helpers ----------

    private fun put(dst: ByteArray, at: Int, s: String) {
        val b = s.toByteArray(Charsets.US_ASCII)
        b.copyInto(dst, at)
    }

    private fun put(dst: ByteArray, at: Int, b: ByteArray) {
        if (at >= 0 && at + b.size <= dst.size) b.copyInto(dst, at)
    }

    private fun shortLe(v: Int): ByteArray = byteArrayOf(
        (v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte()
    )

    private fun intLe(v: Int): ByteArray = byteArrayOf(
        (v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte(),
        ((v shr 16) and 0xFF).toByte(), ((v shr 24) and 0xFF).toByte()
    )

    private fun longLe(v: Long): ByteArray = intLe((v and 0xFFFFFFFFL).toInt()) +
        intLe(((v ushr 32) and 0xFFFFFFFFL).toInt())

    private fun writeLe32(dst: ByteArray, at: Int, v: Long) {
        dst[at] = (v and 0xFF).toByte()
        dst[at + 1] = ((v shr 8) and 0xFF).toByte()
        dst[at + 2] = ((v shr 16) and 0xFF).toByte()
        dst[at + 3] = ((v shr 24) and 0xFF).toByte()
    }

    private fun put(dst: ByteArray, at: Int, v: Int) {
        val b = intLe(v)
        if (at >= 0 && at + 4 <= dst.size) b.copyInto(dst, at)
    }
}

/**
 * Minimal POSIX ustar writer (enough for .tar.gz export).
 */
class TarOutputStream(private val out: OutputStream) : OutputStream() {
    override fun write(b: Int) = out.write(b)

    fun addFile(name: String, file: File) {
        FileInputStream(file).use { addStream(name, file.length(), file.lastModified() / 1000, it) }
    }

    fun addBytes(name: String, data: ByteArray) {
        addStream(name, data.size.toLong(), System.currentTimeMillis() / 1000, data.inputStream())
    }

    private fun addStream(name: String, size: Long, mtime: Long, input: InputStream) {
        val header = ByteArray(512)
        val n = name.toByteArray(Charsets.US_ASCII)
        require(n.size <= 100) { "path too long for tar: $name" }
        n.copyInto(header, 0)
        "000644 \u0000".toByteArray().copyInto(header, 100)          // mode
        "000000 \u0000".toByteArray().copyInto(header, 108)          // uid
        "000000 \u0000".toByteArray().copyInto(header, 116)          // gid
        octal(size, 12).copyInto(header, 124)
        octal(mtime, 12).copyInto(header, 136)
        header[148] = 0x20; header[149] = 0x20; header[150] = 0x20
        header[151] = 0x20; header[152] = 0x00; header[153] = 0x30   // typeflag '0'
        "ustar\u0000".toByteArray().copyInto(header, 257)
        "00".toByteArray().copyInto(header, 263)
        "root\u0000".toByteArray().copyInto(header, 265)
        "root\u0000".toByteArray().copyInto(header, 297)
        // checksum
        var sum = 0
        for (b in header) sum += (b.toInt() and 0xFF)
        val chk = octal(sum.toLong(), 7)
        chk.copyInto(header, 148)
        header[155] = 0x20
        out.write(header)

        input.use { it.copyTo(out) }
        val pad = ((512 - (size % 512)) % 512).toInt()
        if (pad > 0) out.write(ByteArray(pad))
    }

    private fun octal(v: Long, field: Int): ByteArray {
        val s = java.lang.Long.toOctalString(v)
        val body = s.padStart(field - 1, '0').take(field - 1)
        return (body + "\u0000").toByteArray(Charsets.US_ASCII)
    }

    override fun close() {
        out.write(ByteArray(1024)) // two zero blocks
        out.flush()
    }
}
