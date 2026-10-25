package com.nine.dbt

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * A program permanently stored in NINE's library.
 * All paths ([execRel], [libDirs]) are relative to [programDir].
 */
data class LibraryProgram(
    val id: String,
    val name: String,
    val developer: String,
    val os: String,            // "linux" | "windows"
    val kind: String,          // "elf" | "object" | "pe" | "bundle"
    val execRel: String,       // main executable, relative to program dir
    val libDirs: List<String>, // dirs containing .so (linux) / .dll (windows)
    val status: String,
    val addedAt: Long,
    val iconColor: Long
) {
    fun execPath(ctx: Context): File = File(ProgramLibrary.programDir(ctx, id), execRel)
    fun libDirPaths(ctx: Context): List<String> =
        libDirs.map { File(ProgramLibrary.programDir(ctx, id), it).absolutePath }
}

/**
 * Permanent program store + importer.
 *
 * Import accepts ELF binaries, Linux .o objects, Windows .exe (PE), and .zip
 * bundles. A zip may contain the program plus its shared libraries (.so for
 * Linux, .dll for Windows) and an optional `config.json` telling NINE where
 * those libraries are expected:
 *
 *   {
 *     "program": "bin/app",            // main executable inside the package
 *     "os": "linux",                   // optional: "linux" | "windows" (auto-detected otherwise)
 *     "name": "App Name",              // optional display name
 *     "developer": "Studio",           // optional
 *     "libraryPaths": ["lib", "libs"]  // dirs expected to hold .so/.dll
 *   }
 *
 * NINE looks for config.json at the zip root first, then anywhere inside.
 * The importer normalizes what it learned back into a config.json inside the
 * program's private directory so later stages (relink, and the future virtual
 * hard disk placement of libraries) can consume it.
 */
object ProgramLibrary {
    private const val PREFS = "nine_programs"
    private val ICON_COLORS = longArrayOf(
        0xFF00E5FF, 0xFF7C4DFF, 0xFF00E676, 0xFFFFAB00,
        0xFFFF5252, 0xFF64FFDA, 0xFFFF4081, 0xFF448AFF
    )

    fun programDir(ctx: Context, id: String): File = File(File(ctx.filesDir, "programs"), id)

    // ---------- persistence ----------

    fun all(ctx: Context): MutableList<LibraryProgram> {
        val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("programs", "[]") ?: "[]"
        val arr = JSONArray(raw)
        val out = mutableListOf<LibraryProgram>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val libs = mutableListOf<String>()
            val la = o.optJSONArray("libDirs") ?: JSONArray()
            for (j in 0 until la.length()) libs += la.getString(j)
            out += LibraryProgram(
                id = o.getString("id"),
                name = o.getString("name"),
                developer = o.optString("developer", "Imported"),
                os = o.getString("os"),
                kind = o.optString("kind", "elf"),
                execRel = o.getString("execRel"),
                libDirs = libs,
                status = o.optString("status", "Ready"),
                addedAt = o.optLong("addedAt", 0L),
                iconColor = o.optLong("iconColor", ICON_COLORS[0])
            )
        }
        return out
    }

    fun saveAll(ctx: Context, list: List<LibraryProgram>) {
        val arr = JSONArray()
        list.forEach { p ->
            val libs = JSONArray()
            p.libDirs.forEach { libs.put(it) }
            arr.put(
                JSONObject()
                    .put("id", p.id)
                    .put("name", p.name)
                    .put("developer", p.developer)
                    .put("os", p.os)
                    .put("kind", p.kind)
                    .put("execRel", p.execRel)
                    .put("libDirs", libs)
                    .put("status", p.status)
                    .put("addedAt", p.addedAt)
                    .put("iconColor", p.iconColor)
            )
        }
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("programs", arr.toString()).apply()
    }

    fun add(ctx: Context, p: LibraryProgram) {
        val l = all(ctx)
        l.add(0, p)
        saveAll(ctx, l)
    }

    fun update(ctx: Context, p: LibraryProgram) {
        val l = all(ctx)
        val i = l.indexOfFirst { it.id == p.id }
        if (i >= 0) {
            l[i] = p
            saveAll(ctx, l)
        }
    }

    // ---------- import ----------

    fun importFromUri(ctx: Context, uri: Uri): LibraryProgram {
        val displayName = displayName(ctx, uri) ?: "program"
        val id = System.currentTimeMillis().toString(36) + "-" +
            (0..0xFFFF).random().toString(16)
        val dir = programDir(ctx, id)
        dir.mkdirs()

        val magic = sniffStream(ctx, uri)
        return when (magic) {
            "zip" -> importZip(ctx, uri, id, dir, displayName)
            "elf" -> {
                val dest = File(dir, sanitizeFileName(displayName))
                copyTo(ctx, uri, dest)
                val et = elfEType(dest)
                LibraryProgram(
                    id = id, name = baseName(displayName), developer = "Imported",
                    os = "linux", kind = if (et == 1) "object" else "elf",
                    execRel = dest.name, libDirs = emptyList(),
                    status = "Ready", addedAt = System.currentTimeMillis(),
                    iconColor = colorFor(displayName)
                ).also { writeConfigJson(dir, it) }
            }
            "pe" -> {
                val dest = File(dir, sanitizeFileName(displayName))
                copyTo(ctx, uri, dest)
                LibraryProgram(
                    id = id, name = baseName(displayName), developer = "Imported",
                    os = "windows", kind = "pe",
                    execRel = dest.name, libDirs = emptyList(),
                    status = "Ready", addedAt = System.currentTimeMillis(),
                    iconColor = colorFor(displayName)
                ).also { writeConfigJson(dir, it) }
            }
            else -> throw IllegalArgumentException(
                "Unrecognized file — NINE imports ELF, Linux .o, Windows .exe, and .zip packages"
            )
        }
    }

    private fun importZip(ctx: Context, uri: Uri, id: String, dir: File, displayName: String): LibraryProgram {
        var configEntry: String? = null
        ctx.contentResolver.openInputStream(uri)?.use { input ->
            ZipInputStream(input).use { zip ->
                var entry: ZipEntry? = zip.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val dest = File(dir, entry.name)
                        val destCanon = dest.canonicalPath
                        if (!destCanon.startsWith(dir.canonicalPath + File.separator)) {
                            throw IllegalArgumentException("zip entry escapes package dir: ${entry.name}")
                        }
                        dest.parentFile?.mkdirs()
                        dest.outputStream().use { zip.copyTo(it) }
                        if (File(entry.name).name.equals("config.json", ignoreCase = true)) {
                            // root config wins over nested ones
                            if (configEntry == null || !entry.name.contains('/')) configEntry = entry.name
                        }
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }
        } ?: throw IllegalArgumentException("cannot open zip")

        // Parse optional config.json (root first, then nested)
        var cfgProgram: String? = null
        var cfgOs: String? = null
        var cfgName: String? = null
        var cfgDeveloper: String? = null
        var cfgExtra: JSONObject? = null
        val cfgLibPaths = mutableListOf<String>()
        configEntry?.let { rel ->
            runCatching {
                val o = JSONObject(File(dir, rel).readText())
                cfgProgram = o.optString("program").ifBlank { null }?.replace('\\', '/')?.removePrefix("./")
                cfgOs = o.optString("os").ifBlank { null }?.lowercase()
                cfgName = o.optString("name").ifBlank { null }
                cfgDeveloper = o.optString("developer").ifBlank { null }
                val la = o.optJSONArray("libraryPaths")
                if (la != null) for (j in 0 until la.length()) {
                    cfgLibPaths += la.getString(j).replace('\\', '/').removePrefix("./")
                }
                // carry relink/VHD fields so re-imported packages round-trip
                cfgExtra = JSONObject().also { x ->
                    o.optJSONArray("libraries")?.let { x.put("libraries", it) }
                    o.optJSONArray("vhdInstallPaths")?.let { x.put("vhdInstallPaths", it) }
                    o.optJSONObject("nine")?.let { x.put("nine", it) }
                }
            }
        }

        // Scan extracted files: classify executables vs shared libraries by magic
        data class Candidate(val rel: String, val file: File, val os: String, val isLib: Boolean, val et: Int)
        val candidates = mutableListOf<Candidate>()
        dir.walkTopDown().filter { it.isFile }.forEach { f ->
            val rel = f.relativeTo(dir).path.replace(File.separatorChar, '/')
            if (rel.equals("config.json", ignoreCase = true) || rel.endsWith("/config.json", ignoreCase = true))
                return@forEach
            when (fileMagic(f)) {
                "elf" -> {
                    val et = elfEType(f)
                    val libLike = rel.substringAfterLast('/').let { it.contains(".so") }
                    val isLib = libLike || (et == 3 && libLike)
                    candidates += Candidate(rel, f, "linux", isLib || (et == 3 && libLike), et)
                }
                "pe" -> {
                    candidates += Candidate(rel, f, "windows", peIsDll(f), -1)
                }
            }
        }
        if (candidates.isEmpty())
            throw IllegalArgumentException("zip contains no ELF or PE files")

        // Main program: config-specified, else best candidate
        val exec: Candidate = candidates.find { it.rel == cfgProgram && !it.isLib }
            ?: candidates.filter { !it.isLib }.minByOrNull { c ->
                // prefer ET_EXEC, then non-.so PE, then PIE
                when {
                    c.os == "elf" && c.et == 2 -> 0
                    c.os == "pe" -> 1
                    c.os == "elf" && c.et == 3 -> 2
                    else -> 3
                }
            }
            ?: throw IllegalArgumentException("zip has no main executable (only libraries)")

        // OS: config override, else by main program magic
        val os = cfgOs?.takeIf { it == "linux" || it == "windows" } ?: exec.os

        // Library dirs: config-declared paths (if they exist) + parents of found libs
        val libDirs = LinkedHashSet<String>()
        cfgLibPaths.filter { File(dir, it).isDirectory }.forEach { libDirs += it }
        candidates.filter { it.isLib }.forEach { c ->
            val parent = c.rel.substringBeforeLast('/', "")
            if (parent.isNotEmpty()) libDirs += parent
        }

        val program = LibraryProgram(
            id = id,
            name = cfgName ?: baseName(displayName),
            developer = cfgDeveloper ?: "Imported",
            os = os,
            kind = "bundle",
            execRel = exec.rel,
            libDirs = libDirs.toList(),
            status = "Ready",
            addedAt = System.currentTimeMillis(),
            iconColor = colorFor(cfgName ?: displayName)
        )
        writeConfigJson(dir, program, cfgExtra)
        return program
    }

    /**
     * Normalized config.json content: program metadata, optional relink fields
     * carried over from [extra] (libraries[], vhdInstallPaths[], nine.abiLibrary,
     * os override), and the nine.abiLibrary pointer every archive must have.
     */
    private fun buildConfigJson(p: LibraryProgram, extra: JSONObject? = null): JSONObject {
        val o = JSONObject()
            .put("program", p.execRel)
            .put("name", p.name)
            .put("developer", p.developer)
            .put("libraryPaths", JSONArray(p.libDirs))
        val extraOs = extra?.optString("os")?.takeIf { it == "linux" || it == "windows" }
        o.put("os", extraOs ?: p.os)
        extra?.let { x ->
            x.optJSONArray("libraries")?.let { o.put("libraries", it) }
            x.optJSONArray("vhdInstallPaths")?.let { o.put("vhdInstallPaths", it) }
            x.optJSONObject("nine")?.let { o.put("nine", it) }
        }
        if (!o.has("nine")) o.put("nine", JSONObject().put("abiLibrary", "nine/libnexus_core.so"))
        return o
    }

    /** Normalized config.json inside the program dir — NINE looks for this on relink/load. */
    private fun writeConfigJson(dir: File, p: LibraryProgram, extra: JSONObject? = null) {
        File(dir, "config.json").writeText(buildConfigJson(p, extra).toString(2))
    }

    /** Read config.json (if present) from a program's directory. */
    fun readConfigJson(ctx: Context, p: LibraryProgram): JSONObject? =
        runCatching { JSONObject(File(programDir(ctx, p.id), "config.json").readText()) }.getOrNull()

    /**
     * Persist a relink result into the program's config.json so plain Library
     * exports also carry libraries[] / vhdInstallPaths[] / nine.abiLibrary —
     * the fields the VHD installer and Termux layout consume.
     */
    fun saveRelinkToConfig(ctx: Context, p: LibraryProgram, r: RelinkResult) {
        if (!r.ok && r.libraries.isEmpty()) return
        runCatching {
            File(programDir(ctx, p.id), "config.json")
                .writeText(buildConfigJson(p, relinkConfig(r)).toString(2))
        }.onFailure { GuestLog.add("config: persist relink failed: ${it.message}") }
    }

    /** Relink fields as a config.json-shaped extra for [buildConfigJson]. */
    private fun relinkConfig(r: RelinkResult): JSONObject = JSONObject()
        .put("os", r.os)
        .put("libraries", JSONArray().also { arr ->
            r.libraries.forEach { l ->
                arr.put(
                    JSONObject()
                        .put("name", l.name)
                        .put("provider", l.provider)
                        .put("path", l.path)
                        .put("installPath", l.installPath)
                )
            }
        })
        .put("vhdInstallPaths", JSONArray(r.libraries.map { it.installPath }.distinct()))

    /**
     * Record the virtual hard disk this program must run on (the user's
     * active VHD in NINE). Light shells read the same path from
     * assets/vhd_path.txt; both stay in sync through relinks.
     */
    fun setVhdPath(ctx: Context, p: LibraryProgram, vhdPath: String) {
        runCatching {
            val dir = programDir(ctx, p.id)
            val f = File(dir, "config.json")
            val cfg = if (f.exists()) JSONObject(f.readText()) else buildConfigJson(p)
            cfg.put("vhdPath", vhdPath)
            f.writeText(cfg.toString(2))
        }.onFailure { GuestLog.add("config: vhdPath persist failed: ${it.message}") }
    }

    // ---------- export ----------

    /**
     * Stream NINE's ABI library to [block]. Tries the extracted native dir
     * first (extractNativeLibs=true devices), then the installed base/split
     * APKs — where libnexus_core.so always lives when native libs are loaded
     * straight from the APK. Returns false when it could not be found anywhere.
     */
    private fun withAbiLibrary(ctx: Context, block: (InputStream) -> Unit): Boolean {
        val direct = File(ctx.applicationInfo.nativeLibraryDir, "libnexus_core.so")
        if (direct.isFile) {
            direct.inputStream().use(block)
            return true
        }
        val apks = buildList {
            ctx.applicationInfo.sourceDir?.let { add(it) }
            ctx.applicationInfo.splitSourceDirs?.let { addAll(it) }
        }
        for (apk in apks) {
            val f = File(apk)
            if (!f.isFile) continue
            val hit = runCatching {
                ZipFile(f).use { zf ->
                    val e = zf.entries().asSequence().firstOrNull {
                        !it.isDirectory && it.name.startsWith("lib/") &&
                            it.name.endsWith("/libnexus_core.so")
                    }
                    if (e == null) return@use false
                    zf.getInputStream(e).use(block)
                    true
                }
            }.getOrDefault(false)
            if (hit) return true
        }
        return false
    }

    /** Zip-root form of a guest install root: "/usr/lib" -> "usr/lib", "C:\Windows\System32" -> "Windows/System32". */
    private fun zipPathForInstallRoot(installField: String): String =
        installField.replace('\\', '/')
            .replace(Regex("^[A-Za-z]:/"), "")
            .trimStart('/')

    /**
     * Copy every resolved library that has a host file into the archive at its
     * guest install path (config libraries[]: path -> installPath/name), so
     * deploying into the VHD — or running under Termux — is a straight
     * path-for-path copy. Entries dedupe through [seen]; "nine-abi" entries
     * have no file (they are served by NINE's ABI) and are skipped.
     */
    private fun writeInstallPathLibs(zip: ZipOutputStream, cfg: JSONObject, seen: MutableSet<String>) {
        val arr = cfg.optJSONArray("libraries") ?: return
        for (i in 0 until arr.length()) {
            val l = arr.optJSONObject(i) ?: continue
            val hostPath = l.optString("path")
            if (hostPath.isBlank()) continue
            val src = File(hostPath)
            if (!src.isFile) {
                GuestLog.add("package: library file missing on host: $hostPath")
                continue
            }
            val root = zipPathForInstallRoot(l.optString("installPath"))
            if (root.isEmpty()) continue
            val name = l.optString("name").substringAfterLast('/').substringAfterLast('\\')
                .ifBlank { src.name }
            val entry = if (root == name || root.endsWith("/$name")) root else "$root/$name"
            if (!seen.add(entry)) continue
            zip.putNextEntry(ZipEntry(entry))
            src.inputStream().use { it.copyTo(zip) }
            zip.closeEntry()
            GuestLog.info("package: lib $name -> $entry")
        }
    }

    /**
     * Package relinked programs for deployment into a zip at [uri]:
     *   nine/libnexus_core.so            — NINE's compiled ABI library
     *   programs/<name>/…                — program files
     *   programs/<name>/config.json      — enriched: resolved libraries[],
     *                                      vhdInstallPaths[] (unique install
     *                                      paths for the virtual hard disk),
     *                                      nine.abiLibrary
     *   usr/lib/…, Windows/System32/…    — bundled libraries at their guest
     *                                      install paths (VHD / Termux copy)
     */
    fun exportPackaged(
        ctx: Context,
        entries: List<Pair<LibraryProgram, RelinkResult>>,
        uri: Uri
    ) {
        ctx.contentResolver.openOutputStream(uri)?.use { out ->
            ZipOutputStream(out).use { zip ->
                val seen = mutableSetOf("nine/libnexus_core.so")
                val wroteAbi = withAbiLibrary(ctx) { s ->
                    zip.putNextEntry(ZipEntry("nine/libnexus_core.so"))
                    s.copyTo(zip)
                    zip.closeEntry()
                }
                if (!wroteAbi)
                    GuestLog.add("package: warning — libnexus_core.so not found (native dir or APK)")
                entries.forEach { (p, r) ->
                    val dir = programDir(ctx, p.id)
                    if (!dir.isDirectory) return@forEach
                    val prefix = "programs/" + sanitizeFileName(p.name)
                    val cfg = buildConfigJson(p, relinkConfig(r))
                    dir.walkTopDown().filter { it.isFile }.forEach { f ->
                        val rel = f.relativeTo(dir).path.replace(File.separatorChar, '/')
                        if (rel == "config.json") return@forEach // replaced below
                        val entry = "$prefix/$rel"
                        if (!seen.add(entry)) return@forEach
                        zip.putNextEntry(ZipEntry(entry))
                        f.inputStream().use { it.copyTo(zip) }
                        zip.closeEntry()
                    }
                    if (seen.add("$prefix/config.json")) {
                        zip.putNextEntry(ZipEntry("$prefix/config.json"))
                        zip.write(cfg.toString(2).toByteArray(Charsets.UTF_8))
                        zip.closeEntry()
                    }
                    writeInstallPathLibs(zip, cfg, seen)
                    GuestLog.info(
                        "package: ${p.name} -> $prefix (${r.libraries.size} libraries, " +
                            "${r.libraries.map { it.installPath }.distinct().size} install path(s))"
                    )
                }
            }
        } ?: throw IllegalArgumentException("cannot open destination")
    }

    /**
     * Pack the given programs into a deployable zip at [uri]: program files,
     * enriched config.json (libraries[] / vhdInstallPaths[] / nine.abiLibrary
     * when a relink was persisted), libraries at their guest install paths,
     * and nine/libnexus_core.so so the package runs standalone in the VHD
     * or under Termux.
     */
    fun exportPrograms(ctx: Context, progs: List<LibraryProgram>, uri: Uri) {
        ctx.contentResolver.openOutputStream(uri)?.use { out ->
            ZipOutputStream(out).use { zip ->
                val seen = mutableSetOf("nine/libnexus_core.so")
                val wroteAbi = withAbiLibrary(ctx) { s ->
                    zip.putNextEntry(ZipEntry("nine/libnexus_core.so"))
                    s.copyTo(zip)
                    zip.closeEntry()
                }
                if (!wroteAbi)
                    GuestLog.add("export: warning — libnexus_core.so not found (native dir or APK)")
                progs.forEach { p ->
                    val dir = programDir(ctx, p.id)
                    if (!dir.isDirectory) return@forEach
                    val prefix = sanitizeFileName(p.name) + "-" + p.id
                    // refresh config.json from current metadata (+ carried relink fields)
                    val cfg = buildConfigJson(p, readConfigJson(ctx, p))
                    File(dir, "config.json").writeText(cfg.toString(2))
                    dir.walkTopDown().filter { it.isFile }.forEach { f ->
                        val rel = f.relativeTo(dir).path.replace(File.separatorChar, '/')
                        val entry = "$prefix/$rel"
                        if (!seen.add(entry)) return@forEach
                        zip.putNextEntry(ZipEntry(entry))
                        f.inputStream().use { it.copyTo(zip) }
                        zip.closeEntry()
                    }
                    writeInstallPathLibs(zip, cfg, seen)
                    GuestLog.info("export: ${p.name} -> $prefix (+ NINE ABI library)")
                }
            }
        } ?: throw IllegalArgumentException("cannot open destination")
    }

    // ---------- helpers ----------

    private fun copyTo(ctx: Context, uri: Uri, dest: File) {
        ctx.contentResolver.openInputStream(uri)?.use { input ->
            dest.outputStream().use { input.copyTo(it) }
        } ?: throw IllegalArgumentException("cannot open $uri")
    }

    private fun displayName(ctx: Context, uri: Uri): String? {
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (i >= 0) return c.getString(i)
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/')
    }

    private fun sniffStream(ctx: Context, uri: Uri): String =
        ctx.contentResolver.openInputStream(uri)?.use { s ->
            val b = ByteArray(4)
            var off = 0
            while (off < 4) {
                val n = s.read(b, off, 4 - off)
                if (n < 0) break
                off += n
            }
            magicOf(b)
        } ?: ""

    private fun magicOf(b: ByteArray): String = when {
        b.size >= 4 && b[0] == 0x7F.toByte() && b[1] == 'E'.code.toByte() &&
            b[2] == 'L'.code.toByte() && b[3] == 'F'.code.toByte() -> "elf"
        b.size >= 2 && b[0] == 'M'.code.toByte() && b[1] == 'Z'.code.toByte() -> "pe"
        b.size >= 2 && b[0] == 'P'.code.toByte() && b[1] == 'K'.code.toByte() -> "zip"
        else -> ""
    }

    private fun fileMagic(f: File): String =
        RandomAccessFile(f, "r").use { r ->
            val b = ByteArray(4)
            val n = r.read(b)
            if (n < 2) "" else magicOf(b)
        }

    /** ELF e_type: 1=REL (.o), 2=EXEC, 3=DYN (PIE/.so); -1 if not ELF. */
    private fun elfEType(f: File): Int =
        RandomAccessFile(f, "r").use { r ->
            if (r.length() < 18) return@use -1
            val mag = ByteArray(4)
            r.read(mag)
            if (magicOf(mag) != "elf") return@use -1
            r.seek(16)
            r.readUnsignedByte() or (r.readUnsignedByte() shl 8)
        }

    private fun peIsDll(f: File): Boolean =
        RandomAccessFile(f, "r").use { r ->
            if (r.length() < 0x40) return@use false
            val mz = ByteArray(2)
            r.read(mz)
            if (magicOf(mz + ByteArray(2)) != "pe") return@use false
            r.seek(0x3C)
            var lfanew = 0
            for (i in 0 until 4) lfanew = lfanew or (r.readUnsignedByte() shl (8 * i))
            if (lfanew <= 0 || lfanew + 24 > r.length()) return@use false
            r.seek(lfanew.toLong())
            val sig = ByteArray(4)
            r.read(sig)
            if (!(sig[0] == 'P'.code.toByte() && sig[1] == 'E'.code.toByte() &&
                    sig[2].toInt() == 0 && sig[3].toInt() == 0)) return@use false
            // COFF header: Machine(2) NumberOfSections(2) TimeDateStamp(4)
            // PointerToSymbolTable(4) NumberOfSymbols(4) SizeOfOptionalHeader(2) Characteristics(2)
            r.seek(lfanew.toLong() + 22)
            val ch = r.readUnsignedByte() or (r.readUnsignedByte() shl 8)
            (ch and 0x2000) != 0 // IMAGE_FILE_DLL
        }

    private fun baseName(name: String): String =
        name.substringAfterLast('/').substringBeforeLast('.')

    private fun sanitizeFileName(name: String): String =
        name.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_")

    private fun colorFor(seed: String): Long {
        var h = 0
        for (c in seed) h = 31 * h + c.code
        return ICON_COLORS[Math.floorMod(h, ICON_COLORS.size)]
    }
}

/**
 * Programs NINE ships with.
 *
 * `assets/programs/hello-x86_64` is a freestanding C program built from
 * `samples/hello-x86_64/hello.c` (see its build.sh): no libc, no dynamic
 * loader, only mov/xor/lea/syscall. It prints through the Linux write
 * syscall and exits through exit(2), so it doubles as a fast smoke test for
 * the loader, interpreter and syscall path without needing a 700 KB glibc
 * binary.
 *
 * Installed once, on first launch, then treated like any imported program.
 */
object BuiltinPrograms {
    const val HELLO_ID = "nine-hello-x86_64"
    private const val PREFS = "nine_builtins"
    private const val KEY_HELLO = "hello_x86_64_installed_v1"

    fun ensureInstalled(ctx: Context) {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY_HELLO, false)) return
        runCatching {
            val dir = ProgramLibrary.programDir(ctx, HELLO_ID)
            dir.mkdirs()
            val exec = File(dir, "hello")
            ctx.assets.open("programs/hello-x86_64").use { input ->
                exec.outputStream().use { output -> input.copyTo(output) }
            }
            exec.setExecutable(true, false)
            if (ProgramLibrary.all(ctx).none { it.id == HELLO_ID }) {
                ProgramLibrary.add(
                    ctx,
                    LibraryProgram(
                        id = HELLO_ID,
                        name = "Hello (C, x86-64)",
                        developer = "NINE",
                        os = "linux",
                        kind = "elf",
                        execRel = "hello",
                        libDirs = emptyList(),
                        status = "Ready",
                        addedAt = System.currentTimeMillis(),
                        iconColor = 0xFF00E5FF
                    )
                )
            }
            prefs.edit().putBoolean(KEY_HELLO, true).apply()
        }.onFailure {
            GuestLog.add("builtin hello install failed: ${it.message}")
        }
    }
}
