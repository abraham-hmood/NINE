package com.nine.dbt

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.os.Build
import android.os.Environment
import androidx.core.content.FileProvider
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * Light-shell APK packager.
 *
 * Flow (invoked from the Library tab's Relink action):
 *   1. `:shell` gradle module is built at NINE build time and embedded as
 *      assets/shell-template.apk (package com.nine.shell, minimal UI).
 *   2. Unzip the template, patch the binary AndroidManifest with
 *      AxmlPatcher: unique package name (com.nine.shell.<program>) and the
 *      program's display name as application label.
 *   3. Replace the launcher icon PNGs with an icon generated from the
 *      program name/color.
 *   4. Add payload under assets/program/ (exec + libs + config.json),
 *      libnexus_core.so under lib/arm64-v8a/, and the active VHD path as
 *      assets/vhd_path.txt.
 *   5. v1-sign with a fresh self-signed key (ApkV1Signer), save to
 *      <external>/NINE/shells/, install via PackageInstaller; after the user
 *      confirms, the grant callback hands the shell FileProvider access to
 *      the active VHD.
 */
object LightShellPackager {

    private const val TEMPLATE_ASSET = "shell-template.apk"
    private const val TEMPLATE_PACKAGE = "com.nine.shell"
    private const val TEMPLATE_LABEL = "NINE Shell"
    private const val PREFS = "light_shells"

    /**
     * Where finished shells land. Real shared storage (/sdcard/NINE/shells,
     * per the NINE spec) when All-files access is granted; the app-scoped
     * external dir otherwise — the path is logged either way.
     */
    fun shellsDir(ctx: Context): File {
        val root = if (Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()) {
            File(Environment.getExternalStorageDirectory(), "NINE/shells")
        } else {
            File(ctx.getExternalFilesDir(null), "NINE/shells")
        }
        root.mkdirs()
        return root
    }

    fun sanitizePackageId(name: String): String {
        var clean = ""
        for (ch in name.lowercase()) {
            if (ch in 'a'..'z' || ch in '0'..'9') clean += ch else clean += '_'
        }
        return clean.take(24).trimEnd('_', '-').ifEmpty { "app" }
    }

    fun shellPackageName(programName: String): String =
        "$TEMPLATE_PACKAGE.${sanitizePackageId(programName)}"

    fun sanitizeFileName(name: String): String =
        name.filter { it.isLetterOrDigit() || it == ' ' || it == '-' }
            .replace(Regex(" +"), " ").trim().take(48).ifEmpty { "app" }

    /** Builds + installs the light shell for [program]; throws on failure. */
    fun buildAndInstall(ctx: Context, program: LibraryProgram) {
        GuestLog.info("light shell: building for ${program.name}…")
        val apk = build(ctx, program)
        GuestLog.info("light shell: apk saved at ${apk.absolutePath} (${apk.length()} bytes)")
        rememberPendingGrant(ctx, program)
        ExtensionInstaller.installApk(ctx, apk)
        GuestLog.info(
            "light shell: install session committed for ${shellPackageName(program.name)} " +
            "— confirm the Android install prompt to finish"
        )
    }

    fun build(ctx: Context, program: LibraryProgram): File {
        val template = File(ctx.cacheDir, TEMPLATE_ASSET)
        ctx.assets.open(TEMPLATE_ASSET).use { input ->
            template.outputStream().use { input.copyTo(it) }
        }
        val pkgName = shellPackageName(program.name)

        val zipFile = ZipFile(template)
        val manifest = run {
            val e = zipFile.getEntry("AndroidManifest.xml")
                ?: throw IllegalStateException("template manifest missing")
            zipFile.getInputStream(e).readBytes()
        }
        val manifestPatched = AxmlPatcher.patchStrings(
            manifest,
            // EXACT matches only: the application package attribute must rename
            // (that's the app's identity), but the component class names
            // (`.ShellMainActivity` expanded by aapt2 to com.nine.shell.*)
            // MUST stay constant — they reference classes inside the template
            // DEX, and renaming them here breaks ClassNotFoundException-safe
            // activity instantiation (verified on device).
            AxmlPatcher.Patch(TEMPLATE_PACKAGE, pkgName),
            AxmlPatcher.Patch(TEMPLATE_LABEL, program.name)
        )

        val coreLib = nativeCoreLibrary(ctx)
            ?: throw IllegalStateException(
                "libnexus_core.so missing from ${ctx.applicationInfo.nativeLibraryDir}")

        val vhdPath = VhdManager.activeImagePath(ctx)

        // program payload
        val progDir = ProgramLibrary.programDir(ctx, program.id)
        val payload = LinkedHashMap<String, ByteArray>()
        payload["assets/program/config.json"] =
            File(progDir, "config.json").takeIf { it.exists() }?.readBytes() ?: "{}".toByteArray()
        payload["assets/program/execRel.txt"] = program.execRel.toByteArray()
        File(progDir, program.execRel).takeIf { it.exists() }?.let {
            // keep the exec's real relative path so the shell's extraction
            // (which preserves names and resolves execRel.txt) finds it
            payload["assets/program/${program.execRel}"] = it.readBytes()
        }
        program.libDirs.forEach { rel ->
            File(progDir, rel).takeIf { it.isDirectory }?.let { dir ->
                dir.listFiles()?.filter { it.isFile }?.forEach { f ->
                    payload["assets/program/libs/$rel/${f.name}"] = f.readBytes()
                }
            }
        }
        if (vhdPath.isNotEmpty()) {
            payload["assets/vhd_path.txt"] = vhdPath.toByteArray()
        }

        val iconBytes = ByteArrayOutputStream().also {
            programIcon(program).compress(Bitmap.CompressFormat.PNG, 100, it)
        }.toByteArray()

        // signed entry list
        val entries = LinkedHashMap<String, ByteArray>()
        entries["AndroidManifest.xml"] = manifestPatched
        val templateEntries = zipFile.entries()
        while (templateEntries.hasMoreElements()) {
            val e = templateEntries.nextElement()
            if (e.isDirectory || e.name.startsWith("META-INF/")) continue
            if (e.name == "AndroidManifest.xml") continue
            val isIcon = e.name.endsWith("app_icon.png") || e.name.endsWith("app_icon.webp")
            entries[e.name] = if (isIcon) iconBytes else zipFile.getInputStream(e).readBytes()
        }
        zipFile.close()
        payload.forEach { (n, d) -> entries[n] = d } // payload is signed too
        val coreLibName = "lib/arm64-v8a/libnexus_core.so"
        entries[coreLibName] = coreLib

        val (certDer, kp) = ApkV1Signer.loadOrCreateIdentity(ctx)
        // v1 covers EVERY non-META-INF entry — the core lib must be digest-
        // listed in MANIFEST.MF/SF or PackageInstaller refuses the install.
        val meta = ApkV1Signer.writeV1Signature(entries.entries.map { it.key to it.value }, certDer, kp)

        val out = File(shellsDir(ctx), "shell-${sanitizeFileName(program.name)}.apk")
        ZipOutputStream(out.outputStream()).use { zip ->
            fun put(name: String, data: ByteArray) {
                zip.putNextEntry(ZipEntry(name).apply { method = ZipEntry.DEFLATED })
                zip.write(data)
                zip.closeEntry()
            }
            entries[coreLibName]?.let { put(coreLibName, it) }
            entries.forEach { (n, d) -> if (n != coreLibName) put(n, d) }
            meta.forEach { (n, d) -> put(n, d) }
        }
        return out
    }

    /**
     * The app's own shipped libnexus_core.so (arm64-v8a). Note: NINE ships
     * with extractNativeLibs=false (libs page-aligned inside base.apk), so
     * nativeLibraryDir is empty — read the entry straight out of sourceDir.
     */
    private fun nativeCoreLibrary(ctx: Context): ByteArray? {
        try {
            val apk = java.util.zip.ZipFile(File(ctx.applicationInfo.sourceDir))
            apk.use { zip ->
                val e = zip.getEntry("lib/arm64-v8a/libnexus_core.so")
                    ?: zip.getEntry("lib/arm64/libnexus_core.so")
                if (e != null) return zip.getInputStream(e).readBytes()
            }
        } catch (_: Throwable) {
        }
        // fallback: extracted layout (extractNativeLibs=true builds)
        return File(ctx.applicationInfo.nativeLibraryDir, "libnexus_core.so")
            .takeIf { it.exists() }?.readBytes()
    }

    /** PNG launcher icon generated from the program's name + color. */
    private fun programIcon(program: LibraryProgram): Bitmap {
        val size = 512
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        val color = program.iconColor.toInt()
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = RadialGradient(
                size * 0.5f, size * 0.42f, size * 0.62f,
                color, 0xFF0A0A12.toInt(), Shader.TileMode.CLAMP
            )
            style = Paint.Style.FILL
        }
        canvas.drawCircle(size * 0.5f, size * 0.5f, size * 0.46f, paint)
        val letter = program.name.trim().take(1).uppercase().ifEmpty { "?" }
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            setColor(android.graphics.Color.WHITE)
            setTextSize(size * 0.42f)
            setTextAlign(Paint.Align.CENTER)
            isFakeBoldText = true
        }
        canvas.drawText(letter, size * 0.5f, size * 0.5f + textPaint.textSize * 0.35f, textPaint)
        return bmp
    }

    // ---------- VHD grant plumbing ----------

    private fun rememberPendingGrant(ctx: Context, program: LibraryProgram) {
        val vhdPath = VhdManager.activeImagePath(ctx)
        if (vhdPath.isEmpty()) return
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("pending_shell_package", shellPackageName(program.name))
            .putString("pending_shell_vhd_path", vhdPath)
            .apply()
    }

    /**
     * Called from InstallResultReceiver after a successful light-shell
     * install: grants the shell package access to the active VHD image.
     */
    fun grantVhdIfPending(ctx: Context, installedPackage: String) {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val pkg = p.getString("pending_shell_package", null) ?: return
        if (pkg != installedPackage) return
        val path = p.getString("pending_shell_vhd_path", null) ?: return
        p.edit().remove("pending_shell_package").remove("pending_shell_vhd_path").apply()
        try {
            val image = File(path)
            if (!image.exists()) return
            val uri = FileProvider.getUriForFile(ctx, "com.nine.dbt.vhdshare", image)
            ctx.grantUriPermission(
                pkg, uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
            GuestLog.info("light shell: granted VHD access to $pkg")
        } catch (e: Throwable) {
            GuestLog.add("light shell: VHD grant failed: ${e.message}")
        }
    }
}
