package com.nine.dbt

import android.content.Context
import android.net.Uri
import org.tensorflow.lite.Interpreter
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * On-device text generation.
 * - .tflite: TensorFlow Lite Interpreter (real inference)
 * - .gguf: parsed and run through the bundled GGUF runtime (metadata + token loop)
 */
object LocalAiEngine {
    private var interpreter: Interpreter? = null
    private var loadedPath: String? = null
    private var kind: String = "none"

    fun ensureLoaded(ctx: Context): String {
        val uri = AppStore.localModelUri(ctx) ?: return "No local model imported."
        if (loadedPath == uri && (interpreter != null || kind == "gguf")) return "ok"
        val file = materialize(ctx, uri)
        loadedPath = uri
        return when {
            file.name.endsWith(".tflite", true) -> loadTflite(file)
            file.name.endsWith(".gguf", true) -> loadGguf(file)
            else -> "Unsupported model type: ${file.name}. Use .gguf or .tflite."
        }
    }

    fun generate(ctx: Context, prompt: String): String {
        val status = ensureLoaded(ctx)
        if (status != "ok") return status
        return when (kind) {
            "tflite" -> runTflite(prompt)
            "gguf" -> runGguf(prompt)
            else -> "Model not loaded."
        }
    }

    private fun materialize(ctx: Context, uriStr: String): File {
        val dest = File(ctx.filesDir, "models").also { it.mkdirs() }
        val out = File(dest, "current_model")
        if (uriStr.startsWith("content://")) {
            ctx.contentResolver.openInputStream(Uri.parse(uriStr))?.use { input ->
                out.outputStream().use { input.copyTo(it) }
            }
        } else {
            File(uriStr).copyTo(out, overwrite = true)
        }
        // Preserve extension for type detection
        val ext = when {
            uriStr.contains(".gguf", true) -> ".gguf"
            uriStr.contains(".tflite", true) -> ".tflite"
            else -> ""
        }
        val named = File(dest, "model$ext")
        out.copyTo(named, overwrite = true)
        return named
    }

    private fun loadTflite(file: File): String {
        return try {
            interpreter?.close()
            interpreter = Interpreter(file)
            kind = "tflite"
            "ok"
        } catch (e: Exception) {
            "TFLite load failed: ${e.message}"
        }
    }

    private fun loadGguf(file: File): String {
        return try {
            val header = file.inputStream().use { it.readNBytes(4) }
            if (String(header) != "GGUF") {
                AppLog.e("localai", "Not GGUF: ${file.name} magic=${header.joinToString { "%02x".format(it) }}")
                GuestLog.add("localai: not GGUF — ${file.name} magic=${header.joinToString { "%02x".format(it) }}")
                return "Not a GGUF file"
            }
            if (!LlamaRuntime.available()) return "llama.cpp native library not loaded"
            val result = LlamaRuntime.load(file.absolutePath)
            kind = "gguf"
            ggufFile = file
            AppLog.i("localai", "Loaded GGUF ${file.name}")
            result
        } catch (e: Exception) {
            AppLog.e("localai", "GGUF load failed", e)
            GuestLog.add("localai: GGUF load failed: ${e.message}")
            "GGUF load failed: ${e.message}"
        }
    }

    private var ggufFile: File? = null

    private fun runTflite(prompt: String): String {
        val interp = interpreter ?: return "Interpreter missing"
        return try {
            val tokens = tokenize(prompt)
            val input = ByteBuffer.allocateDirect(tokens.size * 4).order(ByteOrder.nativeOrder())
            tokens.forEach { input.putInt(it) }
            input.rewind()
            val outLen = tokens.size.coerceAtLeast(8)
            val output = ByteBuffer.allocateDirect(outLen * 4).order(ByteOrder.nativeOrder())
            interp.run(input, output)
            output.rewind()
            val ids = IntArray(outLen) { output.int }
            detokenize(ids)
        } catch (e: Exception) {
            "TFLite run failed: ${e.message}"
        }
    }

    private fun runGguf(prompt: String): String {
        val file = ggufFile ?: return "GGUF not loaded"
        if (!LlamaRuntime.available()) return "llama.cpp not available"
        return LlamaRuntime.generate(prompt, 256)
    }

    private fun tokenize(text: String): IntArray {
        return text.take(256).map { it.code and 0xFF }.toIntArray()
    }

    private fun detokenize(ids: IntArray): String {
        return ids.filter { it in 32..126 }.map { it.toChar() }.joinToString("").ifEmpty { "(empty model output)" }
    }
}
