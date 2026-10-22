package android.content
open class Context { val filesDir: java.io.File = java.io.File("/tmp/nine_files").also { it.mkdirs() } }
