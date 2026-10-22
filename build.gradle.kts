plugins {
    id("com.android.application") version "8.13.0" apply false
    id("org.jetbrains.kotlin.android") version "2.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.0" apply false
}

// Keep root build outputs out of OneDrive too (see app/build.gradle.kts).
val nineBuildRoot: File = file(
    System.getenv("NINE_BUILD_DIR")
        ?: (System.getProperty("java.io.tmpdir") + File.separator + "nine-build")
)

layout.buildDirectory = file("$nineBuildRoot/root")
