import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Light-shell template APK. Built at NINE build time and copied into
// app/src/main/assets/shell-template.apk; the Relink flow patches it
// (package name/label/icon), adds payload, v1-signs and installs it.
val nineBuildRoot: File = file(
    System.getenv("NINE_BUILD_DIR")
        ?: (System.getProperty("java.io.tmpdir") + File.separator + "nine-build")
)
layout.buildDirectory = file("$nineBuildRoot/shell")

android {
    namespace = "com.nine.shell"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.nine.shell"
        // targetSdk 29 keeps v1-only (JAR) signatures installable, which
        // the runtime signer (ApkV1Signer) produces.
        minSdk = 26
        targetSdk = 29
        versionCode = 1
        versionName = "1.0"
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    // No Compose here: the template stays small and its activities are plain
    // views, matching the "light" in light shell.
    kotlinOptions { jvmTarget = "17" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // core-ktx is only needed for FileProvider used by settings (VHD share);
    // keep dependencies minimal.
    implementation("androidx.core:core-ktx:1.15.0")
}
