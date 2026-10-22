plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// OneDrive "Files On-Demand" (this project lives under OneDrive) periodically
// turns files under build/ and .cxx/ into cloud-only reparse points, which
// breaks Gradle snapshotting with "not a regular file" IOExceptions.
// Redirect all build outputs (including CMake/.cxx trees) to a local,
// non-synced temp directory. Set NINE_BUILD_DIR to override the location.
val nineBuildRoot: File = file(
    System.getenv("NINE_BUILD_DIR")
        ?: (System.getProperty("java.io.tmpdir") + File.separator + "nine-build")
)

layout.buildDirectory = file("$nineBuildRoot/app")

android {
    namespace = "com.nine.dbt"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.nine.dbt"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
            // Keep the .cxx CMake trees out of OneDrive as well
            buildStagingDirectory = nineBuildRoot.resolve("app${File.separator}cxx")
        }
    }

    ndkVersion = "26.1.10909125"
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.8.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.tensorflow:tensorflow-lite:2.16.1")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
