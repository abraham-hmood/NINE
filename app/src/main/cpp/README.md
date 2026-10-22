# Native Core (Phase 0)

This directory contains the C++ NDK core for Nexus.

## Current status
- **Phase 0.2.1**: Project structure with CMake + NDK (arm64-v8a)
- **Phase 0.2.2**: MemoryManager (fully implemented)
- **Phase 0.2.3**: Logging & Diagnostics
  - Structured Logger with levels + categories
  - Ring buffer of recent messages
  - Guest register dump
  - Guest memory dump request
  - Translation cache statistics counters
  - Android log integration
  - MemoryManager now uses the structured logger

## Building
The native library `libnexus_core.so` is built automatically by Gradle/CMake when you sync and build the Android project.

No JNI bindings to the UI have been added yet (per request).
