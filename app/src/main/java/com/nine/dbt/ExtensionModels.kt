package com.nine.dbt

data class Repository(
    val id: String,
    val name: String,
    val url: String,          // e.g. https://github.com/user/nine-extensions
    val branch: String = "main",
    val enabled: Boolean = true
)

enum class CatalogItemType { EXTENSION, PATCH }

data class CatalogItem(
    val id: String,
    val name: String,
    val author: String,
    val description: String,
    val type: CatalogItemType,
    val downloadUrl: String,  // direct URL to .apk or .patch
    val version: String,
    val repositoryId: String,
    val installed: Boolean = false
)

data class InstalledExtension(
    val id: String,
    val name: String,
    val version: String,
    val packageName: String? = null
)

data class InstalledPatch(
    val id: String,
    val name: String,
    val version: String,
    val appliedAt: Long
)
