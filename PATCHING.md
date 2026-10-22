# NINE Self-Patching Design

Patches are `.patch` files. Extensions are `.apk` files.

## Extensions
- Download the APK from the repository catalog URL.
- Install with `PackageInstaller` (user confirms).
- Track in the Installed list.

## Patches
Two supported patch formats (detect by header / extension):

1. **Binary diff** (preferred for APK patching) — `bsdiff`/`bspatch` style.
   - Apply the patch to the currently installed NINE APK (or a staged copy).
   - Verify the result (signature or hash from the catalog).
   - Install the patched APK via `PackageInstaller`.

2. **Unified diff** — standard `.patch` / `.diff`.
   - Used when the patch targets source. Applying it requires a build.
   - This path uses a companion **9Patch** app (or an on-device build step) that:
     1. Receives the base source + patch
     2. Applies the unified diff
     3. Builds a new APK
     4. Hands it back to NINE for installation

## Safety
- Always stage the patched APK; never overwrite the running APK in place.
- Verify hash/signature before install.
- Keep the previous APK so the user can roll back.
- Request `REQUEST_INSTALL_PACKAGES` only when needed.

## Catalog format (in each GitHub repo)
`nine-catalog.json`:
```json
{
  "items": [
    {
      "id": "example-ext",
      "name": "Example Extension",
      "author": "someone",
      "description": "...",
      "type": "extension",
      "version": "1.0.0",
      "downloadUrl": "https://github.com/user/repo/releases/download/v1/ext.apk"
    },
    {
      "id": "example-patch",
      "name": "Example Patch",
      "author": "someone",
      "description": "...",
      "type": "patch",
      "version": "1.0.0",
      "downloadUrl": "https://github.com/user/repo/releases/download/v1/fix.patch"
    }
  ]
}
```
