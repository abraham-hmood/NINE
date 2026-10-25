# NINE Self-Patching Design

Patches are `.patch` files. Extensions are `.apk` files.

## What is actually implemented (audited 2026-10-25)

| Piece | State | Where |
|---|---|---|
| Catalog browsing (`nine-catalog.json`, `type: extension|patch`) | 🟩 | `CatalogFetcher`, `AppStore`, Add Repository screen |
| Extension download | 🟩 | `ExtensionInstaller.download`, progress in the Extensions tab |
| Extension install via `PackageInstaller` | 🟩 | `ExtensionInstaller.installApk` — session + user confirmation |
| Patch download (stored as a file) | 🟩 | same downloader, `type: patch` |
| Unified-diff apply | 🟨 | `ExtensionInstaller.applyPatch` — a line model, not a real hunk applier: `@@` resets the cursor to the top, so multi-hunk patches and offsets are not handled; the result goes to `files/patches/<name>.applied` |
| `compile_patch` agent tool | 🟩 (same limitation) | `ToolExecutor.compilePatch` — writes a `.patch` for the project dir, applies it to `base`, saves the applied text |
| Binary diff (bsdiff/bspatch), patched-APK staging, hash/signature verification, rollback, companion 9Patch builder | ⬛ | design only, below |

So today a patch is a text transformation, not an APK surgery: nothing here
installs a patched build of NINE. The design below is the target, not the
current state.

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
