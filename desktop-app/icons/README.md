# Desktop app icons

Generated from `assets/myotis_logo.svg` by `tools/make-icons.sh`:

- `myotis.png`  — Linux (512×512)
- `myotis.ico`  — Windows (multi-size)
- `myotis.icns` — macOS

These binaries are **not** committed; `desktop-app/build.gradle.kts` wires each icon
only when the file is present, and jpackage falls back to a default icon otherwise.
The release CI workflow regenerates them before packaging.
