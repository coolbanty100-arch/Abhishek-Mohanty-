# DroidShield — Android security scanner starter

A Kotlin + XML Android Studio project (min SDK 26 / Android 8.0) for local app metadata checks and APK inspection. Dark theme; no account, network access, analytics, or cloud uploads.

## Features
- Lists visible installed packages and computes SHA-256 hashes of their installed APK files.
- Checks a small set of explainable indicators: debuggable builds, installer not reported, and selected sensitive permissions.
- Lets the user choose an APK through Android's Storage Access Framework, copies it to app cache with a 200 MB cap, inspects package metadata, computes SHA-256, then deletes the temporary copy.
- Shows severity labels and contextual explanations. Results are indicators, not a definitive malware verdict.
- Unit tests for core heuristic behavior.

## Build
1. Install Android Studio and a JDK 17.
2. Open this `DroidShield` directory in Android Studio.
3. Allow Gradle sync and install Android SDK Platform 35 (or adjust `compileSdk` to an installed platform).
4. Run `app` on an Android 8.0+ device or emulator.
5. Run tests with `./gradlew test` if a Gradle wrapper is available in your environment, or use **Gradle > app > Tasks > verification > test** in Android Studio.

The Gradle wrapper JAR/scripts are not included. Android Studio can generate them via **File > New > New Project** or the local Gradle `wrapper` task if Gradle is installed.

## Permissions and package visibility
The manifest declares `QUERY_ALL_PACKAGES` so the scanner can list installed packages. Android 11+ package visibility otherwise filters package-manager results. Google Play treats broad package visibility as restricted and only permits it for qualifying core functionality; review the current Play policy before publishing. A Play-distributed consumer app may need a narrower `<queries>` declaration and a reduced scan scope.

No storage permission is requested. APK access uses `ACTION_OPEN_DOCUMENT` through `ActivityResultContracts.OpenDocument`, which lets the user choose a file.

## Important limitations
- This is **not a complete antivirus engine** and does not claim to detect all malware.
- The built-in known-bad SHA-256 set is empty. Populate it only from a trusted, maintained threat-intelligence source and include source/update metadata. Hash matches only identify exact known files; repacked or modified malware can have a different hash.
- Permission use, sideloading, or a debuggable flag can be legitimate. These are heuristic indicators and can create false positives.
- Android app sandboxing prevents this app from reading other apps' private data or inspecting all runtime behavior. It does not scan protected app data, memory, kernel state, or all files on the device.
- APK metadata inspection is not static code analysis. The app does not execute APKs, decompile bytecode, verify certificate trust chains, or query a reputation service.
- Hashing every installed APK can take time and battery on some devices. Results are processed on a background dispatcher; the UI is not blocked.
- This starter does not uninstall, disable, quarantine, or modify other apps.

## Safe extension roadmap
1. Add a signed, versioned local hash database with provenance and expiry.
2. Add a proper APK static-analysis module for DEX/manifest indicators, with size and decompression-bomb limits.
3. Add optional user-consented cloud reputation checks, clearly disclosing what hash or metadata is sent and never uploading APKs by default.
4. Add accessibility-friendly result filtering, export, and a reviewed privacy policy.
5. Run device tests across Android 8–16 and verify Play policy eligibility before release.
