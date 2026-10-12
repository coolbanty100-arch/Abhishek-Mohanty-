package com.droidshield.antivirus

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.Locale

/** Lightweight local checks. These heuristics cannot prove an app is malicious. */
object ScanEngine {
    enum class Severity { INFO, LOW, MEDIUM, HIGH }
    data class Finding(val severity: Severity, val title: String, val detail: String)
    data class AppReport(val appName: String, val packageName: String, val sha256: String?, val findings: List<Finding>) {
        val riskScore: Int get() = findings.sumOf { when (it.severity) { Severity.INFO -> 0; Severity.LOW -> 1; Severity.MEDIUM -> 2; Severity.HIGH -> 3 } }
        val isSuspicious: Boolean get() = findings.any { it.severity == Severity.MEDIUM || it.severity == Severity.HIGH }
    }

    // Empty by default: populate only from a trusted, maintained source of verified SHA-256 hashes.
    // A match means known-hash match, not a universal verdict about all versions of an app.
    private val knownBadSha256: Set<String> = emptySet()

    fun sha256(file: File): String? = runCatching {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    fun analyzeApp(
        appName: String,
        packageName: String,
        flags: Int,
        requestedPermissions: Array<String>?,
        installerPackage: String?,
        sha256: String?
    ): AppReport {
        val findings = mutableListOf<Finding>()
        val perms = requestedPermissions.orEmpty().toSet()
        if (flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            findings += Finding(Severity.MEDIUM, "Debuggable build", "The app is marked debuggable. This can be legitimate for development, but is unusual in a production app.")
        }
        if (flags and ApplicationInfo.FLAG_SYSTEM == 0 && installerPackage.isNullOrBlank()) {
            findings += Finding(Severity.LOW, "Installer not identified", "Android did not report an installer package. This can happen with sideloaded apps or some device configurations.")
        }
        val sensitiveGroups = listOf(
            setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"),
            setOf("android.permission.RECORD_AUDIO"),
            setOf("android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"),
            setOf("android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG"),
            setOf("android.permission.SYSTEM_ALERT_WINDOW"),
            setOf("android.permission.REQUEST_INSTALL_PACKAGES")
        )
        val labels = listOf("SMS access", "Microphone access", "Contacts access", "Call-log access", "Overlay capability", "APK installation capability")
        sensitiveGroups.forEachIndexed { index, group ->
            val matches = perms.intersect(group)
            if (matches.isNotEmpty()) findings += Finding(
                Severity.LOW, "Sensitive permission: ${labels[index]}",
                "Requested: ${matches.joinToString()}. The permission may be justified by the app's purpose; inspect its context before deciding."
            )
        }
        if (!sha256.isNullOrBlank() && sha256.lowercase(Locale.ROOT) in knownBadSha256) {
            findings += Finding(Severity.HIGH, "Known hash match", "The file hash matches an entry in the configured local threat list. Verify the source and update date of that list.")
        }
        if (findings.isEmpty()) findings += Finding(Severity.INFO, "No configured indicators found", "This scan found no indicators covered by its limited local rules. It does not prove the app is safe.")
        return AppReport(appName, packageName, sha256, findings)
    }

    @Suppress("DEPRECATION")
    fun installedPackages(pm: PackageManager): List<PackageInfo> {
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }
        return packages.sortedBy { it.applicationInfo?.loadLabel(pm)?.toString()?.lowercase(Locale.ROOT) ?: it.packageName }
    }
}
