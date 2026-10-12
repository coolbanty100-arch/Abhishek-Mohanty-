package com.droidshield.antivirus

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale

class MainActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private lateinit var summary: TextView
    private lateinit var results: TextView
    private lateinit var scanAppsButton: Button
    private lateinit var scanApkButton: Button

    private val apkPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) inspectSelectedApk(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        summary = findViewById(R.id.summary)
        results = findViewById(R.id.results)
        scanAppsButton = findViewById(R.id.scanAppsButton)
        scanApkButton = findViewById(R.id.scanApkButton)
        scanAppsButton.setOnClickListener { scanInstalledApps() }
        scanApkButton.setOnClickListener { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }
    }

    private fun setBusy(busy: Boolean, message: String) {
        status.text = message.uppercase(Locale.ROOT)
        scanAppsButton.isEnabled = !busy
        scanApkButton.isEnabled = !busy
        scanAppsButton.alpha = if (busy) 0.6f else 1f
        scanApkButton.alpha = if (busy) 0.6f else 1f
    }

    private fun scanInstalledApps() {
        setBusy(true, "Scanning installed apps…")
        summary.text = "Reading app metadata and checking local indicators."
        results.text = "Scan in progress…"
        lifecycleScope.launch {
            val scanResult = withContext(Dispatchers.IO) {
                runCatching {
                    val pm = packageManager
                    val packages = ScanEngine.installedPackages(pm)
                    val reports = packages.mapNotNull { pkg ->
                        val info = pkg.applicationInfo ?: return@mapNotNull null
                        val label = runCatching { info.loadLabel(pm).toString() }.getOrDefault(pkg.packageName)
                        val installer = runCatching {
                            if (android.os.Build.VERSION.SDK_INT >= 30) {
                                pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                            } else {
                                @Suppress("DEPRECATION")
                                pm.getInstallerPackageName(pkg.packageName)
                            }
                        }.getOrNull()
                        val hash = ScanEngine.sha256(File(info.sourceDir))
                        ScanEngine.analyzeApp(label, pkg.packageName, info.flags, pkg.requestedPermissions, installer, hash)
                    }
                    reports
                }
            }
            setBusy(false, "Scan complete")
            scanResult.onSuccess { reports ->
                val suspicious = reports.filter { it.isSuspicious }
                summary.text = "Checked ${reports.size} apps · ${suspicious.size} with medium/high indicators\n\nA risk indicator is not a malware verdict. Review findings below."
                results.text = buildString {
                    append("LOCAL APP CHECK\n\n")
                    if (suspicious.isEmpty()) append("No medium/high indicators were found by the current rules. This is not proof of safety.\n")
                    reports.sortedByDescending { it.riskScore }.take(60).forEach { report ->
                        append(if (report.isSuspicious) "⚠ " else "• ")
                        append(report.appName).append("\n")
                        append(report.packageName).append("\n")
                        report.findings.filter { it.severity != ScanEngine.Severity.INFO || report.isSuspicious }.forEach { f ->
                            append("  [${f.severity}] ${f.title}\n  ${f.detail}\n")
                        }
                        append("  SHA-256: ${report.sha256 ?: "unavailable"}\n\n")
                    }
                    if (reports.size > 60) append("Showing 60 of ${reports.size} apps.\n")
                }
            }.onFailure { error ->
                summary.text = "The scan could not finish."
                results.text = "Error: ${error.message ?: error.javaClass.simpleName}\n\nCheck that package visibility is allowed on this device."
            }
        }
    }

    private fun inspectSelectedApk(uri: Uri) {
        setBusy(true, "Inspecting selected APK…")
        lifecycleScope.launch {
            val report = withContext(Dispatchers.IO) {
                runCatching {
                    val temp = File(cacheDir, "selected-${System.currentTimeMillis()}.apk")
                    contentResolver.openInputStream(uri)?.use { input -> temp.outputStream().use { output -> input.copyTo(output) } }
                        ?: error("Could not read the selected file.")
                    try {
                        val length = temp.length()
                        require(length in 1..(200L * 1024 * 1024)) { "APK is empty or larger than the 200 MB safety limit." }
                        @Suppress("DEPRECATION")
                        val pkg = packageManager.getPackageArchiveInfo(temp.absolutePath, PackageManager.GET_PERMISSIONS)
                            ?: error("Android could not parse this file as an APK.")
                        val appInfo = pkg.applicationInfo
                        appInfo.sourceDir = temp.absolutePath
                        appInfo.publicSourceDir = temp.absolutePath
                        val appName = runCatching { appInfo.loadLabel(packageManager).toString() }.getOrDefault(pkg.packageName ?: "Unknown app")
                        val hash = ScanEngine.sha256(temp)
                        val installer = "Selected file (not installed)"
                        val findings = ScanEngine.analyzeApp(appName, pkg.packageName ?: "unknown.package", appInfo.flags, pkg.requestedPermissions, installer, hash)
                        Triple(findings, length, pkg.packageName ?: "unknown.package")
                    } finally { temp.delete() }
                }
            }
            setBusy(false, "APK inspection complete")
            report.onSuccess { (appReport, size, packageName) ->
                summary.text = "Inspected APK · ${size / 1024} KB\nPackage: $packageName\nNo file was installed."
                results.text = buildString {
                    append("APK INSPECTION\n\n")
                    appReport.findings.forEach { f -> append("[${f.severity}] ${f.title}\n${f.detail}\n\n") }
                    append("SHA-256: ${appReport.sha256 ?: "unavailable"}\n\n")
                    append("This checks package metadata and a small set of heuristics. It does not decompile or execute the APK, and does not establish that it is safe.")
                }
            }.onFailure { error ->
                summary.text = "Could not inspect this file."
                results.text = error.message ?: "Unknown error while reading APK."
            }
        }
    }
}
