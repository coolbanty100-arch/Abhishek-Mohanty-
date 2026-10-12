package com.droidshield.antivirus

import android.content.pm.ApplicationInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanEngineTest {
    @Test fun cleanMetadataProducesLimitedInfoFinding() {
        val report = ScanEngine.analyzeApp("Example", "example.app", 0, emptyArray(), "com.android.vending", null)
        assertEquals(1, report.findings.size)
        assertEquals(ScanEngine.Severity.INFO, report.findings.first().severity)
        assertFalse(report.isSuspicious)
    }

    @Test fun debuggableAppGetsMediumIndicatorNotAutomaticMalwareVerdict() {
        val report = ScanEngine.analyzeApp("Debug", "debug.app", ApplicationInfo.FLAG_DEBUGGABLE, emptyArray(), "com.android.vending", null)
        assertTrue(report.findings.any { it.title == "Debuggable build" })
        assertTrue(report.isSuspicious)
        assertFalse(report.findings.any { it.title.contains("malware", ignoreCase = true) })
    }

    @Test fun sensitivePermissionIsExplainedAsContextDependent() {
        val report = ScanEngine.analyzeApp("Mic app", "mic.app", 0, arrayOf("android.permission.RECORD_AUDIO"), "com.android.vending", null)
        assertTrue(report.findings.any { it.title.contains("Microphone access") })
        assertTrue(report.findings.any { it.detail.contains("may be justified") })
    }
}
