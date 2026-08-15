package com.ghost.verify

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ClusteringRulesTest {
    @Test
    fun catalogKeepsScopeAndRejectsUnavailablePlaceholders() {
        val signals = ClusteringSignalCatalog.build(listOf(
            field("boot_id", "identity-1"),
            field("GSF Android ID", "0"),
            field("camera.calibration_sha256", "<unavailable>"),
        )).associateBy { it.name }

        assertEquals("identity", signals.getValue("identity.boot_id").scope)
        assertEquals("identity-1", signals.getValue("identity.boot_id").value)
        assertTrue(signals.getValue("identity.boot_id").available)
        assertFalse(signals.getValue("identity.gsf_android_id").available)
        assertFalse(signals.getValue("physical.camera_calibration").available)
    }

    @Test
    fun detectsBoardPlatformShellBypassWithoutDuplicateFieldNames() {
        val violations = CrossFieldChecker.run(listOf(
            field("ro.board.platform", "mt6785"),
            field("ro.board.platform.shell_getprop", "gs101"),
            field("SOC_MODEL", "MT6785"),
        ))

        assertTrue(violations.any { it.ruleName == "BOARD_PLATFORM_NATIVE_VS_SHELL" })
        assertTrue(violations.any { it.ruleName == "SOC_PLATFORM_VENDOR_MISMATCH" })
    }

    @Test
    fun detectsVersionAgnosticFeatureHook() {
        val violations = CrossFieldChecker.run(listOf(
            field("features.version_contract_violation_count", "1"),
            field("features.version_contract_violations", "android.hardware.camera:listed_v1_but_query_false"),
            field("features.accepts_int_max_count", "2"),
            field("features.accepts_int_max_names", "android.hardware.camera,android.hardware.nfc"),
        ))

        assertTrue(violations.any { it.ruleName == "FEATURE_VERSION_CONTRACT_BROKEN" })
        assertTrue(violations.any { it.ruleName == "FEATURE_ACCEPTS_IMPOSSIBLE_VERSION" })
    }

    @Test
    fun detectsJavaOnlyUptimeRandomization() {
        val violations = CrossFieldChecker.run(listOf(
            field("uptime.java_elapsed_ms", "10000"),
            field("uptime.native_boottime_raw_ms", "500000"),
            field("uptime.native_boottime_libc_ms", "500100"),
            field("uptime.proc_uptime_ms", "500200"),
            field("uptime.boot_epoch_raw_s", "1800000000"),
            field("uptime.proc_stat_btime_s", "1800000001"),
        ))

        assertTrue(violations.any { it.ruleName == "UPTIME_JAVA_VS_RAW_BOOTTIME" })
        assertFalse(violations.any { it.ruleName == "UPTIME_LIBC_VS_RAW_BOOTTIME" })
        assertFalse(violations.any { it.ruleName == "BOOT_EPOCH_RAW_VS_PROC_BTIME" })
    }

    @Test
    fun detectsServiceAndMemoryCrossSourceContradictions() {
        val violations = CrossFieldChecker.run(listOf(
            field("feature.has.nfc", "true"),
            field("nfc.adapter_present", "false"),
            field("feature.has.sensor_barometer", "false"),
            field("sensor.actual.pressure", "true"),
            field("memory.proc_total_kb", "8388608"),
            field("memory.am_total_kb", "4194304"),
            field("memory.am_threshold_unique_count", "3"),
        ))

        assertTrue(violations.any { it.ruleName == "NFC_FEATURE_VS_ADAPTER" })
        assertTrue(violations.any { it.ruleName == "BAROMETER_FEATURE_VS_SENSOR" })
        assertTrue(violations.any { it.ruleName == "MEMTOTAL_PROC_VS_ACTIVITY_MANAGER" })
        assertTrue(violations.any { it.ruleName == "MEMORYINFO_THRESHOLD_UNSTABLE" })
    }

    @Test
    fun detectsPixelCpuPolicyOnNonGoogleTarget() {
        val violations = CrossFieldChecker.run(listOf(
            field("MANUFACTURER", "Xiaomi"),
            field("MODEL", "M2101K7BNY"),
            field("SOC_MANUFACTURER", "MTK"),
            field("cpu.policy_static_profile", "scaling_governor=sched_pixel|scaling_driver=exynos_cpufreq"),
        ))

        assertTrue(violations.any { it.ruleName == "CPU_POLICY_PIXEL_FAMILY_LEAK" })
    }

    private fun field(name: String, value: String): FieldResult = FieldResult.build(
        name = name,
        category = "test",
        sources = listOf(SourceValue("unit", "unit", value)),
    )
}
