package com.ghost.verify

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GmsBaselineRulesTest {
    private fun field(name: String, value: String): FieldResult = FieldResult.build(
        name = name,
        category = "test",
        sources = listOf(SourceValue("unit", "unit", value)),
    )

    /**
     * 通过的最小 GMS 基准:主进程与 app 同一虚拟身份(档案只装在 .unstable,以 probe 体现),
     * 运行时字段一致。
     */
    private fun healthyFields(): List<FieldResult> = listOf(
        field("MANUFACTURER", "Xiaomi"),
        field("BRAND", "Xiaomi"),
        field("MODEL", "2211133C"),
        field("DEVICE", "marble"),
        field("PRODUCT", "marble_global"),
        field("HARDWARE", "qcom"),
        field("BOARD", "marble"),
        field("FINGERPRINT", "Xiaomi/marble_global/marble:13/TKQ1.221114.001/V14.0.4.0.TMRMIXM:user/release-keys"),
        field("ID", "TKQ1.221114.001"),
        field("INCREMENTAL", "V14.0.4.0.TMRMIXM"),
        field("SOC_MODEL", "SM8450"),
        field("SOC_MANUFACTURER", "QTI"),
        field("SKU", "marble"),
        field("BOOTLOADER", "marble-1.0-1"),
        field("HOST", "abfarm-release-x"),
        field("SECURITY_PATCH", "2023-05-05"),
        field("ro.build.description", "marble_global-user 13 TKQ1.221114.001 V14.0.4.0.TMRMIXM release-keys"),
        field("GL_RENDERER", "Adreno (TM) 730"),
        field("GL_VENDOR", "Qualcomm"),
        field("cpu_count.available_processors", "8"),
        field("SDK_INT", "33"),
        field("RELEASE", "13"),
        field("ADB_ENABLED", "0"),
        field("DEVELOPMENT_SETTINGS_ENABLED", "0"),
        field("USB.device_count", "0"),
        field("USB.current_functions", "0"),
        field("USB.native_sys_usb_config", "none"),
        field("USB.native_init_svc_adbd", "stopped"),
        field("battery.is_charging", "false"),
        field("battery.status", "3"),
        field("battery.plugged", "0"),
        field("gms.process_pkg", "com.google.android.gms"),
        field("gms.process_name", "com.google.android.gms"),
        field("gms.profile_probe.present", "true"),
        field("gms.profile_probe.process_name", "com.google.android.gms.unstable"),
        field("gms.profile_probe.applied", "true"),
        field("gms.profile_probe.SOC_MODEL", "Tensor G2"),
        // 主进程与 app 相同(虚拟设备),不是 Pixel。
        field("gms.MANUFACTURER", "Xiaomi"),
        field("gms.BRAND", "Xiaomi"),
        field("gms.MODEL", "2211133C"),
        field("gms.DEVICE", "marble"),
        field("gms.PRODUCT", "marble_global"),
        field("gms.HARDWARE", "qcom"),
        field("gms.BOARD", "marble"),
        field("gms.FINGERPRINT",
            "Xiaomi/marble_global/marble:13/TKQ1.221114.001/V14.0.4.0.TMRMIXM:user/release-keys"),
        field("gms.ID", "TKQ1.221114.001"),
        field("gms.INCREMENTAL", "V14.0.4.0.TMRMIXM"),
        field("gms.SECURITY_PATCH", "2023-05-05"),
        field("gms.RELEASE", "13"),
        field("gms.SDK_INT", "33"),
        field("gms.SOC_MODEL", "SM8450"),
        field("gms.SOC_MANUFACTURER", "QTI"),
        field("gms.SKU", "marble"),
        field("gms.BOOTLOADER", "marble-1.0-1"),
        field("gms.HOST", "abfarm-release-x"),
        field("gms.BUILD_DESCRIPTION", "marble_global-user 13 TKQ1.221114.001 V14.0.4.0.TMRMIXM release-keys"),
        field("gms.gl.renderer", "Adreno (TM) 730"),
        field("gms.gl.vendor", "Qualcomm"),
        field("gms.cpu_count", "8"),
        field("gms.runtime.sys_usb_config", "none"),
        field("gms.runtime.init_svc_adbd", "stopped"),
        field("gms.runtime.adb_enabled", "0"),
        field("gms.runtime.development_settings_enabled", "0"),
        field("gms.runtime.usb_device_count", "0"),
        field("gms.runtime.usb_current_functions", "0"),
        field("gms.battery.is_charging", "false"),
        field("gms.battery.status", "3"),
        field("gms.battery.plugged", "0"),
        // Ghost 给 GMS 主进程的 L1 共享补丁;与虚拟设备同值时既不报 MISMATCH 也不出 ONE_SIDED。
        field("gms.expected.security_patch", "2023-05-05"),
    )

    @Test
    fun healthyBaselineHasNoGmsViolation() {
        val violations = CrossFieldChecker.run(healthyFields())
        assertFalse(violations.filter { it.ruleName.startsWith("GMS_") }.toString(), violations.any { it.ruleName.startsWith("GMS_") })
    }

    @Test
    fun detectsCrossProcessRuntimeMismatch() {
        val fields = healthyFields().map {
            if (it.name == "battery.is_charging") field(it.name, "true") else it
        }
        val violations = CrossFieldChecker.run(fields)
        assertTrue(violations.any {
            it.ruleName == "GMS_RUNTIME_VIEW_MISMATCH" && it.fields.contains("battery.is_charging")
        })
    }

    @Test
    fun detectsProfileLeakingIntoGmsMain() {
        // 档案串进主进程:主进程变成 Pixel,虚拟身份是 Xiaomi。
        val fields = healthyFields().map {
            when (it.name) {
                "gms.MANUFACTURER" -> field(it.name, "Google")
                "gms.MODEL" -> field(it.name, "Pixel 7")
                else -> it
            }
        }
        val violations = CrossFieldChecker.run(fields)
        assertTrue(violations.any {
            it.ruleName == "GMS_IDENTITY_VS_APP" && it.fields.contains("MANUFACTURER")
        })
    }

    @Test
    fun detectsCloneCollectedFromUnstable() {
        val fields = healthyFields().map {
            if (it.name == "gms.process_name") field(it.name, "com.google.android.gms.unstable") else it
        }
        assertTrue(CrossFieldChecker.run(fields).any { it.ruleName == "GMS_CLONE_PROCESS_NAME" })
    }

    @Test
    fun detectsMissingOrMislocatedProfileProbe() {
        val missing = healthyFields().filterNot { it.name == "gms.profile_probe.process_name" }
        assertTrue(CrossFieldChecker.run(missing).any { it.ruleName == "GMS_PROFILE_PROBE_MISSING" })

        val wrongProcess = healthyFields().map {
            if (it.name == "gms.profile_probe.process_name") field(it.name, "com.google.android.gms") else it
        }
        assertTrue(CrossFieldChecker.run(wrongProcess).any {
            it.ruleName == "GMS_PROFILE_PROBE_WRONG_PROCESS"
        })
    }

    @Test
    fun detectsFingerprintBuildDivergence() {
        val fields = healthyFields().map {
            if (it.name == "gms.DEVICE") field(it.name, "cheetah") else it
        }
        val violations = CrossFieldChecker.run(fields)
        assertTrue(violations.any { it.ruleName == "GMS_FINGERPRINT_VS_DEVICE" })
    }

    @Test
    fun detectsGmsUsbStillConnected() {
        val fields = healthyFields().map {
            when (it.name) {
                "gms.runtime.sys_usb_config" -> field(it.name, "mtp,adb")
                "gms.runtime.init_svc_adbd" -> field(it.name, "running")
                else -> it
            }
        }
        assertTrue(CrossFieldChecker.run(fields).any {
            it.ruleName == "GMS_USB_NOT_STOPPED" || it.ruleName == "GMS_RUNTIME_VIEW_MISMATCH"
        })
    }

    @Test
    fun detectsProfileReleaseNotFollowingRuntime() {
        val fields = healthyFields().map {
            if (it.name == "gms.RELEASE") field(it.name, "CANARY") else it
        }
        assertTrue(CrossFieldChecker.run(fields).any { it.ruleName == "GMS_RELEASE_VS_RUNTIME_SDK" })
    }

    // ---------------- 可采性统一语义 / 扩大基准 / 期望值 ----------------

    private fun errorField(name: String, error: String): FieldResult = FieldResult.build(
        name = name,
        category = "test",
        sources = listOf(SourceValue("unit", "unit", null, error)),
    )

    private fun gmsViolations(fields: List<FieldResult>) =
        CrossFieldChecker.run(fields).filter { it.ruleName.startsWith("GMS_") }

    @Test
    fun normalizeObservedClassifiesPlaceholders() {
        assertEquals(null to "placeholder", normalizeObserved("unknown", null))
        assertEquals(null to "placeholder", normalizeObserved("UNKNOWN", null))
        assertEquals(null to "permission", normalizeObserved("<denied: SecurityException>", null))
        assertEquals(null to "permission", normalizeObserved(null, "SecurityException: getSerial"))
        assertEquals(null to "permission", normalizeObserved(null, "java.lang.SecurityException: no READ_PHONE"))
        assertEquals(null to "empty", normalizeObserved("  ", null))
        assertEquals(null to "empty", normalizeObserved(null, null))
        assertEquals(null to "placeholder", normalizeObserved("-1", null, identity = true))
        assertEquals("-1" to null, normalizeObserved("-1", null))
        assertEquals("abc" to null, normalizeObserved(" abc ", null))
    }

    @Test
    fun permissionFieldNotCollectableOnOneSideHasNoViolation() {
        val fields = healthyFields() + listOf(
            errorField("Build.getSerial() (info-only)", "SecurityException: getSerial requires READ_PRIVILEGED_PHONE_STATE"),
            field("gms.telephony.serialno", "present"),
        )
        val result = CrossFieldChecker.evaluate(fields)
        assertTrue(result.violations.filter { it.ruleName.startsWith("GMS_") }.toString(),
            result.violations.none { it.ruleName.startsWith("GMS_") })
        val pair = result.pairs.single { it.field == "telephony.serialno" }
        assertEquals(PairStatus.NOT_COLLECTABLE, pair.status)
        assertEquals("permission", pair.reason)
        // 值本身不进报告:只有 present / null。
        assertNull(pair.left)
    }

    @Test
    fun permissionGatedCountedInCoverage() {
        val fields = listOf(
            errorField("Build.getSerial() (info-only)", "SecurityException: x"),
            field("line1Number", "unknown"),
            field("MODEL", "2211133C"),
        )
        val report = CollectReport(
            timestamp = 0, timestampHuman = "t", sessionId = "s", deviceLabel = "d",
            fieldCount = fields.size, inconsistentCount = 0, fields = fields,
        )
        assertEquals(2, report.coverage.permissionGated)
        assertEquals(0, report.coverage.unavailable)
        assertEquals(1, report.coverage.singleSource)
    }

    @Test
    fun nonPermissionFieldEmptyOnOneSideIsLowOneSided() {
        val fields = healthyFields().map { if (it.name == "gms.HOST") field("gms.HOST", "") else it }
        val violations = gmsViolations(fields)
        val oneSided = violations.filter { it.ruleName == "GMS_ONE_SIDED_VALUE" }
        assertEquals(violations.toString(), 1, oneSided.size)
        assertEquals("low", oneSided.single().severity)
        assertTrue(oneSided.single().fields.contains("HOST"))
        assertTrue(violations.none { it.ruleName == "GMS_IDENTITY_VS_APP" })
    }

    @Test
    fun unstableNotRunningIsNotRunWithoutHigh() {
        val fields = healthyFields().filterNot {
            it.name == "gms.profile_probe.process_name" || it.name == "gms.profile_probe.present" ||
                it.name == "gms.profile_probe.applied" || it.name == "gms.profile_probe.SOC_MODEL"
        } + field("gms.profile_probe.state", "unstable_not_running")
        val result = CrossFieldChecker.evaluate(fields)
        val gms = result.violations.filter { it.ruleName.startsWith("GMS_") }
        assertTrue(gms.toString(), gms.none { it.severity == "high" })
        assertTrue(gms.none { it.ruleName == "GMS_PROFILE_PROBE_MISSING" })
        assertEquals("info", gms.single { it.ruleName == "GMS_PROFILE_PROBE_NOT_RUN" }.severity)
        assertEquals(PairStatus.NOT_RUN, result.pairs.single { it.field == "gms.profile_probe" }.status)
    }

    @Test
    fun probeStateMissingOrAbsentKeepsHigh() {
        val missing = healthyFields().filterNot { it.name == "gms.profile_probe.process_name" }
        assertTrue(gmsViolations(missing).any { it.ruleName == "GMS_PROFILE_PROBE_MISSING" && it.severity == "high" })

        val absent = missing + field("gms.profile_probe.state", "absent")
        assertTrue(gmsViolations(absent).any { it.ruleName == "GMS_PROFILE_PROBE_MISSING" && it.severity == "high" })
    }

    @Test
    fun displaySizeSwapIsMatch() {
        // resolution 是 getRealMetrics 的 "HxW";GMS 给 real 宽高。横竖屏互换算同一块屏。
        val base = healthyFields() + field("resolution", "2400x1080")
        val portrait = base + listOf(field("gms.display.real_width", "1080"), field("gms.display.real_height", "2400"))
        val landscape = base + listOf(field("gms.display.real_width", "2400"), field("gms.display.real_height", "1080"))
        for (fields in listOf(portrait, landscape)) {
            val result = CrossFieldChecker.evaluate(fields)
            assertEquals(PairStatus.MATCH, result.pairs.single { it.field == "display.real_size" }.status)
            assertTrue(result.violations.none { it.ruleName.startsWith("GMS_") })
        }
        val other = base + listOf(field("gms.display.real_width", "1080"), field("gms.display.real_height", "2340"))
        assertTrue(gmsViolations(other).any {
            it.ruleName == "GMS_IDENTITY_VS_APP" && it.fields.contains("resolution")
        })
    }

    @Test
    fun securityPatchFollowsTheL1ExpectedNotTheVirtualDevice() {
        // L1:全部 Google UID 取档案补丁,可以 ≠ 虚拟设备;差异本身不是串档。
        // app 仍是虚拟设备值 2023-05-05,GMS 与 L1 期望是档案值 2023-06-01。
        val profilePatch = healthyFields().map {
            when (it.name) {
                "gms.SECURITY_PATCH", "gms.expected.security_patch" -> field(it.name, "2023-06-01")
                else -> it
            }
        }
        val ok = CrossFieldChecker.evaluate(profilePatch)
        assertEquals(PairStatus.MATCH, ok.pairs.single { it.field == "gms.security_patch" }.status)
        // 与虚拟设备的差异本身不再报 SECURITY_PATCH 身份对。
        assertTrue(ok.violations.none { it.fields.contains("SECURITY_PATCH") })
        // GMS 实际补丁 ≠ 档案 L1 期望 → high,且不再拿虚拟设备值当基准。
        val wrong = healthyFields().map { if (it.name == "gms.SECURITY_PATCH") field(it.name, "2023-01-01") else it }
        assertTrue(gmsViolations(wrong).any {
            it.ruleName == "GMS_SECURITY_PATCH_VS_EXPECTED" && it.severity == "high"
        })
    }

    @Test
    fun newBaselinePairsAreCompared() {
        val fields = healthyFields() + listOf(
            field("timezone", "Asia/Tokyo"), field("gms.timezone", "America/New_York"),
            field("locale", "ja-JP"), field("gms.locale.country", "JP"),
            field("uname.release", "5.10.198-android12"), field("gms.uname.release", "5.10.198-android12"),
        )
        val result = CrossFieldChecker.evaluate(fields)
        assertEquals(PairStatus.MISMATCH, result.pairs.single { it.field == "timezone" }.status)
        assertEquals(PairStatus.MATCH, result.pairs.single { it.field == "locale.country" }.status)
        assertEquals(PairStatus.MATCH, result.pairs.single { it.field == "uname.release" }.status)
        assertTrue(result.violations.any { it.ruleName == "GMS_IDENTITY_VS_APP" && it.fields.contains("timezone") })
    }

    @Test
    fun appVsExpectedDetectsMismatchAndSkipsMissingKeys() {
        val mb = 1024L * 1024L
        val fields = healthyFields() + listOf(
            field("resolution", "2400x1080"),
            field("runtime.total_mem_mb", "7680"),
        )
        val expected = mapOf(
            "build.model" to "2211133C",
            "build.brand" to "Redmi",
            "display.realWidthPixels" to "1080",
            "display.realHeightPixels" to "2400",
            "mem.totalMem" to (7680 * mb + 12345).toString(),
        )
        val result = ExpectedEnvChecker.compare(fields, expected)
        val byField = result.pairs.associateBy { it.field }
        assertEquals(PairStatus.MATCH, byField.getValue("build.model").status)
        assertEquals(PairStatus.MISMATCH, byField.getValue("build.brand").status)
        assertEquals(PairStatus.MATCH, byField.getValue("display.real_size").status)
        assertEquals(PairStatus.MATCH, byField.getValue("mem.totalMem").status)
        // 期望缺键 = 不比较
        assertFalse(byField.containsKey("build.sku"))
        assertEquals("expected.build.brand", byField.getValue("build.brand").rightField)
        assertEquals("BRAND", byField.getValue("build.brand").leftField)
        val v = result.violations.single()
        assertEquals("APP_VS_EXPECTED", v.ruleName)
        assertEquals("high", v.severity)
    }
}
