package com.ghost.verify

/** 单个采集源的结果。 */
data class SourceValue(
    val source: String,        // eg "Build.MANUFACTURER" / "ro.product.manufacturer" / "getprop"
    val layer: String,         // "java" / "native" / "shell" / "proc"
    val value: String?,        // null 表示采集失败
    val error: String? = null
)

/** 单个字段的多源聚合 + 一致性判定。 */
data class FieldResult(
    val name: String,
    val category: String,
    val sources: List<SourceValue>,
    val consistent: Boolean,
    val canonicalValue: String? = null
) {
    companion object {
        fun build(name: String, category: String, sources: List<SourceValue>): FieldResult {
            val nonNullValues = sources.mapNotNull { it.value?.takeIf { v -> v.isNotEmpty() } }.toSet()
            val consistent = nonNullValues.size <= 1
            return FieldResult(
                name = name,
                category = category,
                sources = sources,
                consistent = consistent,
                canonicalValue = nonNullValues.firstOrNull()
            )
        }
    }
}

/** 跨字段一致性违规 — 多个 field 的 canonicalValue 之间应该满足某种关系但不满足。 */
data class CrossFieldViolation(
    val ruleName: String,        // 规则名(便于 grep)
    val severity: String,        // "high" / "medium" / "low"
    val fields: List<String>,    // 涉及的 field 名
    val values: Map<String, String?>, // 各 field 当前值
    val expected: String,        // 期望关系描述
    val note: String = ""
)

/** 整个采集 session 的根 report。 */
data class CollectReport(
    val timestamp: Long,
    val timestampHuman: String,
    val sessionId: String,
    val deviceLabel: String,
    val fieldCount: Int,
    val inconsistentCount: Int,
    val fields: List<FieldResult>,
    val crossFieldViolations: List<CrossFieldViolation> = emptyList()
)

/** 跨字段一致性规则引擎。 */
object CrossFieldChecker {
    /** 检查所有 cross-field 规则,返回 violation 列表 */
    fun run(fields: List<FieldResult>): List<CrossFieldViolation> {
        val map = fields.associateBy { it.name }
        val violations = mutableListOf<CrossFieldViolation>()

        // === DPI 同源校验:所有 dpi 类 field 理论值都 = ghost spoof dpi(±5 容差) ===
        val dpiFields = listOf(
            "dpi_app_resources_java",
            "dpi_native_prop",
            "dpi_density_device_stable",
            "window_metrics_density",
            "iwm_initial_display_density",
            "iwm_base_display_density",
            "wm_density_cmd",
            "settings_secure_display_density_forced",
        )
        violations += checkAllEqualWithin(map, dpiFields, "DPI_ALL_EQUAL", tolerance = 5,
            note = "所有 dpi 读路径应等于同一值(deviceInfo.dpi)")

        // === Resolution 同源校验 ===
        val resFields = listOf(
            "resolution",
            "wm_size_cmd",
            "iwm_initial_display_size",
            "iwm_base_display_size",
        )
        violations += checkAllEqualNormalized(map, resFields, "RESOLUTION_ALL_EQUAL",
            note = "所有 resolution 读路径应等于同一值(normalize 大小写/排序)")

        // === Build 类同源 ===
        violations += checkAllEqualWithin(map, listOf("MANUFACTURER", "BRAND"),
            "BUILD_BRAND_VS_MANUFACTURER", tolerance = 0,
            allowDifferentValues = true,
            note = "manufacturer 跟 brand 通常不同(子品牌)但都需有值")

        // === fingerprint 拆解一致 ===
        // Build.FINGERPRINT = "BRAND/PRODUCT/DEVICE:RELEASE/ID/INCREMENTAL:TYPE/TAGS"
        val fp = map["FINGERPRINT"]?.canonicalValue
        if (!fp.isNullOrBlank()) {
            val parts = fp.split('/', ':').filter { it.isNotBlank() }
            // 解析顺序:[0]=brand, [1]=product, [2]=device, [3]=release, [4]=id, [5]=incremental, [6]=type, [7]=tags
            val fpMap = mapOf(
                "BRAND" to parts.getOrNull(0),
                "PRODUCT" to parts.getOrNull(1),
                "DEVICE" to parts.getOrNull(2),
                "RELEASE" to parts.getOrNull(3),
                "ID" to parts.getOrNull(4),
            )
            for ((fieldName, fpVal) in fpMap) {
                val actual = map[fieldName]?.canonicalValue
                if (!fpVal.isNullOrBlank() && !actual.isNullOrBlank() && fpVal != actual) {
                    violations += CrossFieldViolation(
                        ruleName = "FINGERPRINT_VS_$fieldName",
                        severity = "high",
                        fields = listOf("FINGERPRINT", fieldName),
                        values = mapOf("FINGERPRINT.$fieldName" to fpVal, fieldName to actual),
                        expected = "Build.FINGERPRINT 拆解后 $fieldName 段应等于 Build.$fieldName",
                        note = "fingerprint=$fp"
                    )
                }
            }
        }

        // === SoC 同源 ===
        violations += checkAllEqualString(map, listOf("SOC_MODEL"), listOf("ro.soc.model"),
            "SOC_MODEL_JAVA_VS_NATIVE", note = "Build.SOC_MODEL vs ro.soc.model")
        violations += checkAllEqualString(map, listOf("SOC_MANUFACTURER"), listOf("ro.soc.manufacturer"),
            "SOC_MANU_JAVA_VS_NATIVE", note = "Build.SOC_MANUFACTURER vs ro.soc.manufacturer")
        violations += checkAllEqualString(map, listOf("HARDWARE"),
            listOf("ro.hardware", "ro.boot.hardware"),
            "HARDWARE_JAVA_VS_NATIVE", tolerance = 0,
            note = "Build.HARDWARE vs ro.hardware vs ro.boot.hardware")

        // === SDK ↔ Release 对应 ===
        // SDK 33→13, 34→14, 35→15, 36→16, 32→12, 31→12, 30→11, 29→10
        val sdkToRelease = mapOf(
            29 to "10", 30 to "11", 31 to "12", 32 to "12",
            33 to "13", 34 to "14", 35 to "15", 36 to "16", 37 to "17",
        )
        val sdkInt = map["SDK_INT"]?.canonicalValue?.toIntOrNull()
        val release = map["RELEASE"]?.canonicalValue
        if (sdkInt != null && release != null) {
            val expectedRelease = sdkToRelease[sdkInt]
            if (expectedRelease != null && !release.startsWith(expectedRelease)) {
                violations += CrossFieldViolation(
                    ruleName = "SDK_VS_RELEASE_MISMATCH",
                    severity = "high",
                    fields = listOf("SDK_INT", "RELEASE"),
                    values = mapOf("SDK_INT" to sdkInt.toString(), "RELEASE" to release),
                    expected = "SDK=$sdkInt 对应 Android $expectedRelease",
                    note = "Android 版本映射不一致"
                )
            }
        }

        // === Locale / Timezone 同源 ===
        violations += checkAllEqualString(map, listOf("Locale.getDefault"),
            listOf("persist.sys.locale_native", "persist.sys.locale_shell"),
            "LOCALE_JAVA_VS_NATIVE", tolerance = 0,
            note = "Java Locale.toString() 跟 persist.sys.locale 应同源(可能格式差 en_HK vs en-HK)",
            normalizeLocale = true)
        violations += checkAllEqualString(map, listOf("TimeZone.getDefault"),
            listOf("persist.sys.timezone_native", "persist.sys.timezone_shell"),
            "TIMEZONE_JAVA_VS_NATIVE", tolerance = 0,
            note = "Java TimeZone.getID 跟 persist.sys.timezone 应同源")

        // === SIM Country ISO 同源 ===
        violations += checkAllEqualString(map,
            listOf("TelephonyManager.getSimCountryIso", "TelephonyManager.getNetworkCountryIso"),
            listOf("gsm.operator.iso-country", "gsm.sim.operator.iso-country"),
            "SIM_COUNTRY_ISO_CROSS", tolerance = 0,
            note = "Telephony Java API 跟 native gsm.*.iso-country 应同源(2 letter ISO)",
            caseInsensitive = true)

        // === 物理对角线合理性 ===
        val resV = map["resolution"]?.canonicalValue
        val dpiV = map["dpi_app_resources_java"]?.canonicalValue?.toIntOrNull()
        if (resV != null && dpiV != null && dpiV > 0) {
            val nums = Regex("\\d+").findAll(resV).map { it.value.toInt() }.toList()
            if (nums.size >= 2) {
                val w = nums.max().toDouble(); val h = nums.min().toDouble()
                val diag = Math.sqrt(w*w + h*h) / dpiV
                if (diag !in 4.0..8.5) {
                    violations += CrossFieldViolation(
                        ruleName = "PHYSICAL_DIAGONAL_OUT_OF_RANGE",
                        severity = "high",
                        fields = listOf("resolution", "dpi_app_resources_java"),
                        values = mapOf("resolution" to resV, "dpi" to dpiV.toString(),
                                       "diagonal" to "%.2f\"".format(diag)),
                        expected = "对角线 ∈ [4.0\", 8.5\"](手机范围)",
                        note = "可能 res 或 dpi 错配"
                    )
                }
            }
        }

        return violations
    }

    private fun checkAllEqualString(
        map: Map<String, FieldResult>,
        groupA: List<String>, groupB: List<String>,
        ruleName: String,
        tolerance: Int = 0,
        caseInsensitive: Boolean = false,
        normalizeLocale: Boolean = false,
        note: String = ""
    ): List<CrossFieldViolation> {
        fun norm(v: String?): String? {
            if (v.isNullOrBlank()) return null
            var s: String = v
            if (caseInsensitive) s = s.lowercase()
            if (normalizeLocale) s = s.replace('_', '-')  // en_HK → en-HK
            return s.trim()
        }
        val all = (groupA + groupB)
        val vals = all.mapNotNull { name -> map[name]?.canonicalValue?.let { name to norm(it) } }
            .filter { it.second != null }
        if (vals.size < 2) return emptyList()
        val distinct = vals.map { it.second }.toSet()
        if (distinct.size <= 1) return emptyList()
        return listOf(CrossFieldViolation(
            ruleName = ruleName,
            severity = "medium",
            fields = all,
            values = all.associateWith { map[it]?.canonicalValue },
            expected = "应等价(发现 $distinct)",
            note = note
        ))
    }

    private fun checkAllEqualWithin(
        map: Map<String, FieldResult>,
        fieldNames: List<String>,
        ruleName: String,
        tolerance: Int = 0,
        allowDifferentValues: Boolean = false,
        note: String = ""
    ): List<CrossFieldViolation> {
        val values = fieldNames.mapNotNull { name ->
            map[name]?.canonicalValue?.let { name to it }
        }
        if (values.size < 2 || allowDifferentValues) return emptyList()
        val ints = values.mapNotNull { (n, v) -> v.toIntOrNull()?.let { n to it } }
        if (ints.size < 2) return emptyList()
        val minV = ints.minOf { it.second }
        val maxV = ints.maxOf { it.second }
        if (maxV - minV <= tolerance) return emptyList()
        return listOf(CrossFieldViolation(
            ruleName = ruleName,
            severity = if (maxV - minV > 50) "high" else "medium",
            fields = fieldNames,
            values = fieldNames.associateWith { map[it]?.canonicalValue },
            expected = "所有值应在 ±${tolerance} 内(发现差异 ${maxV - minV})",
            note = note
        ))
    }

    private fun checkAllEqualNormalized(
        map: Map<String, FieldResult>,
        fieldNames: List<String>,
        ruleName: String,
        note: String = ""
    ): List<CrossFieldViolation> {
        // resolution 字段统一 normalize 为 "long×short" 形式
        fun normalize(v: String?): String? {
            if (v.isNullOrBlank()) return null
            val nums = Regex("\\d+").findAll(v).map { it.value.toInt() }.toList()
            if (nums.size < 2) return v
            val long = nums.max()
            val short = nums.min()
            return "${long}x${short}"
        }
        val values = fieldNames.mapNotNull { name ->
            map[name]?.canonicalValue?.let { name to normalize(it) }
        }.filter { it.second != null }
        if (values.size < 2) return emptyList()
        val distinct = values.map { it.second }.toSet()
        if (distinct.size <= 1) return emptyList()
        return listOf(CrossFieldViolation(
            ruleName = ruleName,
            severity = "high",
            fields = fieldNames,
            values = fieldNames.associateWith { map[it]?.canonicalValue },
            expected = "所有 resolution 字段 normalize 后应一致(发现 $distinct)",
            note = note
        ))
    }
}
