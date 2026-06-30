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
            allowDifferentValues = true,  // 子品牌允许不同
            note = "manufacturer 跟 brand 通常不同(子品牌)但都需有值")

        return violations
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
