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

/** 整个采集 session 的根 report。 */
data class CollectReport(
    val timestamp: Long,
    val timestampHuman: String,
    val sessionId: String,
    val deviceLabel: String,
    val fieldCount: Int,
    val inconsistentCount: Int,
    val fields: List<FieldResult>
)
