package com.ghost.verify

import com.google.gson.Gson

/** 只使用合成字段检查报告契约，不调用设备采集器或写入备份对比基线。 */
object ReportSelfTest {
    data class Result(
        val observationContext: ObservationContext,
        val passed: Boolean,
        val checks: Map<String, Boolean>,
        val dataKind: String = "synthetic",
    )

    fun run(context: ObservationContext): Result {
        fun field(name: String, vararg values: String?) = FieldResult.build(name, "synthetic",
            values.mapIndexed { i, value -> SourceValue("fixture$i", "synthetic", value) })
        val fields = listOf(
            field("missing", null, ""),
            field("single", "one", null),
            field("matching", "one", "one", null),
            field("conflict", "one", "two"),
        )
        val report = CollectReport(0, "synthetic", "selftest", "synthetic", 4, 1, fields,
            observationContext = context)
        val gson = Gson()
        val tree = gson.toJsonTree(report).asJsonObject
        val roundTrip = gson.fromJson(tree, CollectReport::class.java)
        val withoutContext = tree.deepCopy().apply { remove("observationContext") }
        val checks = linkedMapOf(
            "missing_is_unavailable" to (fields[0].comparisonStatus == ComparisonStatus.UNAVAILABLE),
            "single_is_not_verified" to (fields[1].comparisonStatus == ComparisonStatus.SINGLE_SOURCE),
            "partial_matching_counts_valid_sources" to
                (fields[2].comparisonStatus == ComparisonStatus.CONSISTENT && fields[2].validSourceCount == 2),
            "conflicting_sources_are_rejected" to (fields[3].comparisonStatus == ComparisonStatus.INCONSISTENT),
            "coverage_counts_each_status" to (report.coverage == FieldCoverage(1, 1, 1, 1)),
            "json_preserves_context_and_fields" to (roundTrip == report),
            "legacy_context_stays_unknown" to
                (gson.fromJson(withoutContext, CollectReport::class.java).observationContext == null),
        )
        return Result(context, checks.values.all { it }, checks)
    }
}
