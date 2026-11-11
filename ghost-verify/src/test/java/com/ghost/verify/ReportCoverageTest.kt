package com.ghost.verify

import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test

class ReportCoverageTest {
    private fun field(vararg values: String?) = FieldResult.build("test", "test",
        values.mapIndexed { i, value -> SourceValue("source$i", "unit", value) })

    @Test fun missingAndSingleSourcesAreNotPresentedAsVerified() {
        val missing = field(null, "")
        val single = field("one", null)
        val partial = field("one", "one", null)
        val conflict = field("one", "two")
        assertEquals(ComparisonStatus.UNAVAILABLE, missing.comparisonStatus)
        assertEquals(ComparisonStatus.SINGLE_SOURCE, single.comparisonStatus)
        assertEquals(ComparisonStatus.CONSISTENT, partial.comparisonStatus)
        assertEquals(2, partial.validSourceCount)
        assertEquals(ComparisonStatus.INCONSISTENT, conflict.comparisonStatus)
        val report = CollectReport(0, "time", "session", "device", 4, 1,
            listOf(missing, single, partial, conflict))
        assertEquals(FieldCoverage(1, 1, 1, 1), report.coverage)
        val json = Gson().toJsonTree(report).asJsonObject
        assertEquals(1, json["coverage"].asJsonObject["unavailable"].asInt)
        assertEquals("SINGLE_SOURCE", json["fields"].asJsonArray[1].asJsonObject["comparisonStatus"].asString)
    }

    @Test fun observationContextSurvivesSerializationWithoutChangingLegacyReports() {
        val context = ObservationContext("com.example.collector", "com.example.collector:worker", 10001, 123)
        val report = CollectReport(0, "time", "session", "device", 1, 0, listOf(field("one")),
            observationContext = context)
        val gson = Gson()
        val json = gson.toJsonTree(report).asJsonObject
        assertEquals(report, gson.fromJson(json, CollectReport::class.java))
        assertEquals("com.example.collector:worker", json["observationContext"].asJsonObject["processName"].asString)
        json.remove("observationContext")
        assertNull(gson.fromJson(json, CollectReport::class.java).observationContext)
    }

    @Test fun syntheticSelfTestChecksCoverageAndSourceContract() {
        val result = ReportSelfTest.run(ObservationContext("com.example.collector", "worker", 10001, 123))
        assertEquals("synthetic", result.dataKind)
        assertEquals(7, result.checks.size)
        assertTrue(result.checks.toString(), result.passed)
    }

    @Test fun logicalDensityDoesNotProduceAPhysicalPhoneDiagonalVerdict() {
        val fields = listOf(
            FieldResult.build("resolution", "display", listOf(SourceValue("java", "java", "2800x2000"))),
            FieldResult.build("dpi_app_resources_java", "display", listOf(SourceValue("java", "java", "400"))),
        )
        assertFalse(CrossFieldChecker.run(fields).any { it.ruleName == "PHYSICAL_DIAGONAL_OUT_OF_RANGE" })
    }
}
