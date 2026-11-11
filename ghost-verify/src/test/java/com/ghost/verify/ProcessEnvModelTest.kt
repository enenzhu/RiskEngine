package com.ghost.verify

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessEnvModelTest {
    private fun obj(json: String): JsonObject = JsonParser.parseString(json).asJsonObject

    private fun env(model: String, extra: String = ""): JsonObject = obj(
        """{"envSchemaVersion":1,"collectedAt":123,"processPkg":"p","processName":"p","pid":1,"uid":2,
            "build":{"model":"$model","sdkInt":33},
            "display":{"widthPixels":1080,"heightPixels":2340,"realWidthPixels":1080,"realHeightPixels":2400,"densityDpi":440},
            "mem":{"totalMem":8000000000,"runtimeFree":12345},
            "features":{"count":10,"sha256":"aaa"}
            $extra}"""
    )

    private fun expected(layer: String, vararg kv: Pair<String, String>) =
        ExpectedEnv("dev1", null, null, layer, false, linkedMapOf(*kv))

    private fun column(id: String, process: String, envJson: JsonObject?, exp: ExpectedEnv?) =
        EnvColumn(id, id.substringBefore(':'), process, envJson?.let { ProcessEnvModel.flatten(it) }, exp)

    // ---------------- 响应解析 ----------------

    @Test
    fun parsesRawAndQuotedJsonAndUnsupported() {
        val ok = GhostCallParser.parse("""{"ok":true,"active":false}""")
        assertTrue(ok is GhostCallResult.Ok)
        // 兼容 gson 再包一层引号
        val quoted = GhostCallParser.parse("\"{\\\"ok\\\":true,\\\"count\\\":3}\"")
        assertEquals("3", (quoted as GhostCallResult.Ok).body.str("count"))

        assertTrue(GhostCallParser.parse("Method not found: expectedEnv") is GhostCallResult.Unsupported)
        assertTrue(GhostCallParser.parse("\"Method not found: observe\"") is GhostCallResult.Unsupported)

        val failed = GhostCallParser.parse("""{"ok":false,"error":"System not ready"}""")
        assertEquals("System not ready", (failed as GhostCallResult.Failed).error)
        assertTrue(GhostCallParser.parse("Unauthorized") is GhostCallResult.Failed)
        assertTrue(GhostCallParser.parse("") is GhostCallResult.Failed)
        assertTrue(GhostCallParser.parse(null) is GhostCallResult.Failed)

        assertEquals(listOf("a", "b"), GhostCallParser.parseStringList("""["a","b",""]"""))
        assertEquals(listOf("a"), GhostCallParser.parseStringList("\"[\\\"a\\\"]\""))
        assertNull(GhostCallParser.parseStringList("Method not found: getHookPkgs"))
    }

    @Test
    fun parsesExpectedEnv() {
        val body = obj("""{"ok":true,"schema":1,"deviceId":"d1","pkg":"com.ghost.verify","process":"com.ghost.verify",
            "layer":"L3","sharedProof":true,"expected":{"build.model":"M1","display.densityDpi":"440"}}""")
        val e = ProcessEnvModel.parseExpected(body)
        assertEquals("L3", e.layer)
        assertEquals(true, e.sharedProof)
        assertEquals("M1", e.expected["build.model"])
        assertEquals(2, e.expected.size)
    }

    @Test
    fun parsesPagedResultsAndKeepsLatest() {
        val (page, next) = ProcessEnvModel.parseResults(obj(
            """{"ok":true,"active":true,"next":2,"results":[
                {"pkg":"com.google.android.gms","process":"com.google.android.gms","at":10,"env":{"build":{"model":"A"}}},
                {"pkg":"com.google.android.gms","process":"com.google.android.gms","at":20,"env":{"build":{"model":"B"}}}]}"""))
        assertEquals(2, next)
        val latest = ProcessEnvModel.latestPerProcess(page)
        assertEquals(1, latest.size)
        assertEquals(20L, latest.single().at)
        assertEquals(-1, ProcessEnvModel.parseResults(obj("""{"ok":true,"results":[]}""")).second)
    }

    // ---------------- 展平 ----------------

    @Test
    fun flattenUsesExpectedKeyNamesAndDropsMetaAndVolatile() {
        val flat = ProcessEnvModel.flatten(env("M1", ""","telephony":{
            "imei":{"value":"861234567890123"},
            "meid":{"value":null,"reason":"permission"}}"""))
        assertEquals("M1", flat["build.model"]?.value)
        assertEquals("33", flat["build.sdkInt"]?.value)
        assertEquals("8000000000", flat["mem.totalMem"]?.value)
        assertEquals("1080x2340", flat["display.size"]?.value)
        assertEquals("1080x2400", flat["display.realSize"]?.value)
        assertFalse(flat.containsKey("display.realWidthPixels"))
        assertFalse(flat.containsKey("collectedAt"))
        assertFalse(flat.containsKey("mem.runtimeFree"))
        // 权限门控:只留有值/无值,原值不出现
        assertEquals("present", flat["telephony.imei"]?.value)
        assertTrue(flat.values.none { it.value?.contains("861234567890123") == true })
        assertNull(flat["telephony.meid"]?.value)
        assertEquals("permission", flat["telephony.meid"]?.reason)
    }

    @Test
    fun redactEnvHidesTelephonyValues() {
        val raw = env("M1", ""","telephony":{"imei":{"value":"861234567890123"}}""")
        val red = ProcessEnvModel.redactEnv(raw)
        assertFalse(red.toString().contains("861234567890123"))
        assertTrue(raw.toString().contains("861234567890123")) // 原对象不被修改
    }

    // ---------------- 比较 ----------------

    @Test
    fun comparesEachProcessAgainstItsOwnExpected() {
        val exp = expected("L3", "build.model" to "M1")
        val cols = listOf(
            column(ProcessEnvModel.SELF_ID, "com.ghost.verify", env("M1"), exp),
            column("com.google.android.gms:com.google.android.gms", "com.google.android.gms", env("M1"), exp),
            column("com.android.vending:com.android.vending", "com.android.vending", env("Pixel 8"), exp),
        )
        val cmp = ProcessEnvModel.compare(cols)
        val row = cmp.rows.single { it.key == "build.model" }
        assertEquals("M1", row.selfExpected)
        assertEquals(PairStatus.MATCH, row.cells.getValue(ProcessEnvModel.SELF_ID).status)
        assertEquals(PairStatus.MATCH, row.cells.getValue("com.google.android.gms:com.google.android.gms").status)
        assertEquals(PairStatus.MISMATCH, row.cells.getValue("com.android.vending:com.android.vending").status)
        assertEquals("✗", ProcessEnvModel.symbol(row.cells.getValue("com.android.vending:com.android.vending")))
        // 只有部分进程 ≠ 期望 → 该进程 hook 漏装或串档
        assertTrue(row.hint!!.contains(ProcessEnvModel.HINT_PROCESS))
        assertTrue(row.hint!!.contains("com.android.vending"))
        assertTrue(cmp.mismatches >= 1)
    }

    @Test
    fun allProcessesAgreeButDifferFromExpectedPointsAtProjection() {
        val exp = expected("L3", "build.model" to "M1")
        val cols = listOf(
            column(ProcessEnvModel.SELF_ID, "com.ghost.verify", env("M2"), exp),
            column("com.google.android.gms:com.google.android.gms", "com.google.android.gms", env("M2"), exp),
        )
        val row = ProcessEnvModel.compare(cols).rows.single { it.key == "build.model" }
        assertTrue(row.hint!!.contains(ProcessEnvModel.HINT_EXPECTED))
    }

    @Test
    fun targetWithoutResultIsNotRun() {
        val cols = listOf(column(ProcessEnvModel.SELF_ID, "com.ghost.verify", env("M1"), null)) +
            ProcessEnvModel.targetColumns(listOf("com.android.vending"), emptyList()) { _, _ -> null to "x" }
        val cmp = ProcessEnvModel.compare(cols)
        assertEquals(listOf("com.android.vending:–"), cmp.notRun)
        assertTrue(cmp.rows.all { it.cells.getValue("com.android.vending:–").status == PairStatus.NOT_RUN })
        assertFalse(ProcessEnvModel.allTargetsCovered(listOf("com.android.vending"), emptyList()))
    }

    @Test
    fun gmsUnstableIsShownAsNotRunAndHeadlessWaitsForIt() {
        val main = ObservedProcess("com.google.android.gms", "com.google.android.gms", 1L, env("M1"))
        val target = listOf("com.google.android.gms")
        val cols = ProcessEnvModel.targetColumns(target, listOf(main)) { _, process ->
            expected(if (process == ProcessEnvModel.GMS_UNSTABLE) "L2" else "L3", "build.model" to "M1") to null
        }
        val unstable = cols.single { it.process == ProcessEnvModel.GMS_UNSTABLE }
        assertNull(unstable.env)
        assertEquals("L2", unstable.expected?.layer)
        assertEquals(PairStatus.NOT_RUN, ProcessEnvModel.compare(cols).rows.single { it.key == "build.model" }.cells.getValue(unstable.id).status)
        assertFalse(ProcessEnvModel.allTargetsCovered(target, listOf(main), requireUnstable = true))
        assertTrue(ProcessEnvModel.allTargetsCovered(target, listOf(main), requireUnstable = false))
        val probe = ObservedProcess("com.google.android.gms", ProcessEnvModel.GMS_UNSTABLE, 2L, env("Pixel 7"))
        assertTrue(ProcessEnvModel.allTargetsCovered(target, listOf(main, probe), requireUnstable = true))
    }

    @Test
    fun permissionGatedCellIsLocked() {
        val e = env("M1", ""","telephony":{"meid":{"value":null,"reason":"permission"}}""")
        val cols = listOf(
            column(ProcessEnvModel.SELF_ID, "com.ghost.verify", e, null),
            column("com.google.android.gms:com.google.android.gms", "com.google.android.gms", e, null),
        )
        val row = ProcessEnvModel.compare(cols).rows.single { it.key == "telephony.meid" }
        val c = row.cells.getValue(ProcessEnvModel.SELF_ID)
        assertEquals(PairStatus.NOT_COLLECTABLE, c.status)
        assertEquals("🔒", ProcessEnvModel.symbol(c))
        assertEquals("permissions", row.group)
        assertFalse(row.hasDiff)
    }

    @Test
    fun glExtensionsStayVisibleButAreNotComparedAcrossDifferentProbeApis() {
        fun f(count: Int) = env("M1", ""","gl":{"extensions":{"count":$count,"sha256":"digest$count"}}""")
        val cols = listOf(
            column(ProcessEnvModel.SELF_ID, "com.ghost.verify", f(105), null),
            column("com.google.android.gms:com.google.android.gms", "com.google.android.gms", f(104), null),
        )
        val cmp = ProcessEnvModel.compare(cols)
        for (key in listOf("gl.extensions.count", "gl.extensions.sha256")) {
            val row = cmp.rows.single { it.key == key }
            assertTrue(row.hint!!.contains("仅供观测"))
            assertEquals(PairStatus.NOT_COLLECTABLE, row.cells.getValue(ProcessEnvModel.SELF_ID).status)
            assertEquals("–", ProcessEnvModel.symbol(row.cells.getValue(ProcessEnvModel.SELF_ID)))
        }
        assertEquals(0, cmp.mismatches)
    }

    @Test
    fun crossProcessComparisonWithinLayerOnly() {
        fun f(sha: String) = env("M1").apply {
            add("features", obj("""{"count":10,"sha256":"$sha"}"""))
        }
        val cols = listOf(
            column(ProcessEnvModel.SELF_ID, "com.ghost.verify", f("bbb"), null),
            column("com.google.android.gms:com.google.android.gms", "com.google.android.gms", f("aaa"), null),
            column("com.android.vending:com.android.vending", "com.android.vending", f("aaa"), null),
            // L2 档案进程不与 L3 互比
            column("com.google.android.gms:${ProcessEnvModel.GMS_UNSTABLE}", ProcessEnvModel.GMS_UNSTABLE, f("ccc"), null),
        )
        val row = ProcessEnvModel.compare(cols).rows.single { it.key == "features.sha256" }
        assertEquals(PairStatus.MISMATCH, row.cells.getValue(ProcessEnvModel.SELF_ID).status)
        assertEquals(PairStatus.MATCH, row.cells.getValue("com.android.vending:com.android.vending").status)
        assertEquals(PairStatus.MATCH, row.cells.getValue("com.google.android.gms:${ProcessEnvModel.GMS_UNSTABLE}").status)
        assertEquals("runtime", row.group)
        assertTrue(row.hasDiff)
    }

    @Test
    fun realSizeComparedUnordered() {
        val exp = expected("L3", "display.realWidthPixels" to "2400", "display.realHeightPixels" to "1080")
        val cols = listOf(column(ProcessEnvModel.SELF_ID, "com.ghost.verify", env("M1"), exp))
        val row = ProcessEnvModel.compare(cols).rows.single { it.key == "display.realSize" }
        assertEquals("2400x1080", row.selfExpected)
        assertEquals(PairStatus.MATCH, row.cells.getValue(ProcessEnvModel.SELF_ID).status)
    }

    @Test
    fun layerFallbackForUnstable() {
        assertEquals("L2", ProcessEnvModel.defaultLayer(ProcessEnvModel.GMS_UNSTABLE))
        assertEquals("L3", ProcessEnvModel.defaultLayer("com.google.android.gms"))
    }
}
