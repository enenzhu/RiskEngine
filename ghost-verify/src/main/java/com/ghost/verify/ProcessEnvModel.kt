package com.ghost.verify

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser

/*
 * 进程环境观测(ProcessEnvActivity)的纯逻辑:解析 Ghost call provider 响应、展平 env、
 * 逐进程对期望值 / 跨进程比对、归因提示。只依赖 Gson,不碰 Android API,可在 JVM 单测
 * (android.jar 里的 org.json 是 stub,单测里不能用)。
 */

/** Ghost `content://com.ghost.call/<verb>` 的一次响应。 */
sealed class GhostCallResult {
    data class Ok(val body: JsonObject) : GhostCallResult()
    data class Failed(val error: String) : GhostCallResult()
    /** 旧 Ghost 返回 "Method not found: <verb>" → 页面显示"Ghost 版本不支持",不计风险。 */
    data class Unsupported(val detail: String) : GhostCallResult()
}

object GhostCallParser {
    /**
     * cursor 第 0 列第一行的原始字符串 → 结果。
     * - 约定是原始 JSON 对象串;兼容被 gson 再包一层的情况:首字符是 `"` 先按 JSON string 解一层。
     * - "Method not found..."(裸串或 error 字段)→ Unsupported。
     * - ok=true → Ok;其它(ok=false / 非对象 / 解析失败)→ Failed(error)。
     */
    fun parse(raw: String?): GhostCallResult {
        var s = raw?.trim().orEmpty()
        if (s.isEmpty()) return GhostCallResult.Failed("empty response")
        if (s.startsWith('"')) {
            s = runCatching { JsonParser.parseString(s).asString.trim() }
                .getOrElse { return GhostCallResult.Failed("bad json string: ${it.message?.take(120)}") }
        }
        if (s.startsWith("Method not found", ignoreCase = true)) return GhostCallResult.Unsupported(s)
        val el = runCatching { JsonParser.parseString(s) }
            .getOrElse { return GhostCallResult.Failed("bad json: ${s.take(120)}") }
        if (!el.isJsonObject) return GhostCallResult.Failed("not a json object: ${s.take(120)}")
        val obj = el.asJsonObject
        val ok = obj.get("ok")?.takeIf { it.isJsonPrimitive }?.asString == "true"
        if (ok) return GhostCallResult.Ok(obj)
        val err = obj.str("error") ?: "ok=false"
        if (err.startsWith("Method not found", ignoreCase = true)) return GhostCallResult.Unsupported(err)
        return GhostCallResult.Failed(err)
    }

    /** `getHookPkgs` 返回 JSON 字符串数组(同样兼容外面再包一层引号);解析失败 → null。 */
    fun parseStringList(raw: String?): List<String>? {
        var s = raw?.trim().orEmpty()
        if (s.startsWith('"')) s = runCatching { JsonParser.parseString(s).asString.trim() }.getOrNull() ?: return null
        if (!s.startsWith('[')) return null
        val arr = runCatching { JsonParser.parseString(s).asJsonArray }.getOrNull() ?: return null
        return arr.mapNotNull { e -> e.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() } }
    }
}

/** 取对象里的标量字段为字符串;缺失或 JSON null → null,对象/数组 → 其 JSON 文本。 */
internal fun JsonObject.str(key: String): String? {
    val v = get(key) ?: return null
    return when {
        v.isJsonNull -> null
        v.isJsonPrimitive -> v.asString
        else -> v.toString()
    }
}

/** `expectedEnv` 的成功响应。expected 缺键 = Ghost 对该项没有确定期望 → 不比较。 */
data class ExpectedEnv(
    val deviceId: String?,
    val pkg: String?,
    val process: String?,
    /** L2 = Play Integrity 档案(gms.unstable,期望 Pixel);L3 = 虚拟设备。 */
    val layer: String?,
    val sharedProof: Boolean?,
    val expected: Map<String, String>,
)

/** 展平后的一个格子。gated=权限门控标识(telephony),value 只会是 "present" 或 null。 */
data class EnvCell(val value: String?, val reason: String? = null, val gated: Boolean = false)

/** 一列:verify 自身或某个被观测进程。env=null 表示该目标在观测期内没有结果(NOT_RUN)。 */
data class EnvColumn(
    /** "pkg:process";verify 自身列为 [ProcessEnvModel.SELF_ID]。 */
    val id: String,
    val pkg: String,
    val process: String?,
    val env: Map<String, EnvCell>?,
    val expected: ExpectedEnv?,
    val expectedError: String? = null,
)

data class EnvCellResult(
    val value: String?,
    /** 该列自己的期望值(按 pkg+process 取的 expectedEnv);null = 无期望,走跨进程比较。 */
    val expected: String?,
    val status: PairStatus,
    val reason: String? = null,
)

data class EnvRow(
    val key: String,
    val group: String,
    /** "Ghost 期望"列显示的值 = verify 自身进程的期望值。 */
    val selfExpected: String?,
    val cells: Map<String, EnvCellResult>,
    val hint: String? = null,
) {
    val hasDiff: Boolean
        get() = cells.values.any { it.status == PairStatus.MISMATCH || it.status == PairStatus.ONE_SIDED }
}

data class ProcessEnvComparison(
    val columns: List<String>,
    val rows: List<EnvRow>,
    /** 观测期内一个结果都没有的目标列。 */
    val notRun: List<String>,
    /** 所有列(含 verify 自身)的 MISMATCH 格子数。 */
    val mismatches: Int,
    val hints: List<String>,
)

/** `observe?op=results` 里的一条。 */
data class ObservedProcess(val pkg: String, val process: String, val at: Long?, val env: JsonObject?)

object ProcessEnvModel {
    const val SELF_ID = "verify(self)"
    const val GMS_UNSTABLE = "com.google.android.gms.unstable"

    val GROUP_ORDER = listOf("build", "display", "gl", "mem", "kernel", "runtime", "permissions")

    const val HINT_EXPECTED = "全部进程一致但≠期望 → 优先怀疑期望值/配置投影"
    const val HINT_PROCESS = "该进程 hook 漏装或串档"

    /** env 顶层元数据,不作为比较行。 */
    private val META_KEYS = setOf(
        "envSchemaVersion", "collectedAt", "processPkg", "processName", "pid", "uid", "error", "fatal",
    )

    /**
     * 进程间天然不同或时刻在变的值:不比较(原始 env 仍随导出保存)。
     * androidId 自 Android 8 起按 app 签名区分,跨进程不同是正常的。
     */
    private val VOLATILE_KEYS = setOf(
        "mem.runtimeTotal", "mem.runtimeMax", "mem.runtimeFree", "mem.diskFree",
        "runtimeEnv.batteryLevel", "runtimeEnv.batteryTemperatureTenthC", "runtimeEnv.batteryVoltageMv",
        "androidId",
    )

    fun groupOf(key: String): String = when {
        key.startsWith("build.") -> "build"
        key.startsWith("display.") -> "display"
        key.startsWith("gl.") || key.startsWith("hwAnchor.") || key == "reqGlEsVersion" -> "gl"
        key.startsWith("mem.") || key == "cpuCount" -> "mem"
        key.startsWith("uname.") -> "kernel"
        key.startsWith("telephony.") -> "permissions"
        else -> "runtime"
    }

    /** 没拿到 layer 字段时的兜底:gms.unstable 期望 Pixel 档案(L2),其余跟虚拟设备(L3)。 */
    fun defaultLayer(process: String?): String = if (process == GMS_UNSTABLE) "L2" else "L3"

    fun layerOf(col: EnvColumn): String = col.expected?.layer ?: defaultLayer(col.process)

    fun parseExpected(body: JsonObject): ExpectedEnv {
        val exp = linkedMapOf<String, String>()
        body.get("expected")?.takeIf { it.isJsonObject }?.asJsonObject?.entrySet()?.forEach { (k, v) ->
            if (v.isJsonPrimitive) exp[k] = v.asString
        }
        return ExpectedEnv(
            deviceId = body.str("deviceId"),
            pkg = body.str("pkg"),
            process = body.str("process"),
            layer = body.str("layer"),
            sharedProof = body.str("sharedProof")?.toBooleanStrictOrNull(),
            expected = exp,
        )
    }

    /** 期望值改成与 [flatten] 同名的比较键:真实宽高合成 display.realSize。 */
    fun expectedKeys(exp: ExpectedEnv?): Map<String, String> {
        if (exp == null) return emptyMap()
        val out = LinkedHashMap(exp.expected)
        mergeSize(out, "display.realWidthPixels", "display.realHeightPixels", "display.realSize")
        return out
    }

    /**
     * env → 点路径扁平表,键名与 expectedEnv 的 key 一致(build.model、uname.release…)。
     * - 元数据与 [VOLATILE_KEYS] 不进表;
     * - telephony.<id>:{value, reason} → 只留"有值/无值"(present / null + reason),值本身不出现;
     * - 宽高合成 display.size / display.realSize("WxH",比较时无序)。
     */
    fun flatten(env: JsonObject): Map<String, EnvCell> {
        val out = linkedMapOf<String, EnvCell>()
        fun walk(path: String, el: JsonElement) {
            when {
                el.isJsonNull -> out[path] = EnvCell(null, "empty")
                el.isJsonObject -> for ((k, v) in el.asJsonObject.entrySet()) walk("$path.$k", v)
                el.isJsonArray -> out[path] = EnvCell(el.toString())
                else -> out[path] = EnvCell(el.asString)
            }
        }
        for ((k, v) in env.entrySet()) {
            if (k in META_KEYS) continue
            if (k == "telephony" && v.isJsonObject) {
                for ((id, t) in v.asJsonObject.entrySet()) out["telephony.$id"] = gatedCell(t)
                continue
            }
            if (v.isJsonObject) for ((kk, vv) in v.asJsonObject.entrySet()) walk("$k.$kk", vv)
            else walk(k, v)
        }
        VOLATILE_KEYS.forEach { out.remove(it) }
        mergeSizeCells(out, "display.widthPixels", "display.heightPixels", "display.size")
        mergeSizeCells(out, "display.realWidthPixels", "display.realHeightPixels", "display.realSize")
        return out
    }

    private fun gatedCell(t: JsonElement): EnvCell {
        if (!t.isJsonObject) return EnvCell(null, "empty", gated = true)
        val o = t.asJsonObject
        val (v, _) = normalizeObserved(o.str("value"), null, identity = true)
        return if (v != null) EnvCell("present", null, gated = true)
        else EnvCell(null, o.str("reason")?.takeIf { it.isNotBlank() } ?: "empty", gated = true)
    }

    private fun mergeSize(map: MutableMap<String, String>, w: String, h: String, to: String) {
        val wv = map.remove(w)
        val hv = map.remove(h)
        if (wv != null && hv != null) map[to] = "${wv.trim()}x${hv.trim()}"
    }

    private fun mergeSizeCells(map: MutableMap<String, EnvCell>, w: String, h: String, to: String) {
        val wv = map.remove(w)?.value
        val hv = map.remove(h)?.value
        if (wv != null || hv != null) {
            map[to] = if (wv != null && hv != null) EnvCell("${wv}x$hv") else EnvCell(null, "empty")
        }
    }

    /** 导出用:telephony 的 value 换成 "present",原值不落盘。 */
    fun redactEnv(env: JsonObject): JsonObject {
        val copy = env.deepCopy()
        copy.get("telephony")?.takeIf { it.isJsonObject }?.asJsonObject?.entrySet()?.forEach { (_, t) ->
            if (t.isJsonObject) {
                val o = t.asJsonObject
                if (o.str("value") != null) o.addProperty("value", "present")
            }
        }
        return copy
    }

    /** `observe?op=results&from=N` → (本页结果, next);next=-1 表示没有下一页。 */
    fun parseResults(body: JsonObject): Pair<List<ObservedProcess>, Int> {
        val list = mutableListOf<ObservedProcess>()
        body.get("results")?.takeIf { it.isJsonArray }?.asJsonArray?.forEach { r ->
            if (!r.isJsonObject) return@forEach
            val o = r.asJsonObject
            val pkg = o.str("pkg") ?: return@forEach
            list += ObservedProcess(
                pkg = pkg,
                process = o.str("process") ?: pkg,
                at = o.str("at")?.toLongOrNull(),
                env = o.get("env")?.let { e ->
                    when {
                        e.isJsonObject -> e.asJsonObject
                        // 兼容 env 被序列化成字符串的情况
                        e.isJsonPrimitive -> runCatching { JsonParser.parseString(e.asString).asJsonObject }.getOrNull()
                        else -> null
                    }
                },
            )
        }
        val next = body.str("next")?.toIntOrNull() ?: -1
        return list to next
    }

    /** 同一进程多次采集只留最新一条(进程重启后会重报)。 */
    fun latestPerProcess(results: List<ObservedProcess>): List<ObservedProcess> =
        results.groupBy { "${it.pkg}:${it.process}" }.values
            .map { same -> same.maxByOrNull { it.at ?: Long.MIN_VALUE }!! }
            .sortedWith(compareBy({ it.pkg }, { it.process }))

    /** 每个目标包至少有一个进程结果;headless 包含 GMS 时还要等 unstable(否则 8 秒就 stop,来不及点 Check integrity)。 */
    fun allTargetsCovered(targets: List<String>, results: List<ObservedProcess>, requireUnstable: Boolean = false): Boolean =
        targets.all { t -> results.any { it.pkg == t } } &&
            (!requireUnstable || results.any { it.pkg == "com.google.android.gms" &&
                (it.process == GMS_UNSTABLE || it.process == "com.google.android.gms:unstable") })

    private fun isSizeKey(key: String) = key == "display.size" || key == "display.realSize"

    /** 比较用规范形:大小写不敏感;宽高按无序对。 */
    private fun canon(key: String, v: String): String {
        if (isSizeKey(key)) {
            val parts = v.split('x').map { it.trim() }
            if (parts.size == 2) return parts.sortedBy { it.toLongOrNull() ?: Long.MAX_VALUE }.joinToString("x")
        }
        return v.lowercase()
    }

    /**
     * 逐行逐列判定:
     * - 列没有结果 → NOT_RUN;telephony 无值(带 reason)→ NOT_COLLECTABLE(🔒,不计风险);
     * - 该列有期望值 → 与之比较(MATCH / MISMATCH;本进程该键为空 → ONE_SIDED);
     * - 无期望值 → 同 layer 的列之间比较(L2 档案进程与 L3 进程本来就不同,不互比):
     *   取多数值,偏离者 MISMATCH;该进程 schema 里根本没有这个键 → NOT_COLLECTABLE(absent)。
     * 归因提示(只针对有期望值的行,按 layer 分组):全部 ≠ 期望且彼此相同 → [HINT_EXPECTED];
     * 只有部分 ≠ 期望(或彼此也不同)→ [HINT_PROCESS] 并列出这些进程。
     */
    fun compare(columns: List<EnvColumn>): ProcessEnvComparison {
        val expByCol = columns.associate { it.id to expectedKeys(it.expected) }
        val keys = LinkedHashSet<String>()
        columns.firstOrNull { it.id == SELF_ID }?.let { self ->
            keys += expByCol[self.id].orEmpty().keys
            self.env?.keys?.let { keys += it }
        }
        for (c in columns) {
            keys += expByCol[c.id].orEmpty().keys
            c.env?.keys?.let { keys += it }
        }
        val ordered = keys.sortedBy { GROUP_ORDER.indexOf(groupOf(it)).let { i -> if (i < 0) GROUP_ORDER.size else i } }
        val selfExp = expByCol[SELF_ID].orEmpty()

        val rows = ordered.map { key ->
            val cells = linkedMapOf<String, EnvCellResult>()
            val pending = mutableListOf<EnvColumn>()
            for (c in columns) {
                val env = c.env
                if (env == null) {
                    cells[c.id] = EnvCellResult(null, expByCol[c.id]?.get(key), PairStatus.NOT_RUN, "no_result")
                    continue
                }
                val cell = env[key]
                val exp = expByCol[c.id]?.get(key)
                cells[c.id] = when {
                    cell != null && cell.gated && cell.value == null ->
                        EnvCellResult(null, exp, PairStatus.NOT_COLLECTABLE, cell.reason)
                    exp != null && cell?.value == null ->
                        EnvCellResult(null, exp, PairStatus.ONE_SIDED, cell?.reason ?: "absent")
                    exp != null ->
                        EnvCellResult(cell!!.value, exp,
                            if (canon(key, cell.value!!) == canon(key, exp)) PairStatus.MATCH else PairStatus.MISMATCH)
                    // verify 的 NativeBridge 用 GLES2 glGetString(GL_EXTENSIONS),注入端 GlProbe 用
                    // GLES3 glGetStringi;两种枚举集合可能差一项(wa_26:105 vs 104),保留观测值但不比较。
                    key.startsWith("gl.extensions.") ->
                        EnvCellResult(cell?.value, null, PairStatus.NOT_COLLECTABLE, "different_probe_api")
                    else -> {
                        pending += c
                        EnvCellResult(cell?.value, null, PairStatus.NOT_RUN) // 占位,下面跨进程比较覆盖
                    }
                }
            }
            // 无期望值:同 layer 内跨进程比较。
            for ((_, group) in pending.groupBy { layerOf(it) }) {
                val values = group.mapNotNull { c -> c.env?.get(key)?.value?.let { canon(key, it) } }
                val majority = values.groupingBy { it }.eachCount().maxByOrNull { it.value }?.key
                for (c in group) {
                    val cell = c.env?.get(key)
                    cells[c.id] = when {
                        cell == null -> EnvCellResult(null, null, PairStatus.NOT_COLLECTABLE, "absent")
                        cell.value == null && majority == null ->
                            EnvCellResult(null, null, PairStatus.NOT_COLLECTABLE, cell.reason ?: "empty")
                        cell.value == null -> EnvCellResult(null, null, PairStatus.ONE_SIDED, cell.reason ?: "empty")
                        canon(key, cell.value) == majority ->
                            EnvCellResult(cell.value, null, PairStatus.MATCH,
                                if (values.size <= 1) "no_peer" else null)
                        else -> EnvCellResult(cell.value, null, PairStatus.MISMATCH, "differs_from_peers")
                    }
                }
            }
            EnvRow(key, groupOf(key), selfExp[key], cells,
                if (key.startsWith("gl.extensions.")) "GLES2/3 枚举接口不同，仅供观测" else hintFor(key, columns, cells))
        }

        val notRun = columns.filter { it.env == null }.map { it.id }
        val mismatches = rows.sumOf { r -> r.cells.values.count { it.status == PairStatus.MISMATCH } }
        val hints = rows.mapNotNull { r -> r.hint?.let { "${r.key}: $it" } }
        return ProcessEnvComparison(columns.map { it.id }, rows, notRun, mismatches, hints)
    }

    private fun hintFor(key: String, columns: List<EnvColumn>, cells: Map<String, EnvCellResult>): String? {
        val parts = mutableListOf<String>()
        for ((layer, group) in columns.groupBy { layerOf(it) }) {
            val compared = group.filter { c ->
                val r = cells[c.id]
                r?.expected != null && (r.status == PairStatus.MATCH || r.status == PairStatus.MISMATCH)
            }
            val mism = compared.filter { cells[it.id]?.status == PairStatus.MISMATCH }
            if (mism.isEmpty()) continue
            val ok = compared.size - mism.size
            val distinctActual = mism.mapNotNull { cells[it.id]?.value?.let { v -> canon(key, v) } }.distinct().size
            parts += if (ok == 0 && distinctActual <= 1) "[$layer] $HINT_EXPECTED"
            else "[$layer] ${mism.joinToString(",") { it.id }} ≠ 期望 → $HINT_PROCESS"
        }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(";")
    }

    /** 由目标包与观测结果组列:有结果的每个进程一列,没结果的目标补一列 NOT_RUN。 */
    fun targetColumns(
        targets: List<String>,
        results: List<ObservedProcess>,
        expectedFor: (pkg: String, process: String) -> Pair<ExpectedEnv?, String?>,
    ): List<EnvColumn> {
        val latest = latestPerProcess(results)
        val cols = mutableListOf<EnvColumn>()
        for (t in targets) {
            val mine = latest.filter { it.pkg == t }
            if (mine.isEmpty()) {
                if (t == "com.google.android.gms") {
                    for (process in listOf(t, GMS_UNSTABLE)) {
                        val (exp, err) = expectedFor(t, process)
                        cols += EnvColumn("$t:$process", t, process, null, exp, err)
                    }
                } else cols += EnvColumn("$t:–", t, null, null, null, "no_result")
                continue
            }
            for (r in mine) {
                val (exp, err) = expectedFor(r.pkg, r.process)
                cols += EnvColumn("${r.pkg}:${r.process}", r.pkg, r.process, r.env?.let { flatten(it) }, exp, err)
            }
            if (t == "com.google.android.gms" && mine.none { it.process == GMS_UNSTABLE || it.process == "$t:unstable" }) {
                val (exp, err) = expectedFor(t, GMS_UNSTABLE)
                cols += EnvColumn("$t:$GMS_UNSTABLE", t, GMS_UNSTABLE, null, exp, err)
            }
        }
        // 非目标包也可能被上报(例如共享进程),附在后面。
        for (r in latest.filter { it.pkg !in targets }) {
            val (exp, err) = expectedFor(r.pkg, r.process)
            cols += EnvColumn("${r.pkg}:${r.process}", r.pkg, r.process, r.env?.let { flatten(it) }, exp, err)
        }
        return cols
    }

    /** 表格格子符号:✓ 一致 / ✗ 不一致 / 🔒 不可采 / – 未运行、单侧缺值或该进程没采这个键。 */
    fun symbol(cell: EnvCellResult): String = when (cell.status) {
        PairStatus.MATCH -> "✓"
        PairStatus.MISMATCH -> "✗"
        PairStatus.NOT_COLLECTABLE -> if (cell.reason == "absent" || cell.reason == "different_probe_api") "–" else "🔒"
        PairStatus.ONE_SIDED, PairStatus.NOT_RUN -> "–"
    }
}
