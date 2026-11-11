package com.ghost.verify

import android.app.ActivityManager
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.text.InputType
import android.util.DisplayMetrics
import android.util.Log
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TableLayout
import android.widget.TableRow
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.concurrent.thread

/**
 * 进程环境观测页:让 Ghost 在目标进程(gms / vending …)里注入采集 env,与 Ghost 期望值、
 * verify 自身读值逐字段对照。所有 provider 调用都在后台线程。
 *
 * headless:
 *   am start -n com.ghost.verify/.ProcessEnvActivity --es auto observe \
 *     --es targets com.google.android.gms,com.android.vending --ei ttl 600 --ei wait 60 [--ez keep true]
 * 完成后 logcat 打 `OBSERVE_DONE path=<路径> processes=<N> mismatches=<M>`。
 */
class ProcessEnvActivity : AppCompatActivity() {

    private lateinit var btnToggle: Button
    private lateinit var etTtl: EditText
    private lateinit var cbRestart: CheckBox
    private lateinit var btnOnlyDiff: Button
    private lateinit var tvStatus: TextView
    private lateinit var tableHost: LinearLayout

    private var targets = DEFAULT_TARGETS.toMutableList()
    private var hookPkgs: List<String> = emptyList()
    private var observeActive = false
    private var onlyDiff = false
    @Volatile private var unsupported = false
    @Volatile private var lastTtl = DEFAULT_TTL

    // 最近一次刷新得到的快照(导出用)
    private var lastStart: JsonObject? = null
    private var lastColumns: List<EnvColumn> = emptyList()
    private var lastRaw: Map<String, ObservedProcess> = emptyMap()
    private var lastComparison: ProcessEnvComparison? = null
    private var selfRawEnv: JsonObject? = null
    private val expectedCache = HashMap<String, Pair<ExpectedEnv?, String?>>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        buildUi()

        if (intent?.getStringExtra("auto") == "observe") {
            intent.getStringExtra("targets")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?.takeIf { it.isNotEmpty() }?.let { targets = it.toMutableList() }
            val ttl = intent.getIntExtra("ttl", DEFAULT_TTL)
            val waitSec = intent.getIntExtra("wait", 60)
            val keep = intent.getBooleanExtra("keep", false)
            val restart = intent.getBooleanExtra("restart", true)
            etTtl.setText(ttl.toString())
            cbRestart.isChecked = restart
            runHeadless(ttl, waitSec, keep, restart)
        } else {
            loadHookPkgs()
            refresh()
        }
    }

    // ------------------------------------------------------------------
    // UI(代码构建,风格同 MainActivity)
    // ------------------------------------------------------------------

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            fitsSystemWindows = true
            androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(this) { v, insets ->
                val bars = insets.getInsets(
                    androidx.core.view.WindowInsetsCompat.Type.systemBars()
                        or androidx.core.view.WindowInsetsCompat.Type.displayCutout()
                )
                v.setPadding(32 + bars.left, 32 + bars.top, 32 + bars.right, 32 + bars.bottom)
                insets
            }
        }
        btnToggle = Button(this).apply { text = "开始注入采集" }
        etTtl = EditText(this).apply {
            setText(DEFAULT_TTL.toString())
            inputType = InputType.TYPE_CLASS_NUMBER
            hint = "TTL 秒"
        }
        cbRestart = CheckBox(this).apply { text = "重启目标"; isChecked = true }
        val row1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnToggle, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f))
            addView(etTtl, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(cbRestart, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.4f))
        }
        val btnTargets = Button(this).apply { text = "目标" }
        val btnRefresh = Button(this).apply { text = "刷新" }
        val btnExport = Button(this).apply { text = "导出" }
        btnOnlyDiff = Button(this).apply { text = "只看差异" }
        val row2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            for (b in listOf(btnTargets, btnRefresh, btnExport, btnOnlyDiff)) {
                addView(b, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            }
        }
        tvStatus = TextView(this).apply {
            textSize = 12f
            setPadding(0, 16, 0, 16)
            text = "目标: ${targets.joinToString()}"
        }
        tableHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val scroll = ScrollView(this).apply {
            addView(HorizontalScrollView(this@ProcessEnvActivity).apply { addView(tableHost) })
        }
        root.addView(row1)
        root.addView(row2)
        root.addView(tvStatus)
        root.addView(scroll)
        setContentView(root)

        btnToggle.setOnClickListener { if (observeActive) stopObserve() else startObserve() }
        btnTargets.setOnClickListener { pickTargets() }
        btnRefresh.setOnClickListener { refresh() }
        btnExport.setOnClickListener {
            thread {
                val f = exportJson()
                runOnUiThread { setStatus("导出: ${f?.absolutePath ?: "<保存失败>"}") }
            }
        }
        btnOnlyDiff.setOnClickListener {
            onlyDiff = !onlyDiff
            btnOnlyDiff.text = if (onlyDiff) "显示全部" else "只看差异"
            lastComparison?.let { renderTable(it) }
        }
    }

    private fun setStatus(s: String) {
        tvStatus.text = buildString {
            append("目标: ${targets.joinToString()}\n")
            if (unsupported) append("⚠ Ghost 版本不支持观测\n")
            append(s)
        }
    }

    private fun pickTargets() {
        val items = (DEFAULT_TARGETS + hookPkgs + targets).distinct()
        val checked = BooleanArray(items.size) { items[it] in targets }
        AlertDialog.Builder(this)
            .setTitle("观测目标")
            .setMultiChoiceItems(items.toTypedArray(), checked) { _, i, on -> checked[i] = on }
            .setPositiveButton("确定") { _, _ ->
                targets = items.filterIndexed { i, _ -> checked[i] }.toMutableList()
                setStatus("已选 ${targets.size} 个目标")
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun loadHookPkgs() {
        thread {
            val list = GhostCallParser.parseStringList(GhostCall.raw(applicationContext, "getHookPkgs", emptyMap()))
            hookPkgs = list.orEmpty().filter { it != packageName }
        }
    }

    private fun ttl(): Int = etTtl.text.toString().toIntOrNull() ?: DEFAULT_TTL

    // ------------------------------------------------------------------
    // observe verb
    // ------------------------------------------------------------------

    private fun startObserve() {
        val t = ttl()
        val restart = cbRestart.isChecked
        val pkgs = targets.toList()
        btnToggle.isEnabled = false
        thread {
            val r = callStart(pkgs, t, restart)
            runOnUiThread {
                btnToggle.isEnabled = true
                when (r) {
                    is GhostCallResult.Ok -> {
                        observeActive = true
                        btnToggle.text = "停止注入采集"
                        setStatus("已开始: until=${r.body.str("until")} restarted=${r.body.str("restarted")}")
                    }
                    is GhostCallResult.Unsupported -> setStatus("start 不支持")
                    is GhostCallResult.Failed -> setStatus("start 失败: ${r.error}")
                }
            }
        }
    }

    private fun stopObserve() {
        btnToggle.isEnabled = false
        thread {
            val r = GhostCall.query(applicationContext, "observe", mapOf("op" to "stop"))
            runOnUiThread {
                btnToggle.isEnabled = true
                observeActive = false
                btnToggle.text = "开始注入采集"
                setStatus(if (r is GhostCallResult.Ok) "已停止" else "stop: $r")
            }
        }
    }

    /** 后台线程调用。ttl 由 Ghost 钳到 10..1800 秒,这里也先钳一遍。 */
    private fun callStart(pkgs: List<String>, ttl: Int, restart: Boolean): GhostCallResult {
        val r = GhostCall.query(applicationContext, "observe", mapOf(
            "op" to "start",
            "pkgs" to pkgs.joinToString(","),
            "ttl" to ttl.coerceIn(10, MAX_TTL).toString(),
            "restart" to if (restart) "1" else "0",
        ))
        if (r is GhostCallResult.Unsupported) unsupported = true
        if (r is GhostCallResult.Ok) lastStart = r.body
        lastTtl = ttl
        return r
    }

    /** 拉全部结果(分页:next>=0 用 from=next 继续,-1 结束)。后台线程调用。 */
    private fun fetchAllResults(): Pair<List<ObservedProcess>, GhostCallResult?> {
        val all = mutableListOf<ObservedProcess>()
        var from = 0
        repeat(MAX_PAGES) {
            val r = GhostCall.query(applicationContext, "observe", mapOf("op" to "results", "from" to from.toString()))
            if (r !is GhostCallResult.Ok) {
                if (r is GhostCallResult.Unsupported) unsupported = true
                return all to r
            }
            val (page, next) = ProcessEnvModel.parseResults(r.body)
            all += page
            if (next < 0 || next == from) return all to null
            from = next
        }
        return all to null
    }

    private fun expectedFor(pkg: String, process: String): Pair<ExpectedEnv?, String?> =
        expectedCache.getOrPut("$pkg:$process") {
            when (val r = GhostCall.query(applicationContext, "expectedEnv", mapOf("pkg" to pkg, "process" to process))) {
                is GhostCallResult.Ok -> ProcessEnvModel.parseExpected(r.body) to null
                is GhostCallResult.Unsupported -> null to "unsupported"
                is GhostCallResult.Failed -> null to r.error
            }
        }

    /** 拉一次 status + results,重算比较。后台线程调用;返回 (比较结果, 状态文字)。 */
    @Synchronized
    private fun recompute(): Pair<ProcessEnvComparison, String> {
        // 期望值按进程取,每次刷新都重新问(Ghost 可能刚切换设备档案)。
        expectedCache.clear()
        val status = GhostCall.query(applicationContext, "observe", mapOf("op" to "status"))
        if (status is GhostCallResult.Unsupported) unsupported = true
        val (results, err) = if (unsupported) emptyList<ObservedProcess>() to null else fetchAllResults()
        val latest = ProcessEnvModel.latestPerProcess(results)
        lastRaw = latest.associateBy { "${it.pkg}:${it.process}" }

        val selfEnv = selfRawEnv ?: SelfEnv.collect(applicationContext).also { selfRawEnv = it }
        val myProcess = android.app.Application.getProcessName()
        val (selfExp, selfErr) = expectedFor(packageName, myProcess)
        val self = EnvColumn(ProcessEnvModel.SELF_ID, packageName, myProcess,
            ProcessEnvModel.flatten(selfEnv), selfExp, selfErr)
        val cols = listOf(self) + ProcessEnvModel.targetColumns(targets, latest, ::expectedFor)
        lastColumns = cols
        val cmp = ProcessEnvModel.compare(cols)
        lastComparison = cmp
        val statusText = buildString {
            when (status) {
                is GhostCallResult.Ok -> append("active=${status.body.str("active")} until=${status.body.str("until")} count=${status.body.str("count")}")
                is GhostCallResult.Unsupported -> append("Ghost 版本不支持观测")
                is GhostCallResult.Failed -> append("status 失败: ${status.error}")
            }
            if (err is GhostCallResult.Failed) append("\nresults 失败: ${err.error}")
            append("\n期望(self): ").append(selfExp?.let { "layer=${it.layer} keys=${it.expected.size}" } ?: (selfErr ?: "-"))
            append("\n进程: ${latest.size}  未运行: ${cmp.notRun.joinToString().ifEmpty { "-" }}  ✗: ${cmp.mismatches}")
            if (cmp.hints.isNotEmpty()) append("\n提示:\n  ").append(cmp.hints.take(8).joinToString("\n  "))
        }
        if (status is GhostCallResult.Ok) observeActive = status.body.str("active") == "true"
        return cmp to statusText
    }

    private fun refresh() {
        setStatus("刷新中...")
        thread {
            val (cmp, text) = recompute()
            runOnUiThread {
                btnToggle.text = if (observeActive) "停止注入采集" else "开始注入采集"
                setStatus(text)
                renderTable(cmp)
            }
        }
    }

    // ------------------------------------------------------------------
    // headless
    // ------------------------------------------------------------------

    private fun runHeadless(ttl: Int, waitSec: Int, keep: Boolean, restart: Boolean) {
        setStatus("headless observe: ttl=$ttl wait=${waitSec}s keep=$keep")
        thread {
            val start = callStart(targets, ttl, restart)
            Log.i(TAG, "OBSERVE_START status=${statusWord(start)} targets=${targets.joinToString(",")}")
            var cmp: ProcessEnvComparison? = null
            var text = ""
            if (start is GhostCallResult.Ok) {
                val deadline = System.currentTimeMillis() + waitSec * 1000L
                while (true) {
                    val (c, t) = recompute()
                    cmp = c; text = t
                    val covered = ProcessEnvModel.allTargetsCovered(targets, lastRaw.values.toList(),
                        requireUnstable = "com.google.android.gms" in targets)
                    if (covered || System.currentTimeMillis() >= deadline) break
                    Thread.sleep(POLL_MS)
                }
            } else {
                val (c, t) = recompute()
                cmp = c; text = t
            }
            val file = exportJson()
            if (!keep && start is GhostCallResult.Ok) {
                GhostCall.query(applicationContext, "observe", mapOf("op" to "stop"))
            }
            val processes = lastColumns.count { it.id != ProcessEnvModel.SELF_ID && it.env != null }
            Log.i(TAG, "OBSERVE_STATUS start=${statusWord(start)} notRun=${cmp?.notRun?.joinToString(",")}")
            Log.i(TAG, "OBSERVE_DONE path=${file?.absolutePath} processes=$processes mismatches=${cmp?.mismatches ?: 0}")
            runOnUiThread {
                setStatus(text + "\n导出: ${file?.absolutePath ?: "<保存失败>"}")
                cmp?.let { renderTable(it) }
            }
        }
    }

    private fun statusWord(r: GhostCallResult) = when (r) {
        is GhostCallResult.Ok -> "ok"
        is GhostCallResult.Unsupported -> "unsupported"
        is GhostCallResult.Failed -> "error:${r.error.take(80)}"
    }

    // ------------------------------------------------------------------
    // 表格
    // ------------------------------------------------------------------

    private fun renderTable(cmp: ProcessEnvComparison) {
        tableHost.removeAllViews()
        val table = TableLayout(this)
        val header = TableRow(this)
        header.addView(cell("字段", bold = true))
        header.addView(cell("Ghost 期望", bold = true))
        for (c in cmp.columns) header.addView(cell(c, bold = true))
        table.addView(header)
        var group = ""
        for (row in cmp.rows) {
            if (onlyDiff && !row.hasDiff) continue
            if (row.group != group) {
                group = row.group
                table.addView(TableRow(this).apply { addView(cell("【$group】", bold = true)) })
            }
            val tr = TableRow(this)
            tr.addView(cell(row.key))
            tr.addView(cell(trunc(row.selfExpected) ?: "–"))
            for (id in cmp.columns) {
                val c = row.cells[id]
                if (c == null) { tr.addView(cell("–")); continue }
                val text = buildString {
                    append(ProcessEnvModel.symbol(c))
                    c.value?.let { append(' ').append(trunc(it)) }
                    // 该进程自己的期望与"Ghost 期望"列不同(L2/L3)时,把它的期望也写出来。
                    if (c.status == PairStatus.MISMATCH && c.expected != null && c.expected != row.selfExpected) {
                        append("\n期望:").append(trunc(c.expected))
                    }
                }
                tr.addView(cell(text, highlight = c.status == PairStatus.MISMATCH))
            }
            table.addView(tr)
            row.hint?.let { h ->
                table.addView(TableRow(this).apply { addView(cell("  ↳ $h")) })
            }
        }
        tableHost.addView(table)
    }

    private fun cell(text: String, bold: Boolean = false, highlight: Boolean = false) = TextView(this).apply {
        this.text = text
        textSize = 11f
        typeface = if (bold) Typeface.DEFAULT_BOLD else Typeface.MONOSPACE
        setPadding(12, 6, 12, 6)
        maxWidth = 640
        if (highlight) setBackgroundColor(Color.argb(80, 255, 60, 60))
    }

    private fun trunc(s: String?, max: Int = 48): String? =
        s?.let { if (it.length > max) it.take(max) + "…" else it }

    // ------------------------------------------------------------------
    // 导出(Download/ghost_verify/observe_<ts>.json,失败退回私有目录;同 MainActivity)
    // ------------------------------------------------------------------

    private data class ColumnExport(
        val id: String,
        val pkg: String,
        val process: String?,
        val at: Long?,
        val layer: String,
        val expected: ExpectedEnv?,
        val expectedError: String?,
        /** 原始 env;telephony 的值已换成 "present"。 */
        val env: JsonObject?,
    )

    private data class ObserveExport(
        val spec: String,
        val generatedAt: Long,
        val targets: List<String>,
        val ttl: Int,
        val unsupported: Boolean,
        val start: JsonObject?,
        val columns: List<ColumnExport>,
        val comparison: ProcessEnvComparison?,
    )

    private fun exportJson(): File? {
        val now = System.currentTimeMillis()
        val ts = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date(now))
        val cols = lastColumns.map { c ->
            val raw = if (c.id == ProcessEnvModel.SELF_ID) selfRawEnv else lastRaw[c.id]?.env
            ColumnExport(c.id, c.pkg, c.process, lastRaw[c.id]?.at, ProcessEnvModel.layerOf(c),
                c.expected, c.expectedError, raw?.let { ProcessEnvModel.redactEnv(it) })
        }
        val export = ObserveExport(
            spec = "ghost_verify.process_env.v1",
            generatedAt = now,
            targets = targets.toList(),
            ttl = lastTtl,
            unsupported = unsupported,
            start = lastStart,
            columns = cols,
            comparison = lastComparison,
        )
        val json = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create().toJson(export)
        val name = "observe_$ts.json"
        return try {
            val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "ghost_verify")
            if (!dir.exists()) dir.mkdirs()
            File(dir, name).apply { writeText(json) }
        } catch (t: Throwable) {
            try {
                val dir = File(getExternalFilesDir(null), "ghost_verify").apply { mkdirs() }
                File(dir, name).apply { writeText(json) }
            } catch (e: Throwable) {
                null
            }
        }
    }

    companion object {
        private const val TAG = "GhostVerifyObserve"
        private const val DEFAULT_TTL = 600
        private const val MAX_TTL = 1800
        private const val POLL_MS = 3_000L
        private const val MAX_PAGES = 64
        private val DEFAULT_TARGETS = listOf("com.google.android.gms", "com.android.vending")
    }
}

/** `content://com.ghost.call/<verb>?k=v` 调用;只能在后台线程用。 */
object GhostCall {
    private const val AUTHORITY = "content://com.ghost.call/"

    /** 原始 cursor 第 0 列第一行;provider 抛异常 → null。 */
    fun raw(context: Context, verb: String, params: Map<String, String>): String? {
        val b = Uri.parse(AUTHORITY + verb).buildUpon()
        params.forEach { (k, v) -> b.appendQueryParameter(k, v) }
        return try {
            context.contentResolver.query(b.build(), null, null, null, null)
                ?.use { if (it.moveToFirst()) it.getString(0) else "" }
        } catch (t: Throwable) {
            Log.w("GhostCall", "query $verb failed: ${t.javaClass.simpleName}: ${t.message}")
            null
        }
    }

    fun query(context: Context, verb: String, params: Map<String, String>): GhostCallResult =
        raw(context, verb, params)?.let { GhostCallParser.parse(it) }
            ?: GhostCallResult.Failed("provider 调用失败或无 cursor")
}

/**
 * verify 自身进程的 env,schema 与 Ghost Collector.collectEnv 一致(子集:不含 runtimeEnv / glsl)。
 * features / sharedLibs / gl.extensions 的摘要算法同 Ghost:排序后逐项 sha256(项 + '\n')。
 */
object SelfEnv {
    fun collect(ctx: Context): JsonObject {
        val root = org.json.JSONObject()
        fun safe(block: () -> Unit) = runCatching(block)
        root.put("envSchemaVersion", 1)
        root.put("collectedAt", System.currentTimeMillis())
        root.put("processPkg", ctx.packageName)
        root.put("processName", android.app.Application.getProcessName())
        root.put("pid", android.os.Process.myPid())
        root.put("uid", android.os.Process.myUid())
        safe {
            root.put("build", org.json.JSONObject().apply {
                put("device", Build.DEVICE); put("hardware", Build.HARDWARE); put("board", Build.BOARD)
                put("product", Build.PRODUCT); put("model", Build.MODEL); put("fingerprint", Build.FINGERPRINT)
                put("manufacturer", Build.MANUFACTURER); put("brand", Build.BRAND); put("id", Build.ID)
                put("release", Build.VERSION.RELEASE); put("sdkInt", Build.VERSION.SDK_INT)
                put("host", Build.HOST); put("bootloader", Build.BOOTLOADER)
                put("incremental", Build.VERSION.INCREMENTAL); put("securityPatch", Build.VERSION.SECURITY_PATCH)
                put("sku", listOf("ro.boot.hardware.sku", "ro.boot.product.hardware.sku", "ro.oem.key1")
                    .map { runCatching { NativeBridge.getSystemProperty(it) }.getOrDefault("") }
                    .firstOrNull { it.isNotEmpty() } ?: "")
                if (Build.VERSION.SDK_INT >= 31) {
                    put("socModel", Build.SOC_MODEL); put("socManufacturer", Build.SOC_MANUFACTURER)
                }
                put("displayId", Build.DISPLAY); put("type", Build.TYPE); put("tags", Build.TAGS)
            })
        }
        safe {
            val l = ctx.resources.configuration.locales.get(0)
            val filled = runCatching {
                android.icu.util.ULocale.addLikelySubtags(android.icu.util.ULocale.forLocale(l)).toLocale()
            }.getOrDefault(l)
            root.put("locale", org.json.JSONObject().apply {
                put("language", filled.language); put("script", filled.script)
                put("country", filled.country); put("tag", filled.toLanguageTag())
            })
        }
        root.put("timezone", TimeZone.getDefault().id)
        safe {
            val m = ctx.resources.displayMetrics
            val d = org.json.JSONObject().apply {
                put("widthPixels", m.widthPixels); put("heightPixels", m.heightPixels)
                put("densityDpi", m.densityDpi); put("xDpi", m.xdpi.toDouble()); put("yDpi", m.ydpi.toDouble())
            }
            val real = DisplayMetrics()
            @Suppress("DEPRECATION")
            (ctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay.getRealMetrics(real)
            d.put("realWidthPixels", real.widthPixels); d.put("realHeightPixels", real.heightPixels)
            root.put("display", d)
        }
        safe {
            val g = NativeBridge.getGlesStrings()
            val renderer = g.getOrNull(1).orEmpty()
            root.put("gl", org.json.JSONObject().apply {
                put("vendor", g.getOrNull(0).orEmpty()); put("renderer", renderer); put("version", g.getOrNull(2).orEmpty())
                put("extensions", digest(g.getOrNull(3).orEmpty().split(' ', '\n').filter { it.isNotBlank() }))
            })
            root.put("hwAnchor", org.json.JSONObject().apply {
                put("gpuFamily", gpuFamilyOf(renderer)); put("gpuRenderer", renderer)
                put("cpuAbiPrimary", Build.SUPPORTED_ABIS.firstOrNull() ?: "")
            })
        }
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        safe {
            val mi = ActivityManager.MemoryInfo(); am?.getMemoryInfo(mi)
            root.put("mem", org.json.JSONObject().apply { put("totalMem", mi.totalMem) })
        }
        root.put("cpuCount", Runtime.getRuntime().availableProcessors())
        safe {
            val u = android.system.Os.uname()
            root.put("uname", org.json.JSONObject().apply {
                put("sysname", u.sysname); put("nodename", u.nodename); put("release", u.release)
                put("version", u.version); put("machine", u.machine)
            })
        }
        safe { root.put("reqGlEsVersion", am?.deviceConfigurationInfo?.reqGlEsVersion ?: 0) }
        safe {
            val items = ctx.packageManager.systemAvailableFeatures.orEmpty().map { fi ->
                org.json.JSONObject().apply {
                    if (fi.name != null) { put("name", fi.name); put("version", fi.version) }
                    else put("glEsVersion", fi.glEsVersion)
                }.toString()
            }
            root.put("features", digest(items))
        }
        safe { root.put("sharedLibs", digest(ctx.packageManager.systemSharedLibraryNames.orEmpty().toList())) }
        safe {
            root.put("androidId", android.provider.Settings.Secure.getString(
                ctx.contentResolver, android.provider.Settings.Secure.ANDROID_ID))
        }
        safe {
            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? android.telephony.TelephonyManager
            root.put("telephony", org.json.JSONObject().apply {
                put("imei", gated { tm?.imei })
                put("meid", gated { tm?.meid })
                put("serialno", gated { Build.getSerial() })
            })
        }
        return JsonParser.parseString(root.toString()).asJsonObject
    }

    /** {value, reason}:同 Ghost gatedId —— SecurityException → permission,空 → empty。 */
    private fun gated(read: () -> String?): org.json.JSONObject {
        val o = org.json.JSONObject()
        val r = runCatching(read)
        val v = r.getOrNull()?.takeIf { it.isNotBlank() && it != "unknown" }
        o.put("value", v ?: org.json.JSONObject.NULL)
        if (v == null) {
            val e = r.exceptionOrNull()
            o.put("reason", when {
                e is SecurityException -> "permission"
                e != null -> "error:${e.javaClass.simpleName}"
                else -> "empty"
            })
        }
        return o
    }

    private fun digest(items: List<String>): org.json.JSONObject {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val sorted = items.sorted()
        for (s in sorted) { md.update(s.toByteArray(Charsets.UTF_8)); md.update('\n'.code.toByte()) }
        return org.json.JSONObject().apply {
            put("count", sorted.size)
            put("sha256", md.digest().joinToString("") { "%02x".format(it) })
        }
    }

    /** 与 Ghost Collector.gpuFamilyOf 同一关键词表。 */
    private fun gpuFamilyOf(raw: String): String {
        val g = raw.lowercase(Locale.ROOT)
        return when {
            g.isEmpty() -> "UNKNOWN"
            g.contains("adreno") -> "QUALCOMM"
            g.contains("mali") || g.contains("immortalis") -> "ARM"
            g.contains("powervr") || g.contains("imagination") || g.contains("dxt") -> "IMAGINATION"
            g.contains("xclipse") -> "SAMSUNG"
            else -> "UNKNOWN"
        }
    }
}
