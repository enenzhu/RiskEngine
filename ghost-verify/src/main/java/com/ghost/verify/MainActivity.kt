package com.ghost.verify

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import com.google.gson.GsonBuilder
import com.wsttxm.riskenginesdk.RiskEngine
import com.wsttxm.riskenginesdk.RiskEngineConfig
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var btnCollect: Button
    private lateinit var btnList: Button
    private lateinit var btnClear: Button
    private lateinit var btnViewMode: Button
    private lateinit var tvSummary: TextView
    private lateinit var tvLog: TextView

    // 视图模式:0=全字段 / 1=只看不一致 / 2=只看 SDK 检测
    private var viewMode: Int = 0
    private var lastReport: CollectReport? = null
    private var lastSdkReport: com.wsttxm.riskenginesdk.model.RiskReport? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Theme.Material3 默认带 ActionBar(显示 "Ghost Verify" 标题),
        // 在 Android 16 + edge-to-edge 下它会盖住 LinearLayout 第一个 button → 按钮不可见
        supportActionBar?.hide()

        // 初始化 RiskEngine SDK(同应用进程,只 init 一次)
        if (!RiskEngine.isInitialized()) {
            RiskEngine.init(
                applicationContext,
                RiskEngineConfig.Builder()
                    .debugLog(true)
                    .collectTimeout(15000)
                    .build()
            )
        }

        // 简单代码 UI(避免 layout xml 依赖)
        // Android 15+/Pixel: targetSdk 36 默认 edge-to-edge,需要监听 WindowInsets 调 padding,
        // 否则顶部按钮会被 statusBar/notch 遮住,底部按钮会被 navigation bar 遮住
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            fitsSystemWindows = true
            androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(this) { v, insets ->
                val bars = insets.getInsets(
                    androidx.core.view.WindowInsetsCompat.Type.systemBars()
                            or androidx.core.view.WindowInsetsCompat.Type.displayCutout()
                )
                v.setPadding(48 + bars.left, 48 + bars.top, 48 + bars.right, 48 + bars.bottom)
                insets
            }
        }
        btnCollect = Button(this).apply { text = "采集设备信息" }
        btnList = Button(this).apply { text = "列出已保存报告" }
        btnClear = Button(this).apply { text = "清空报告" }
        btnViewMode = Button(this).apply { text = "视图: 全字段" }
        tvSummary = TextView(this).apply {
            text = "等待采集..."
            textSize = 14f
            setPadding(0, 24, 0, 24)
        }
        tvLog = TextView(this).apply {
            textSize = 11f
            // 等宽 + 文字可选(便于复制单个值)
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply { addView(tvLog) }

        // 操作 button 横向一行,节省垂直空间
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnCollect, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f))
            addView(btnViewMode, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        val btnRow2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnList,  LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnClear, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        root.addView(btnRow)
        root.addView(btnRow2)
        root.addView(tvSummary)
        root.addView(scroll)
        setContentView(root)

        ensureStoragePermission()

        btnCollect.setOnClickListener { runCollection() }
        btnList.setOnClickListener { listReports() }
        btnClear.setOnClickListener { clearReports() }
        btnViewMode.setOnClickListener {
            viewMode = (viewMode + 1) % 3
            btnViewMode.text = when (viewMode) {
                0 -> "视图: 全字段"
                1 -> "视图: 只看不一致"
                else -> "视图: 只看 SDK"
            }
            // 重新渲染当前 report
            lastReport?.let { tvLog.text = formatSummary(it, lastSdkReport) }
        }
    }

    private fun ensureStoragePermission() {
        // Android 11+ 优先 MANAGE_EXTERNAL_STORAGE,否则 fallback 到 legacy WRITE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.data = Uri.parse("package:$packageName")
                try { startActivity(intent) } catch (_: Throwable) {}
            }
        } else {
            ActivityCompat.requestPermissions(this,
                arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE, Manifest.permission.READ_PHONE_STATE),
                1)
        }
    }

    private fun runCollection() {
        tvSummary.text = "采集中..."
        btnCollect.isEnabled = false
        thread {
            val t0 = System.currentTimeMillis()
            // 1) ghost-verify 自己的多路径一致性采集
            val ghostReport = GhostCollector(applicationContext).collectAll()
            val ghostCost = System.currentTimeMillis() - t0

            // 2) RiskEngine SDK 全量采集(fingerprint + 检测器结果)
            val sdkT0 = System.currentTimeMillis()
            var sdkReport: com.wsttxm.riskenginesdk.model.RiskReport? = null
            var sdkError: String? = null
            try {
                sdkReport = RiskEngine.collectSync()
            } catch (t: Throwable) {
                sdkError = "${t.javaClass.simpleName}: ${t.message}"
            }
            val sdkCost = System.currentTimeMillis() - sdkT0

            // 3) 合并写一份 JSON(顶层两个键:ghost / riskengine_sdk)
            val combined = linkedMapOf<String, Any?>(
                "_meta" to linkedMapOf(
                    "session_id" to ghostReport.sessionId,
                    "timestamp" to ghostReport.timestamp,
                    "timestamp_human" to ghostReport.timestampHuman,
                    "device_label" to ghostReport.deviceLabel,
                    "ghost_cost_ms" to ghostCost,
                    "sdk_cost_ms" to sdkCost,
                    "sdk_error" to sdkError,
                ),
                "ghost" to ghostReport,
                "riskengine_sdk" to sdkReport,
            )
            val json = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
                .toJson(combined)
            val file = saveReport(json, ghostReport.timestampHuman)

            runOnUiThread {
                btnCollect.isEnabled = true
                lastReport = ghostReport
                lastSdkReport = sdkReport
                tvSummary.text = buildString {
                    append("✅ 采集完成\n")
                    append("ghost: ${ghostCost}ms / SDK: ${sdkCost}ms\n")
                    append("设备: ${ghostReport.deviceLabel}\n")
                    append("ghost 字段: ${ghostReport.fieldCount}, ❌不一致: ${ghostReport.inconsistentCount}\n")
                    if (sdkReport != null) {
                        append("SDK 风险等级: ${sdkReport.overallRiskLevel}, 分数: ${sdkReport.riskScore}/${sdkReport.maxRiskScore}\n")
                        append("SDK 检测: ⚠️${sdkReport.warningCount} / 🚨${sdkReport.dangerCount}\n")
                    } else {
                        append("⚠️ SDK 采集失败: $sdkError\n")
                    }
                    append("文件: ${file?.absolutePath ?: "<save failed>"}\n")
                }
                tvLog.text = formatSummary(ghostReport, sdkReport)
            }
        }
    }

    private fun saveReport(json: String, ts: String): File? {
        return try {
            val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "ghost_verify")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, "ghost_verify_${ts}.json")
            file.writeText(json)
            file
        } catch (t: Throwable) {
            // fallback 到 app 私有目录
            val dir = File(getExternalFilesDir(null), "ghost_verify")
            dir.mkdirs()
            val file = File(dir, "ghost_verify_${ts}.json")
            try {
                file.writeText(json)
                file
            } catch (e: Throwable) {
                null
            }
        }
    }

    private fun listReports() {
        val publicDir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "ghost_verify")
        val privateDir = File(getExternalFilesDir(null), "ghost_verify")
        val publicFiles: List<File> = publicDir.listFiles()?.toList() ?: emptyList()
        val privateFiles: List<File> = privateDir.listFiles()?.toList() ?: emptyList()
        val files: List<File> = (publicFiles + privateFiles)
            .filter { it.name.endsWith(".json") }
            .sortedByDescending { it.lastModified() }
        tvLog.text = if (files.isEmpty()) {
            "(还没有报告)"
        } else {
            files.joinToString("\n") { f ->
                val ts = SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(Date(f.lastModified()))
                "$ts  ${f.length() / 1024}K  ${f.absolutePath}"
            }
        }
        tvSummary.text = "${files.size} 份报告"
    }

    private fun clearReports() {
        var deleted = 0
        for (dir in listOf(
            File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "ghost_verify"),
            File(getExternalFilesDir(null), "ghost_verify"),
        )) {
            dir.listFiles()?.forEach { if (it.delete()) deleted++ }
        }
        tvSummary.text = "已删除 $deleted 份报告"
        tvLog.text = ""
    }

    /** 截断长字符串,>=maxLen 加省略号 */
    private fun trunc(s: String?, maxLen: Int = 100): String =
        s?.let { if (it.length > maxLen) it.take(maxLen) + "…" else it } ?: "<null>"

    /** 单个 field 渲染:✅/❌ name = value;不一致时展开各 source */
    private fun renderField(sb: StringBuilder, f: FieldResult, expandSources: Boolean) {
        val mark = if (f.consistent) "✅" else "❌"
        sb.append("  $mark ${f.name} = ${trunc(f.canonicalValue)}\n")
        if (expandSources || !f.consistent) {
            f.sources.forEach { s ->
                val sLabel = if (s.source.isNotEmpty()) " (${trunc(s.source, 40)})" else ""
                sb.append("      ${s.layer.padEnd(7)}$sLabel = ${trunc(s.value)}\n")
            }
        }
    }

    private fun formatSummary(
        report: CollectReport,
        sdkReport: com.wsttxm.riskenginesdk.model.RiskReport?,
    ): String {
        val sb = StringBuilder()

        // ==== Part 1: ghost-verify 字段 ====
        // viewMode 控制范围:0=全字段 / 1=只看不一致 / 2=只看 SDK(跳过 ghost)
        if (viewMode != 2) {
            val showAll = viewMode == 0
            val ghostFields = if (showAll) report.fields else report.fields.filter { !it.consistent }
            sb.append("==== Ghost-Verify ${if (showAll) "全字段" else "不一致字段"} ")
            sb.append("(${ghostFields.size}/${report.fieldCount},❌${report.inconsistentCount}) ====\n\n")

            if (ghostFields.isEmpty()) {
                sb.append("(无项符合 — 全部字段一致 ✅)\n\n")
            } else {
                // 按 category 分组,保留 collector 内顺序
                val grouped = LinkedHashMap<String, MutableList<FieldResult>>()
                ghostFields.forEach { grouped.getOrPut(it.category) { mutableListOf() }.add(it) }
                for ((cat, list) in grouped) {
                    val incons = list.count { !it.consistent }
                    sb.append("【${cat}】 ${list.size} 字段")
                    if (incons > 0) sb.append(" / ❌$incons")
                    sb.append("\n")
                    list.forEach { renderField(sb, it, expandSources = !showAll) }
                    sb.append("\n")
                }
            }
        }

        // ==== Part 2: RiskEngine SDK 检测 ====
        sb.append("==== RiskEngine SDK 检测 ====\n")
        if (sdkReport == null) {
            sb.append("(SDK 采集失败)\n")
        } else {
            sb.append("总分: ${sdkReport.riskScore}/${sdkReport.maxRiskScore}  ")
            sb.append("⚠️ ${sdkReport.warningCount}  🚨 ${sdkReport.dangerCount}  ")
            sb.append("等级: ${sdkReport.overallRiskLevel}\n\n")
            sdkReport.detections.forEach { det ->
                val icon = when (det.status.toString()) {
                    "DANGER" -> "🚨"
                    "WARNING" -> "⚠️"
                    "SAFE" -> "✅"
                    else -> "❓"
                }
                val ev = trunc(det.evidence, 150)
                sb.append("$icon [${det.detectorName}] ${det.status} - $ev\n")
            }
        }
        return sb.toString()
    }
}
