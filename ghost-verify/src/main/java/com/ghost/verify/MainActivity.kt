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
    private lateinit var tvSummary: TextView
    private lateinit var tvLog: TextView

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
        tvSummary = TextView(this).apply {
            text = "等待采集..."
            textSize = 14f
            setPadding(0, 24, 0, 24)
        }
        tvLog = TextView(this).apply { textSize = 11f }
        val scroll = ScrollView(this).apply { addView(tvLog) }

        root.addView(btnCollect)
        root.addView(btnList)
        root.addView(btnClear)
        root.addView(tvSummary)
        root.addView(scroll)
        setContentView(root)

        ensureStoragePermission()

        btnCollect.setOnClickListener { runCollection() }
        btnList.setOnClickListener { listReports() }
        btnClear.setOnClickListener { clearReports() }
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

    private fun formatSummary(
        report: CollectReport,
        sdkReport: com.wsttxm.riskenginesdk.model.RiskReport?,
    ): String {
        val sb = StringBuilder()

        // ==== 部分 1:ghost-verify 不一致字段 ====
        sb.append("==== ghost 不一致字段(${report.inconsistentCount}/${report.fieldCount}) ====\n\n")
        for (field in report.fields) {
            if (!field.consistent) {
                sb.append("❌ [${field.category}] ${field.name}\n")
                field.sources.forEach { src ->
                    val v = src.value?.let { vv -> if (vv.length > 80) vv.take(80) + "…" else vv } ?: "<null>"
                    sb.append("    ${src.layer.padEnd(7)} ${src.source} = $v\n")
                }
                sb.append("\n")
            }
        }
        if (report.inconsistentCount == 0) sb.append("(全部字段一致 ✅)\n")

        // ==== 部分 2:关键字段速览 ====
        sb.append("\n==== 关键字段 ====\n")
        for (k in listOf("MANUFACTURER","BRAND","MODEL","DEVICE","SOC_MODEL","SOC_MANUFACTURER",
            "FINGERPRINT","SECURITY_PATCH","GL_RENDERER","GL_VENDOR","RADIO","BOOTLOADER")) {
            val f = report.fields.firstOrNull { it.name == k } ?: continue
            sb.append("[${if (f.consistent) "✅" else "❌"}] ${f.name} = ${f.canonicalValue ?: "<null>"}\n")
        }

        // ==== 部分 3:RiskEngine SDK 检测结果 ====
        sb.append("\n==== RiskEngine SDK 检测 ====\n")
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
                val ev = det.evidence?.let { e -> if (e.length > 100) e.take(100) + "…" else e } ?: ""
                sb.append("$icon [${det.detectorName}] ${det.status} - $ev\n")
            }
        }
        return sb.toString()
    }
}
