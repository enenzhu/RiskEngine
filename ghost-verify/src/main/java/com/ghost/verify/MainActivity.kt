package com.ghost.verify

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.View
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
    private lateinit var sectionContainer: LinearLayout

    // 视图模式:0=全字段 / 1=只看不一致 / 2=只看 SDK 检测
    private var viewMode: Int = 0
    private var lastReport: CollectReport? = null
    private var lastSdkReport: com.wsttxm.riskenginesdk.model.RiskReport? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Theme.Material3 默认带 ActionBar(显示 "Ghost Verify" 标题),
        // 在 Android 16 + edge-to-edge 下它会盖住 LinearLayout 第一个 button → 按钮不可见
        supportActionBar?.hide()

        // 合成自检在 SDK 初始化、权限请求和采集器之前返回。
        if (intent?.getStringExtra("auto") == "selftest") {
            runReportSelfTest()
            return
        }

        if (intent?.getStringExtra("auto") == "restore-audit") {
            runRestoreAudit()
            return
        }

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
        // 分模块折叠容器(替代单块 tvLog 全 dump):每个 category 一个可折叠分区
        sectionContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val scroll = ScrollView(this).apply { addView(sectionContainer) }

        // 操作 button 横向一行,节省垂直空间
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnCollect, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f))
            addView(btnViewMode, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        val btnAppList = Button(this).apply { text = "App 列表" }
        val btnRow2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnList,  LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnClear, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnAppList, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        val btnProcessEnv = Button(this).apply { text = "进程环境观测" }
        btnProcessEnv.setOnClickListener {
            startActivity(android.content.Intent(this, ProcessEnvActivity::class.java))
        }
        root.addView(btnRow)
        root.addView(btnRow2)
        root.addView(btnProcessEnv)
        root.addView(tvSummary)
        root.addView(scroll)
        setContentView(root)

        ensureStoragePermission()

        btnCollect.setOnClickListener { runCollection() }
        btnList.setOnClickListener { listReports() }
        btnClear.setOnClickListener { clearReports() }
        btnAppList.setOnClickListener {
            startActivity(android.content.Intent(this, AppListActivity::class.java))
        }
        btnViewMode.setOnClickListener {
            viewMode = (viewMode + 1) % 3
            btnViewMode.text = when (viewMode) {
                0 -> "视图: 全字段"
                1 -> "视图: 只看不一致"
                else -> "视图: 只看 SDK"
            }
            // 重新渲染当前 report
            lastReport?.let { renderCollection(it, lastSdkReport) }
        }

        // ★headless 触发(脚本化备份/还原验证用):am start ... --es auto collect → 自动跑一次采集(含 restore-diff)。
        if (intent?.getStringExtra("auto") == "collect") {
            btnCollect.post { runCollection() }
        }
    }

    /** 恢复回归专用：不初始化 SDK、不读 GMS 账号或 SnapshotStore、不运行网络探针。 */
    private fun runRestoreAudit() {
        val status = TextView(this).apply { text = "恢复字段观测采集中..."; setPadding(32, 32, 32, 32) }
        setContentView(status)
        val runId = intent?.getStringExtra("audit_run_id").orEmpty()
        if (!runId.matches(Regex("[A-Za-z0-9_-]{1,80}"))) {
            status.text = "缺少合法 audit_run_id"
            android.util.Log.e("GhostVerifyRestore", "COLLECT_FAILED reason=invalid_run_id")
            return
        }
        thread {
            try {
                val dir = File(getExternalFilesDir(null) ?: filesDir, "restore_audit").apply { mkdirs() }
                val output = File(dir, "restore_audit_$runId.json")
                check(!output.exists()) { "run_id_reused" }
                val startedAt = System.currentTimeMillis()
                val before = restoreAuditState()
                val report = GhostCollector(applicationContext, restoreAuditOnly = true).collectAll()
                val after = restoreAuditState()
                val audit = RestoreAuditContext(runId, startedAt, System.currentTimeMillis(), before, after)
                val body = linkedMapOf(
                    "_meta" to mapOf("restore_audit" to audit),
                    "ghost" to report,
                )
                output.writeText(GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(body))
                android.util.Log.i("GhostVerifyRestore", "COLLECT_DONE path=${output.absolutePath} fields=${report.fieldCount}")
                runOnUiThread { status.text = "恢复字段观测已保存，待本地比较器审计。\n${output.absolutePath}" }
            } catch (_: Throwable) {
                android.util.Log.e("GhostVerifyRestore", "COLLECT_FAILED reason=collection_or_save_failed")
                runOnUiThread { status.text = "恢复字段观测失败（run ID 不得重复），不能作为回归通过证据。" }
            }
        }
    }

    private fun restoreAuditState(): RestoreAuditState {
        val process = android.app.Application.getProcessName()
        val roster = runCatching { GhostCall.raw(applicationContext, "getHookPkgs", emptyMap()) }.getOrNull()
        val response = GhostCall.query(applicationContext, "expectedEnv", mapOf("pkg" to packageName, "process" to process))
        return RestoreAuditState.fromResponses(roster, response, packageName, process)
    }

    private fun runReportSelfTest() {
        val context = ObservationContext(
            packageName = packageName,
            processName = android.app.Application.getProcessName(),
            uid = android.os.Process.myUid(),
            pid = android.os.Process.myPid(),
        )
        val result = ReportSelfTest.run(context)
        val json = GsonBuilder().setPrettyPrinting().create().toJson(result)
        val output = File(getExternalFilesDir(null) ?: filesDir, "report_selftest.json")
        val saveError = runCatching { output.writeText(json) }.exceptionOrNull()
        setContentView(ScrollView(this).apply {
            addView(TextView(this@MainActivity).apply {
                text = "报告合成自检: ${if (result.passed) "PASS" else "FAIL"}\n" +
                    "只验证报告格式与判定逻辑，不采集设备字段。\n" +
                    "${saveError?.let { "结果保存失败: ${it.message}" } ?: "文件: ${output.absolutePath}"}\n\n$json"
                setPadding(32, 32, 32, 32)
            })
        })
        android.util.Log.i("GhostVerifySelfTest",
            "passed=${result.passed} checks=${result.checks.size} saved=${saveError == null}")
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

        // Phase H runtime permissions:WiFi scan results 需要 location 危险权限
        // (Android 10+ 强制),其它 normal/signature 权限装包时给。
        val needed = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            for (perm in listOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
                Manifest.permission.READ_PHONE_STATE,
                Manifest.permission.CAMERA,
            )) {
                if (checkSelfPermission(perm) != PackageManager.PERMISSION_GRANTED) {
                    needed += perm
                }
            }
            if (needed.isNotEmpty()) {
                ActivityCompat.requestPermissions(this, needed.toTypedArray(), 2)
            }
        }
    }

    private fun runCollection() {
        tvSummary.text = "采集中..."
        btnCollect.isEnabled = false
        val collectionReferrer = referrer?.toString()
        val hasExplicitReferrer = intent?.hasExtra(Intent.EXTRA_REFERRER) == true ||
            intent?.hasExtra(Intent.EXTRA_REFERRER_NAME) == true
        thread {
            // 0) GMS 进程 clone 基准(Google 档案视角)。失败不阻断主采集,错误进 _meta。
            val gmsCloneT0 = System.currentTimeMillis()
            val (gmsClone, gmsCloneError) = GmsClone.collect(applicationContext)
            val gmsCloneCost = System.currentTimeMillis() - gmsCloneT0

            // 0.5) Ghost 给本进程的期望值(APP_VS_EXPECTED)。旧 Ghost → unsupported,不比较、不计风险。
            val myProcess = android.app.Application.getProcessName()
            val expectedResp = GhostCall.query(applicationContext,
                "expectedEnv", mapOf("pkg" to packageName, "process" to myProcess))
            val expectedEnv = (expectedResp as? GhostCallResult.Ok)?.let { ProcessEnvModel.parseExpected(it.body) }
            // GMS 主进程走的是 L1(Google 共享档案补丁),与虚拟设备本来就可以不同;单独取它的期望
            // SECURITY_PATCH,不然 GMS↔app 身份对比会把 L1 的正常差异报成串档。
            val gmsExpectedPatch = if (gmsClone != null) runCatching {
                val resp = GhostCall.query(applicationContext, "expectedEnv",
                    mapOf("pkg" to "com.google.android.gms", "process" to "com.google.android.gms"))
                (resp as? GhostCallResult.Ok)?.let { ProcessEnvModel.parseExpected(it.body).expected["build.securityPatch"] }
            }.getOrNull() else null
            val expectedStatus = when (expectedResp) {
                is GhostCallResult.Ok -> "ok layer=${expectedEnv?.layer} keys=${expectedEnv?.expected?.size}"
                is GhostCallResult.Unsupported -> "unsupported"
                is GhostCallResult.Failed -> "error: ${expectedResp.error}"
            }

            val t0 = System.currentTimeMillis()
            // 1) ghost-verify 自己的多路径一致性采集
            val ghostReport = GhostCollector(
                applicationContext,
                collectionReferrer,
                hasExplicitReferrer,
                gmsClone,
                expectedEnv?.expected,
                gmsExpectedPatch,
            ).collectAll()
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

            // 2.5) ★备份/还原验证:先读上次快照(可能是 restore 带回的 baseline),与本次 fresh 采集比对,再覆盖到私有目录。
            //   还原成功 ⇒ 当前设备身份字段 + app 列表 == baseline;任何 mismatch = 还原漏了该字段/app(或没还原到该设备)。
            val prevSnapshot = SnapshotStore.readPrevious(applicationContext)
            val appListMap = runCatching { AppListExport.collect(applicationContext, ghostReport.deviceLabel) }.getOrElse { emptyMap() }
            val curSnapshot = SnapshotStore.capture(ghostReport, appListMap)
            val restoreDiff = SnapshotStore.diff(prevSnapshot, curSnapshot)
            SnapshotStore.writeCurrent(applicationContext, curSnapshot)

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
                    "gms_clone_cost_ms" to gmsCloneCost,
                    "gms_clone_path" to gmsClone?.rawPath,
                    "gms_clone_error" to gmsCloneError,
                    // ok / unsupported(旧 Ghost) / error
                    "expected_env_status" to when (expectedResp) {
                        is GhostCallResult.Ok -> "ok"
                        is GhostCallResult.Unsupported -> "unsupported"
                        is GhostCallResult.Failed -> "error"
                    },
                    "expected_env_error" to (expectedResp as? GhostCallResult.Failed)?.error,
                    "expected_env_layer" to expectedEnv?.layer,
                    "expected_env_device_id" to expectedEnv?.deviceId,
                ),
                "ghost" to ghostReport,
                "riskengine_sdk" to sdkReport,
                "restore_diff" to restoreDiff,   // ★备份/还原验证:baseline(私有目录快照)vs 当前 fresh
            )
            val json = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
                .toJson(combined)
            val file = saveReport(json, ghostReport.timestampHuman)
            // ★同步落一份机器可读 app 列表(install-time / installer / 签名 / base.apk mtime + 反检测异常标记),
            //   与设备报告同一时间戳 → adb pull 后可跨"一键新机"关联 diff。
            val appListFile = AppListExport.save(applicationContext, ghostReport.deviceLabel, ghostReport.timestampHuman)

            runOnUiThread {
                btnCollect.isEnabled = true
                lastReport = ghostReport
                lastSdkReport = sdkReport
                val (hiRisk, lowRisk) = countRisk(ghostReport)
                tvSummary.text = buildString {
                    append("✅ 采集完成\n")
                    append("ghost: ${ghostCost}ms / SDK: ${sdkCost}ms\n")
                    append("设备: ${ghostReport.deviceLabel}\n")
                    ghostReport.observationContext?.let {
                        append("采集器: ${it.processName} / uid=${it.uid} / pid=${it.pid}\n")
                        append("来源范围: 采集器及子进程；不证明 GMS/DroidGuard 的实际采集或上传。\n")
                    }
                    append("ghost 字段: ${ghostReport.fieldCount}, 多源冲突: ${ghostReport.coverage.inconsistent}, 跨字段告警: ${ghostReport.crossFieldViolations.size}\n")
                    append("覆盖: 未采集 ${ghostReport.coverage.unavailable} / 单来源 ${ghostReport.coverage.singleSource} / 多源一致 ${ghostReport.coverage.consistent} / 权限不可采 ${ghostReport.coverage.permissionGated}\n")
                    append("Ghost 期望值: ${expectedStatus}\n")
                    append("字段风险: 🚨$hiRisk / ⚠$lowRisk\n")
                    append("聚集信号: ${ghostReport.clusteringSignals.count { it.available }}/${ghostReport.clusteringSignals.size} 可读\n")
                    if (sdkReport != null) {
                        append("SDK 风险等级: ${sdkReport.overallRiskLevel}, 分数: ${sdkReport.riskScore}/${sdkReport.maxRiskScore}\n")
                        append("SDK 检测: ⚠️${sdkReport.warningCount} / 🚨${sdkReport.dangerCount}\n")
                    } else {
                        append("⚠️ SDK 采集失败: $sdkError\n")
                    }
                    append("文件: ${file?.absolutePath ?: "<save failed>"}\n")
                    append("App列表: ${appListFile?.absolutePath ?: "<save failed>"}\n")
                    append("\n").append(restoreDiff.summary()).append("\n")   // ★备份/还原验证结果
                }
                renderCollection(ghostReport, sdkReport)
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
        showPlainText(if (files.isEmpty()) {
            "(还没有报告)"
        } else {
            files.joinToString("\n") { f ->
                val ts = SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(Date(f.lastModified()))
                "$ts  ${f.length() / 1024}K  ${f.absolutePath}"
            }
        })
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
        showPlainText("")
    }

    /** 截断长字符串,>=maxLen 加省略号 */
    private fun trunc(s: String?, maxLen: Int = 100): String =
        s?.let { if (it.length > maxLen) it.take(maxLen) + "…" else it } ?: "<null>"

    /**
     * 风险标记:把已知风险信号(VPN / proxy / hook / 缺锁屏 / 装黑产 app)从 ghost-verify
     * field value 解读出来。返回:
     *   "🚨 ..." 高风险(明确是 anchor / 工具特征)
     *   "⚠ ..."  中风险(可疑配置 / 测试机特征)
     *   null    无风险
     * 默认 ✅/❌ 只看 cross-source consistency 不够 — 例如 vpn_active=true 单 source 一致
     * 但显然是高风险,不该打 ✅。
     */
    private fun riskTag(f: FieldResult): String? {
        val v = f.canonicalValue ?: return null
        return when (f.name) {
            // === 网络异常(VPN/代理) ===
            "network.vpn_active" -> if (v == "true") "🚨 VPN 激活" else null
            "network.dns.via_vpn_or_proxy" ->
                if (v.startsWith("true")) "🚨 DNS 走 VPN/代理隧道" else null
            "network.proxy_host" -> if (v != "<none>") "🚨 HTTP 代理已设" else null
            // === Hook 框架检测 ===
            "magisk.detected","root.detected","frida.detected","xposed.detected",
            "lsposed.detected" -> if (v != "false") "🚨 ${f.name.substringBefore('.')} 检测到" else null
            "emulator.detected" -> if (v != "false") "🚨 模拟器" else null
            "anti_evasion.stacktrace_xposed","anti_evasion.pm_call_stack" ->
                if (v != "clean") "🚨 stack 含 hook 框架痕迹" else null
            "debugger.attached" -> if (v.contains("true")) "🚨 调试器附加" else null
            "selinux.mode" -> if (v != "enforcing" && v != "1") "🚨 SELinux 非 enforcing" else null
            // === 风控奇葩 ===
            "keyguard.is_secure" -> if (v == "false") "⚠ 未设锁屏密码" else null
            "build_prop.mtime_secure" ->
                if (!v.startsWith("secure=true")) "🚨 build.prop 被改" else null
            // app_market.packages 的 OEM 缺失判断交给已品牌感知的 applist.oem_store(这条品牌盲,
            //   对 Pixel/Sony/Nothing/AOSP 只有 Play 会误报)→ 不在这里打 risk。
            // major_apps.installtime 查的是国内 5 app(微信/QQ/支付宝/抖音/淘宝),境外 farming 机
            //   本就不装 → <none-installed> 是正常,不打 risk(需要时按 locale/SIM 门控再加回)。
            "wifi.surrounding_count" -> {
                val n = Regex("\\d+").find(v)?.value?.toIntOrNull()
                if (n != null && n <= 1) "⚠ WiFi 周围 SSID ≤ 1" else null
            }
            // === 黑产 app ===
            "app.has_loan","app.has_sms_bomber","app.has_location_spoof",
            "app.has_phone_changer","app.has_gambling","app.has_automation",
            "app.has_root_manager","app.has_hook_framework","app.has_vpn_proxy",
            "app.has_sniff_capture" ->
                if (v.startsWith("true")) "🚨 装了 ${f.name.removePrefix("app.has_")} 类 app" else null
            "app.sensitive_visible" -> {
                val n = Regex("^\\d+").find(v)?.value?.toIntOrNull() ?: 0
                if (n > 0) "🚨 整机敏感 app 暴露 $n 个" else null
            }
            // === 环境暴露面 ===
            "env.su_paths" -> {
                val n = Regex("exposed=(\\d+)").find(v)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                if (n > 0) "🚨 su 路径可被 app 视角探测到 $n 个" else null
            }
            "env.su_command_path" ->
                // "su not found" 是 mksh `type su` 内建的干净输出(打到 stdout,没被 2>/dev/null 吃),
                // 不是找到了 su → 只有值里含真实路径(有 '/')且不含 "not found" 才算真找到。
                if (v.contains("/") && !v.contains("not found", ignoreCase = true))
                    "🚨 command/which 能找到 su" else null
            "env.root_artifact_paths" -> {
                val n = Regex("exposed=(\\d+)").find(v)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                if (n > 0) "🚨 Root/module 路径可被 app 视角探测到 $n 个" else null
            }
            "env.data_adb_listing" -> when {
                v.contains("Permission denied", ignoreCase = true) -> null
                v.contains("No such file", ignoreCase = true) -> null
                v == "<empty>" -> null
                else -> "🚨 /data/adb 目录信息可见"
            }
            "env.proc_maps_keywords",
            "env.proc_smaps_keywords",
            "env.proc_mountinfo_keywords",
            "env.proc_fd_keywords",
            "env.proc_other_process_keywords",
            "env.cmd_package_list_sensitive",
            "env.getprop_root_keywords" ->
                if (v != "clean") "🚨 ${f.name.removePrefix("env.")} 含 Root/Hook/工具关键词" else null
            "env.cmd_service_list" -> when {
                v == "clean" || v == "clean(empty)" -> null
                else -> "⚠ service list 可读取敏感服务名"
            }
            "env.settings_tooling_keys" ->
                if (v.startsWith("clean").not() && Regex("auto|nb4a|nekobox|kitsunebi|tt\\.hi|lsposed|xposed|reqable", RegexOption.IGNORE_CASE).containsMatchIn(v))
                    "🚨 Settings 暴露工具/无障碍/VPN 包名"
                else null
            "env.pms_direct_sensitive_pkgs" ->
                if (v != "clean") "🚨 direct getPackageInfo 能看到敏感包" else null
            // === 云真机桌面暴露面 ===
            "cloud.home_resolved" -> when {
                v.contains("com.tt.hi") -> "🚨 默认 HOME 暴露 Ghost"
                v == "<none>" -> "⚠ 默认 HOME 无法解析"
                else -> null
            }
            "cloud.home_candidates" ->
                if (v.contains("com.tt.hi")) "🚨 HOME 枚举暴露 Ghost" else null
            "cloud.ghost_package_visible" ->
                if (v == "true") "🚨 PackageManager 可直接看到 Ghost" else null
            "cloud.launch_referrer" ->
                if (v.contains("com.tt.hi")) "🚨 Activity referrer 暴露 Ghost" else null
            "cloud.launch_identity_consistency" ->
                if (v.startsWith("MISMATCH")) "🚨 启动来源与目标 App 所见 HOME 不一致" else null
            // === 安装列表 spoof 攻防面板 ===
            "applist.brand_match" ->
                if (v.startsWith("MISSING")) "🚨 品牌不符:列表无 OEM 包" else null
            "applist.oem_store" -> when {
                v.startsWith("MISMATCH") -> "🚨 OEM 商店伪造穿帮(在列表但解析不到)"
                v.startsWith("MISSING") -> "⚠ 缺 OEM 应用商店"
                else -> null
            }
            "applist.ghost_pkgs" -> {
                val n = Regex("^\\d+").find(v)?.value?.toIntOrNull() ?: 0
                if (n > 0) "🚨 $n 个伪造包被交叉校验隔离(无 launcher+无签名)" else null
            }
            "applist.nosig_count" -> {
                val n = Regex("^\\d+").find(v)?.value?.toIntOrNull() ?: 0
                if (n > 0) "🚨 $n 个包无签名(签名探针可抓伪造)" else null
            }
            "applist.vector_delta" -> {
                val nums = Regex("\\d+").findAll(v).map { it.value.toInt() }.toList()
                if (nums.any { it > 5 }) "⚠ 跨枚举路径差异大(某路径漏伪造)" else null
            }
            "applist.count_multi" -> {
                val nums = Regex("\\d+").findAll(v).map { it.value.toInt() }.toList()
                when {
                    nums.isEmpty() -> null
                    nums.min() < 20 -> "⚠ 安装列表过短(<20,不像真机)"
                    nums.max() > 700 -> "⚠ 安装列表过长(>700)"
                    else -> null
                }
            }
            else -> null
        }
    }

    /** 单个 field 渲染:🚨/⚠/❌/✅ + name + value;risk/不一致 时展开各 source */
    private fun renderField(sb: StringBuilder, f: FieldResult, expandSources: Boolean) {
        val risk = riskTag(f)
        val mark = when {
            risk?.startsWith("🚨") == true -> "🚨"
            risk?.startsWith("⚠") == true -> "⚠ "
            f.comparisonStatus == ComparisonStatus.UNAVAILABLE -> "❔"
            f.comparisonStatus == ComparisonStatus.SINGLE_SOURCE -> "▫"
            !f.consistent -> "❌"
            else -> "✅"
        }
        sb.append("  $mark ${f.name} = ${trunc(f.canonicalValue)} [${f.comparisonStatus}; ${f.validSourceCount}/${f.sources.size} 来源]")
        if (risk != null) sb.append("  ← $risk")
        sb.append("\n")
        if (expandSources || !f.consistent || risk != null) {
            f.sources.forEach { s ->
                val sLabel = if (s.source.isNotEmpty()) " (${trunc(s.source, 40)})" else ""
                sb.append("      ${s.layer.padEnd(7)}$sLabel = ${trunc(s.value)}\n")
            }
        }
    }

    private fun countRisk(report: CollectReport): Pair<Int, Int> {
        var hi = 0; var lo = 0
        for (f in report.fields) {
            val r = riskTag(f) ?: continue
            if (r.startsWith("🚨")) hi++ else if (r.startsWith("⚠")) lo++
        }
        for (violation in report.crossFieldViolations) {
            // info 级只是说明(如 unstable 未运行),不计风险。
            when (violation.severity) {
                "high" -> hi++
                "info" -> {}
                else -> lo++
            }
        }
        return hi to lo
    }

    /**
     * 分模块渲染:每个 category 一个可折叠分区(默认收起,header 显示状态摘要;有 🚨 的自动展开)。
     * viewMode:0=全字段 / 1=只看不一致 / 2=只看 SDK(跳过 ghost)。
     */
    private fun renderCollection(
        report: CollectReport,
        sdkReport: com.wsttxm.riskenginesdk.model.RiskReport?,
    ) {
        sectionContainer.removeAllViews()

        // ==== Part 1: ghost-verify 字段,按 category 分模块折叠 ====
        if (viewMode != 2) {
            val showAll = viewMode == 0
            val ghostFields = if (showAll) report.fields else report.fields.filter { !it.consistent }
            if (ghostFields.isEmpty()) {
                addSection("Ghost-Verify(无多源冲突)", "未采集和单来源见覆盖汇总，不代表已验证通过；跨字段告警单独列出", expanded = false)
            } else {
                val grouped = LinkedHashMap<String, MutableList<FieldResult>>()
                ghostFields.forEach { grouped.getOrPut(it.category) { mutableListOf() }.add(it) }
                for ((cat, list) in grouped) {
                    var hi = 0; var lo = 0; var incons = 0
                    list.forEach { f ->
                        val r = riskTag(f)
                        if (r?.startsWith("🚨") == true) hi++ else if (r?.startsWith("⚠") == true) lo++
                        if (!f.consistent) incons++
                    }
                    val statusMark = if (hi > 0) "🚨" else if (lo > 0 || incons > 0) "⚠" else if (list.any { it.comparisonStatus != ComparisonStatus.CONSISTENT }) "▫" else "✅"
                    val header = buildString {
                        append("$statusMark 【$cat】 ${list.size}")
                        if (hi > 0) append("  🚨$hi")
                        if (lo > 0) append("  ⚠$lo")
                        if (incons > 0) append("  ❌$incons")
                    }
                    val body = StringBuilder()
                    list.forEach { renderField(body, it, expandSources = !showAll) }
                    // 有高危的模块默认展开,其余收起 → 一屏先看模块状态,问题模块直接可见
                    addSection(header, body.toString().trimEnd('\n'), expanded = hi > 0)
                }
            }

            if (report.crossFieldViolations.isNotEmpty()) {
                val high = report.crossFieldViolations.count { it.severity == "high" }
                val body = report.crossFieldViolations.joinToString("\n\n") { violation ->
                    buildString {
                        append(when (violation.severity) { "high" -> "🚨 "; "info" -> "ℹ "; else -> "⚠ " })
                        append(violation.ruleName).append("\n")
                        append("  实际: ").append(violation.values.entries.joinToString { (name, value) ->
                            "$name=${trunc(value, 80)}"
                        }).append("\n")
                        append("  期望: ").append(violation.expected)
                        if (violation.note.isNotBlank()) append("\n  说明: ").append(violation.note)
                    }
                }
                val mark = if (high > 0) "🚨" else "⚠"
                addSection(
                    "$mark 【跨字段风控规则】 ${report.crossFieldViolations.size}  🚨$high",
                    body,
                    expanded = high > 0,
                )
            }
        }

        // ==== Part 2: RiskEngine SDK 检测(单独一个可折叠分区)====
        if (sdkReport == null) {
            addSection("⚠ 【RiskEngine SDK】 采集失败", "(SDK 采集失败)", expanded = false)
        } else {
            val mark = if (sdkReport.dangerCount > 0) "🚨" else if (sdkReport.warningCount > 0) "⚠" else "✅"
            val header = "$mark 【RiskEngine SDK】 ${sdkReport.overallRiskLevel} " +
                    "${sdkReport.riskScore}/${sdkReport.maxRiskScore}  🚨${sdkReport.dangerCount} ⚠${sdkReport.warningCount}"
            val body = StringBuilder()
            sdkReport.detections.forEach { det ->
                val icon = when (det.status.toString()) {
                    "DANGER" -> "🚨"; "WARNING" -> "⚠️"; "SAFE" -> "✅"; else -> "❓"
                }
                body.append("$icon [${det.detectorName}] ${det.status} - ${trunc(det.evidence, 150)}\n")
            }
            addSection(header, body.toString().trimEnd('\n'), expanded = sdkReport.dangerCount > 0)
        }
    }

    /** 往容器加一个可折叠分区:header 可点击展开/收起 body。 */
    private fun addSection(header: String, body: String, expanded: Boolean) {
        val headerTv = TextView(this).apply {
            textSize = 13f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setPadding(0, 20, 0, 8)
        }
        val bodyTv = TextView(this).apply {
            text = body
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(8, 0, 0, 8)
            visibility = if (expanded) View.VISIBLE else View.GONE
        }
        fun updateHeader(exp: Boolean) { headerTv.text = (if (exp) "▼ " else "▶ ") + header }
        updateHeader(expanded)
        headerTv.setOnClickListener {
            val show = bodyTv.visibility != View.VISIBLE
            bodyTv.visibility = if (show) View.VISIBLE else View.GONE
            updateHeader(show)
        }
        sectionContainer.addView(headerTv)
        sectionContainer.addView(bodyTv)
    }

    /** 列表/清空等纯文本输出:清容器放一块可选文本。 */
    private fun showPlainText(text: String) {
        sectionContainer.removeAllViews()
        sectionContainer.addView(TextView(this).apply {
            this.text = text
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
        })
    }
}
