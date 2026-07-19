package com.ghost.verify

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.google.gson.GsonBuilder
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * App 列表机器可读导出 —— 把 verify 视角(第三方 caller,已被 ghost hook)读到的每个 app 的
 * install-time / installer / 签名 / 路径 / base.apk mtime 结构化落盘,方便 adb pull 后跨"一键新机"diff。
 *
 * ★同时内置反检测交叉校验(anomalies):把风控 SDK / AF 会抓的逻辑矛盾直接标出来,拉下文件即见,
 *   不用肉眼比对 —— 后续 referrer/归因对抗测试也在此累积字段。
 *   - lastUpdate < firstInstall(真机不可能)          ← P8 修复的正是这个
 *   - firstInstall / lastUpdate 在未来
 *   - base.apk mtime 与 firstInstall 明显不一致(stat sourceDir vs PM firstInstall,深探针穿帮)
 *   - 第三方 app 的 installer 不是 Play
 */
object AppListExport {

    private val FMT = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private const val PLAY = "com.android.vending"
    private const val DAY_MS = 86_400_000L
    // mtime 与 firstInstall 容差:> 1 天视为不一致(触发穿帮标记)
    private const val MTIME_TOLERANCE_MS = DAY_MS

    private fun fmt(ms: Long): String? = if (ms > 0) FMT.format(Date(ms)) else null

    /** 采集全量 app 列表为结构化 Map(可直接 Gson 序列化)。 */
    fun collect(context: Context, deviceModel: String?): Map<String, Any?> {
        val pm = context.packageManager
        val now = System.currentTimeMillis()
        val list = runCatching { pm.getInstalledPackages(0) }.getOrElse { emptyList() }

        val apps = list.mapNotNull { pi ->
            val ai = pi.applicationInfo ?: return@mapNotNull null
            val pkg = pi.packageName
            val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pkg)

            val src = runCatching { pm.getInstallSourceInfo(pkg) }.getOrNull()
            val sourceDir = ai.sourceDir
            // base.apk 物理 mtime(非 root 也能 stat,detector 就靠它 vs firstInstall 对账)
            val apkMtime = runCatching { File(sourceDir).lastModified() }.getOrDefault(0L)

            val first = pi.firstInstallTime
            val last = pi.lastUpdateTime

            val anomalies = mutableListOf<String>()
            if (last in 1 until first) anomalies += "lastUpdate_lt_firstInstall"
            if (first > now) anomalies += "firstInstall_in_future"
            if (last > now) anomalies += "lastUpdate_in_future"
            // ★物理不变量:base.apk 每次安装/更新都会被重写 → mtime 应 ≈ lastUpdate
            //   (实测真机 GMS/vending/chrome 的 apkMtime 皆 ≈ lastUpdate,与 firstInstall 差可达十余年)。
            //   spoof 时若只 touch mtime=firstInstall 而 lastUpdate>firstInstall,stat 探针即穿帮。
            if (apkMtime > 0 && last > 0 && Math.abs(apkMtime - last) > MTIME_TOLERANCE_MS) {
                anomalies += "apkMtime_lastUpdate_mismatch"
            }
            if (!system && src?.installingPackageName != null && src.installingPackageName != PLAY) {
                anomalies += "installer_not_play"
            }

            linkedMapOf<String, Any?>(
                "pkg" to pkg,
                "label" to label,
                "system" to system,
                "uid" to ai.uid,
                "versionName" to pi.versionName,
                "versionCode" to pi.longVersionCode,
                "firstInstall" to first,
                "firstInstallHuman" to fmt(first),
                "lastUpdate" to last,
                "lastUpdateHuman" to fmt(last),
                "installer" to src?.installingPackageName,
                "initiatingPkg" to src?.initiatingPackageName,
                "sourceDir" to sourceDir,
                "apkMtime" to apkMtime,
                "apkMtimeHuman" to fmt(apkMtime),
                "apkMtimeVsFirstInstallSec" to if (apkMtime > 0 && first > 0) (apkMtime - first) / 1000 else null,
                "minSdk" to ai.minSdkVersion,
                "targetSdk" to ai.targetSdkVersion,
                "signature" to sigHash(pm, pkg),
                "anomalies" to anomalies,
            )
        }.sortedWith(compareBy<Map<String, Any?>> { it["system"] as Boolean }
            .thenBy { (it["label"] as String).lowercase() })

        val thirdParty = apps.count { it["system"] == false }
        val withAnomaly = apps.filter { (it["anomalies"] as List<*>).isNotEmpty() }

        return linkedMapOf(
            "_meta" to linkedMapOf(
                "timestamp" to now,
                "timestampHuman" to FMT.format(Date(now)),
                "model" to deviceModel,
                "total" to apps.size,
                "thirdParty" to thirdParty,
                "system" to (apps.size - thirdParty),
                "anomalyCount" to withAnomaly.size,
                // 顶层汇总:哪些包有异常 + 什么异常,拉下文件一眼定位
                "anomalies" to withAnomaly.associate { it["pkg"] as String to it["anomalies"] },
            ),
            "apps" to apps,
        )
    }

    /** 采集并写入 Download/ghost_verify/applist_<ts>.json;失败回落 app 私有目录。返回落盘文件或 null。 */
    fun save(context: Context, deviceModel: String?, ts: String): File? {
        val json = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
            .toJson(collect(context, deviceModel))
        val name = "applist_${ts}.json"
        return runCatching {
            val dir = File(android.os.Environment.getExternalStoragePublicDirectory(
                android.os.Environment.DIRECTORY_DOWNLOADS), "ghost_verify")
            if (!dir.exists()) dir.mkdirs()
            File(dir, name).apply { writeText(json) }
        }.getOrElse {
            runCatching {
                val dir = File(context.getExternalFilesDir(null), "ghost_verify")
                dir.mkdirs()
                File(dir, name).apply { writeText(json) }
            }.getOrNull()
        }
    }

    /** 签名 SHA-256(前 16 hex);伪造/名级伪装包无签名 → <none>。 */
    private fun sigHash(pm: PackageManager, pkg: String): String = runCatching {
        val pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = pi.signingInfo?.apkContentsSigners
        if (signers.isNullOrEmpty()) "<none>"
        else {
            val md = MessageDigest.getInstance("SHA-256")
            signers.joinToString(", ") { s ->
                md.digest(s.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
            }
        }
    }.getOrElse { "<err:${it.javaClass.simpleName}>" }
}
