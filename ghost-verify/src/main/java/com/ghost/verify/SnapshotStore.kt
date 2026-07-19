package com.ghost.verify

import android.content.Context
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.io.File

/**
 * ★备份/还原验证:把采集到的设备身份指纹 + app 列表缓存到 **app 内部私有目录**(/data/data/com.ghost.verify/files/)。
 * 这个目录正是 ghost per-app 备份 tar 抓取的目标 → 快照随备份走、随还原回。
 *
 * 用法(restore-diff):每次采集时**先读**已存在的快照(baseline,可能是刚 restore 带回来的),与当前 fresh 采集比对:
 *   还原成功 ⇒ 当前设备 == 备份时快照(身份字段 + app 列表一致);任何 mismatch = 还原漏了该字段/app。
 * 比对完再用当前覆盖,供下次用。
 *
 * 为何用 filesDir 而非 Download/getExternalFilesDir:只有内部 /data/data/<pkg> 会进 per-app 备份 tar;
 * 外部存储(/sdcard)由 device-env clear 处理、不在 per-app tar 里。
 */
object SnapshotStore {

    private const val FILE = "ghost_snapshot.json"
    private val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

    /** 定义设备身份的**稳定字段**(还原后必须逐一相等;易变字段如 uptime/battery/时间不纳入)。 */
    private val IDENTITY_FIELDS = setOf(
        // build
        "MANUFACTURER", "BRAND", "MODEL", "DEVICE", "PRODUCT", "BOARD", "HARDWARE",
        "FINGERPRINT", "SOC_MODEL", "SOC_MANUFACTURER",
        "MARKETNAME_VIVO", "MARKETNAME_XIAOMI", "MARKETNAME_SAMSUNG",
        // version
        "SDK_INT", "RELEASE", "SECURITY_PATCH",
        // display
        "resolution", "dpi_app_resources_java",
        // telephony(SIM 身份)
        "simCountryIso", "simOperator", "simOperatorName", "networkOperator",
        // 设备 ID
        "GAID (Google Advertising ID)", "GSF Android ID", "Widevine.deviceUniqueId",
        "Settings.Secure.ANDROID_ID", "android_id",
        // TEE attestation Build IDs(还原后应仍一致)
        "tee.id.brand vs Build.BRAND", "tee.id.model vs Build.MODEL",
        // locale/tz
        "Locale", "TimeZone", "persist.sys.locale", "persist.sys.timezone",
    )

    data class Snapshot(
        val deviceLabel: String,
        val timestampHuman: String,
        val fields: Map<String, String?>,     // 身份字段 canonical value
        val apps: Map<String, String>,        // pkg → "firstInstall|lastUpdate|apkMtime"
        val cryptoCipherHex: String? = null,  // ★Keystore AES/GCM(canary) 密文(随备份走 → 还原后用当前密钥解 = 跨设备解密测试)
        val cryptoIvHex: String? = null,
    )

    /** 从采集报告 + app 列表抽出快照(身份字段 + app 时间三元组 + Keystore 跨设备解密密文)。 */
    fun capture(report: CollectReport, appList: Map<String, Any?>): Snapshot {
        val f = report.fields
            .filter { it.name in IDENTITY_FIELDS }
            .associate { it.name to it.canonicalValue }
        val apps = LinkedHashMap<String, String>()
        @Suppress("UNCHECKED_CAST")
        (appList["apps"] as? List<Map<String, Any?>>)?.forEach { a ->
            val pkg = a["pkg"] as? String ?: return@forEach
            apps[pkg] = "${a["firstInstall"]}|${a["lastUpdate"]}|${a["apkMtime"]}"
        }
        val enc = KeystoreCryptoProbe.encrypt(KeystoreCryptoProbe.CANARY)
        return Snapshot(report.deviceLabel, report.timestampHuman, f, apps, enc?.first, enc?.second)
    }

    private fun file(context: Context) = File(context.filesDir, FILE)

    /** 读上一份快照(可能是 restore 带回来的 baseline);无则 null。 */
    fun readPrevious(context: Context): Snapshot? = runCatching {
        val fl = file(context)
        if (!fl.exists()) return null
        gson.fromJson(fl.readText(), object : TypeToken<Snapshot>() {}.type) as Snapshot
    }.getOrNull()

    /** 写当前快照到私有目录(覆盖)。 */
    fun writeCurrent(context: Context, snapshot: Snapshot): Boolean = runCatching {
        file(context).writeText(gson.toJson(snapshot)); true
    }.getOrElse { false }

    data class RestoreDiff(
        val hadBaseline: Boolean,
        val baselineLabel: String?,
        val baselineTime: String?,
        val sameDeviceLabel: Boolean,
        val fieldMismatches: List<String>,   // "name: baseline=X vs current=Y"
        val appsMissing: List<String>,       // 备份时有、现在没有(还原漏装/漏记录)
        val appsChanged: List<String>,       // 时间三元组变了(installTime/mtime 没还原对 → 归因穿帮)
        val crossDeviceDecrypt: String? = null,  // ★用当前设备密钥解 baseline 密文:ok/fail/null(无 baseline 密文)
    ) {
        val ok: Boolean get() = hadBaseline && sameDeviceLabel && fieldMismatches.isEmpty() && appsMissing.isEmpty() && appsChanged.isEmpty()
        fun summary(): String = when {
            !hadBaseline -> "restore-diff: 无 baseline 快照(首次采集,已写入;备份→还原后再采即可验证)"
            ok -> "✅ restore-diff: 当前设备 == baseline 快照($baselineLabel @$baselineTime)—— 身份字段 + app 列表全一致,还原成功"
            else -> buildString {
                append("❌ restore-diff vs baseline($baselineLabel @$baselineTime):\n")
                if (!sameDeviceLabel) append("  ⚠ 设备标签不同(可能没还原到该设备)\n")
                if (fieldMismatches.isNotEmpty()) append("  身份字段不一致(${fieldMismatches.size}):\n${fieldMismatches.joinToString("\n"){ "    - $it" }}\n")
                if (appsMissing.isNotEmpty()) append("  还原后缺失的 app(${appsMissing.size}): ${appsMissing.take(20)}\n")
                if (appsChanged.isNotEmpty()) append("  app 时间三元组变了(installTime/mtime 没还原对=归因穿帮风险)(${appsChanged.size}): ${appsChanged.take(20)}\n")
            }
        }.let { base -> if (crossDeviceDecrypt != null) "$base\n  🔐 Keystore 跨设备解密: $crossDeviceDecrypt" else base }
    }

    /** baseline(上次/还原带回)vs current(本次 fresh)对比。 */
    fun diff(baseline: Snapshot?, current: Snapshot): RestoreDiff {
        if (baseline == null) return RestoreDiff(false, null, null, false, emptyList(), emptyList(), emptyList())
        val fieldMismatches = mutableListOf<String>()
        val allFieldNames = (baseline.fields.keys + current.fields.keys)
        for (n in allFieldNames) {
            val b = baseline.fields[n]; val c = current.fields[n]
            if (b != c && !(b.isNullOrEmpty() && c.isNullOrEmpty())) fieldMismatches += "$n: baseline=$b vs current=$c"
        }
        val appsMissing = baseline.apps.keys.filter { it !in current.apps }
        val appsChanged = baseline.apps.keys.filter { it in current.apps && baseline.apps[it] != current.apps[it] }
        // ★跨设备解密:用**当前设备**的 Keystore 密钥解 baseline(可能是还原带回的)密文 → ==canary?
        //   ok = ghost 常量 seed 让密钥跨设备一致 → farm app 加密 token 扛过备份/还原;fail = 密钥没移植,会丢加密数据。
        val xdev = if (baseline.cryptoCipherHex != null && baseline.cryptoIvHex != null) {
            val dec = KeystoreCryptoProbe.decrypt(baseline.cryptoCipherHex, baseline.cryptoIvHex)
            if (dec == KeystoreCryptoProbe.CANARY) "✅ ok(baseline 密文用当前设备密钥解开=canary,跨设备解密成功→加密数据可移植)"
            else "❌ fail(解不出/不匹配:${dec ?: "null"})—— Keystore 密钥没跨设备移植,farm app 会丢加密 token/登录态"
        } else null
        return RestoreDiff(
            hadBaseline = true,
            baselineLabel = baseline.deviceLabel,
            baselineTime = baseline.timestampHuman,
            sameDeviceLabel = baseline.deviceLabel == current.deviceLabel,
            fieldMismatches = fieldMismatches,
            appsMissing = appsMissing,
            appsChanged = appsChanged,
            crossDeviceDecrypt = xdev,
        )
    }
}
