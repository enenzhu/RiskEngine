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
        // ★RSA(no-op 加密):密文随备份走,还原后用当前设备 RSA 密钥解 == canary ?(老备份能解)
        val rsaCipherB64: String? = null,
        // ★EC(真签名):签名 + 原文随备份走;EC 是真密钥相关,还原后用当前 EC 公钥验签
        //   —— 同设备(确定性密钥)应验过;跨设备/新机(per-device 密钥)验不过=预期。
        val ecSignedData: String? = null,
        val ecSignatureB64: String? = null,
        // 聚集锚:公钥指纹(同设备 restore 应相同;跨新机应变=per-device 反聚集生效)
        val ecPubKeyHash: String? = null,
        val rsaPubKeyHash: String? = null,
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
        val rsaEnc = KeystoreCryptoProbe.rsaEncrypt(KeystoreCryptoProbe.CANARY)
        val ecSig = KeystoreCryptoProbe.ecSign(KeystoreCryptoProbe.CANARY)
        return Snapshot(
            report.deviceLabel, report.timestampHuman, f, apps,
            cryptoCipherHex = enc?.first, cryptoIvHex = enc?.second,
            rsaCipherB64 = rsaEnc,
            ecSignedData = if (ecSig != null) KeystoreCryptoProbe.CANARY else null,
            ecSignatureB64 = ecSig,
            ecPubKeyHash = KeystoreCryptoProbe.ecPubKeyHash(),
            rsaPubKeyHash = KeystoreCryptoProbe.rsaPubKeyHash(),
        )
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
        val crossDeviceDecrypt: String? = null,  // ★AES:用当前设备密钥解 baseline 密文:ok/fail/null(无 baseline 密文)
        val rsaCrossDecrypt: String? = null,     // ★RSA(no-op):同上
        val ecCrossVerify: String? = null,       // ★EC(真签名):用当前公钥验 baseline 签名
        val pubKeyDelta: String? = null,         // 公钥指纹 baseline vs current(same=同密钥 / diff=per-device 变了)
    ) {
        val ok: Boolean get() = hadBaseline && sameDeviceLabel && fieldMismatches.isEmpty() && appsMissing.isEmpty() && appsChanged.isEmpty()
        // 加解密结论(与身份/app 的 restore-diff 分开):AES+RSA 是 no-op 加密,必须 ok;EC 是真签名,不纳入硬性 ok。
        val cryptoOk: Boolean get() =
            (crossDeviceDecrypt?.startsWith("✅") != false) && (rsaCrossDecrypt?.startsWith("✅") != false)
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
        }.let { base ->
            val crypto = buildString {
                if (crossDeviceDecrypt != null) append("\n  🔐 AES 跨设备解密: $crossDeviceDecrypt")
                if (rsaCrossDecrypt != null)   append("\n  🔐 RSA 跨设备解密: $rsaCrossDecrypt")
                if (ecCrossVerify != null)     append("\n  ✍️ EC 跨设备验签: $ecCrossVerify")
                if (pubKeyDelta != null)       append("\n  🔑 公钥指纹: $pubKeyDelta")
            }
            base + crypto
        }
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
        // ★RSA(no-op 加密):与 AES 同理,密文与密钥值无关 → 老备份必须能解。
        val rsaXdev = baseline.rsaCipherB64?.let { c ->
            val dec = KeystoreCryptoProbe.rsaDecrypt(c)
            if (dec == KeystoreCryptoProbe.CANARY) "✅ ok(baseline RSA 密文用当前设备私钥解开=canary → 老备份能解)"
            else "❌ fail(解不出/不匹配:${dec ?: "null"})—— RSA no-op 断了,老备份加密数据解不开"
        }
        // ★EC(真签名,密钥相关):用当前 EC 公钥验 baseline 签名。按**公钥是否变了**判读(比设备标签准):
        //   - 验过 → EC 密钥与 baseline 相同,签名可移植。
        //   - 验不过 + 公钥变了 → 预期:EC 密钥变了(旧固定→新每设备派生 的转换,或跨新机),旧签名自然验不过;非加解密回归。
        //   - 验不过 + 公钥没变 → 真异常(公钥相同却验不过,疑签名/验签实现问题)。
        val ecKeyChanged = baseline.ecPubKeyHash != null && current.ecPubKeyHash != null &&
            baseline.ecPubKeyHash != current.ecPubKeyHash
        val ecX = if (baseline.ecSignatureB64 != null && baseline.ecSignedData != null) {
            val okv = KeystoreCryptoProbe.ecVerify(baseline.ecSignedData, baseline.ecSignatureB64)
            when {
                okv -> "✅ verify ok(旧签名用当前 EC 公钥验过 → EC 密钥与 baseline 相同,签名可移植)"
                ecKeyChanged -> "⚠ verify fail 且 EC 公钥已变 → **预期**(EC 是真签名;密钥旧固定→新每设备派生 或 跨新机 → 旧签名不可验;非加解密回归)"
                else -> "❌ verify fail 但 EC 公钥未变 → 异常(公钥相同却验不过,疑签名/验签实现问题)"
            }
        } else null
        // 公钥指纹对比(same=同一密钥;diff=密钥变了)。
        val pkDelta = if (baseline.ecPubKeyHash != null || baseline.rsaPubKeyHash != null) {
            fun d(name: String, b: String?, c: String?): String = when {
                b == null || c == null -> "$name=?(缺)"
                b == c -> "$name=same(${b.take(12)}…)"
                else -> "$name=DIFF(baseline ${b.take(12)}… vs current ${c.take(12)}…)"
            }
            d("ec", baseline.ecPubKeyHash, current.ecPubKeyHash) + " " +
                d("rsa", baseline.rsaPubKeyHash, current.rsaPubKeyHash)
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
            rsaCrossDecrypt = rsaXdev,
            ecCrossVerify = ecX,
            pubKeyDelta = pkDelta,
        )
    }
}
