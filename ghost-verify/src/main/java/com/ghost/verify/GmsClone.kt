package com.ghost.verify

import android.content.Context
import android.net.Uri
import org.json.JSONObject
import java.io.File

/**
 * GMS 进程 clone 采集 —— 让 GMS 用自己的 hook 视角采一遍设备字段,作为测试基准。
 *
 * ghost 对普通 app 和 Google 进程(Beta 档案)给的 Build/native 视图不同:
 *   - 普通 app 看到虚拟机型;GMS/Play 看到 Google 兼容档案(Pixel),但两者共享同一物理运行时。
 * 同一个字段在两个进程里应当被同一套 hook 覆盖,分歧 = 某条 hook 只装了一边。本类把这些值
 * 作为报告里的 `gms.*` 基准字段,由 [CrossFieldChecker] 与 app 侧字段逐项比对。
 *
 * 机制:进程内 `contentResolver.query("content://com.ghost.call/collectClone?out=…")` 直连 provider
 * (ghost 的 isOperatorCaller 已放行 com.ghost.verify uid)。provider 发 CLONE_COLLECT 广播让 GMS
 * 进程内 ghost 的 Collector 采集,root 拷到本 app 私有目录。
 * ★不用 exec `content`:app uid 下 app_process 因 framework.jar 重定向起不来(RuntimeInit abort);也不走 su:
 *   app 的 mount namespace 里看不到任何 su 路径。
 * 输出含账号材料和 binding_key,只留在私有目录,不进报告正文。
 */
class GmsClone private constructor(
    private val root: JSONObject,
    val rawPath: String,
    val costMs: Long,
) {
    fun str(path: String): String? {
        return try {
            var cur: Any? = root
            for (seg in path.split('.')) {
                cur = (cur as? JSONObject)?.opt(seg) ?: return null
            }
            when (cur) {
                null, JSONObject.NULL -> null
                is String -> cur.takeIf { it.isNotEmpty() }
                else -> cur.toString()
            }
        } catch (_: Throwable) {
            null
        }
    }

    val processPkg: String? get() = str("processPkg")
    val processName: String? get() = str("processName")
    val collectedAt: Long? get() = str("collectedAt")?.toLongOrNull()

    companion object {
        private const val PROVIDER = "content://com.ghost.call/collectClone"

        fun collect(context: Context, timeoutMs: Long = 55_000): Pair<GmsClone?, String?> {
            val t0 = System.currentTimeMillis()
            val dir = File(context.filesDir, "gms_clone").apply { mkdirs() }
            dir.listFiles()?.sortedByDescending { it.lastModified() }?.drop(3)?.forEach { it.delete() }
            val out = File(dir, "clone_${System.currentTimeMillis()}.json")
            val queryUri = Uri.parse("$PROVIDER?out=${out.absolutePath}")
            val providerOut = try {
                val cur = context.contentResolver.query(queryUri, null, null, null, null)
                android.util.Log.i("GmsClone", "query cur=$cur cols=${cur?.columnNames?.joinToString()} count=${cur?.count} uid=${android.os.Process.myUid()}")
                cur?.use { if (it.moveToFirst()) it.getString(0) else "" } ?: ""
            } catch (t: Throwable) {
                android.util.Log.e("GmsClone", "query failed uri=$queryUri", t)
                return null to "provider 调用失败:${t.javaClass.simpleName}: ${t.message}"
            }
            // 成功返回落盘路径;失败返回 "clone 采集失败:…" 或 Unauthorized/System not ready
            val err = if (providerOut == out.absolutePath) null
            else "provider 拒绝:${providerOut.take(300)}"

            val deadline = System.currentTimeMillis() + timeoutMs
            while (!out.isFile && System.currentTimeMillis() < deadline) {
                Thread.sleep(300)
            }
            if (!out.isFile) return null to (err ?: "clone 产物未生成")
            val json = runCatching { out.readText() }.getOrNull()
            if (json.isNullOrBlank() || json.length < 100) return null to "clone 产物为空"
            val root = runCatching { JSONObject(json) }.getOrElse { return null to "clone JSON 解析失败" }
            val pkg = root.optString("processPkg")
            if (pkg.isNotEmpty() && !pkg.startsWith("com.google.android.gms")) {
                return null to "clone 进程不是 gms: $pkg"
            }
            // .unstable 装了 Play Integrity 档案,若采到它,gms.* 就不再是主进程的虚拟身份基准。
            val processName = root.optString("processName")
            if (processName.endsWith(".unstable") || processName.endsWith(":unstable")) {
                return null to "clone 进程是 unstable: $processName"
            }
            return GmsClone(root, out.absolutePath, System.currentTimeMillis() - t0) to null
        }
    }
}