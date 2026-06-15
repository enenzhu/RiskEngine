package com.ghost.verify

import android.annotation.SuppressLint
import android.content.Context
import android.opengl.GLES10
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.DisplayMetrics
import android.view.WindowManager
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Ghost 一键新机 字段采集器 — 多路径交叉验证。
 *
 * 设计思路:对每个 ghost 改过的字段,提供 2-5 个独立采集路径:
 *   - Java 反射(Build.* / BuildConfig)
 *   - libc __system_property_get(NativeBridge)
 *   - getprop shell(Process.exec)
 *   - /proc 文件解析(native readFile)
 *   - 框架 API(Settings/PackageManager/TelephonyManager/DisplayMetrics/SensorManager)
 *   - EGL native(GLES native glGetString)
 *
 * 一致性: 同字段不同路径 value 集合去重后 ≤ 1 个就 consistent;否则就是 ghost spoof
 *         漏了某条路径,会在 JSON 报告里标 ❌。
 */
class GhostCollector(private val context: Context) {

    private val fields = mutableListOf<FieldResult>()

    fun collectAll(): CollectReport {
        fields.clear()

        // ============================================================
        // A. Build 类静态字段(ghost BuildHook 改的字段)
        // ============================================================
        category("build") {
            field("MANUFACTURER",
                "Build.MANUFACTURER" jLayer { Build.MANUFACTURER },
                "ro.product.manufacturer" nLayer { NativeBridge.getSystemProperty("ro.product.manufacturer") },
                "ro.product.system.manufacturer" nLayer { NativeBridge.getSystemProperty("ro.product.system.manufacturer") },
                "ro.product.vendor.manufacturer" nLayer { NativeBridge.getSystemProperty("ro.product.vendor.manufacturer") },
                "ro.product.odm.manufacturer" nLayer { NativeBridge.getSystemProperty("ro.product.odm.manufacturer") },
                "getprop ro.product.manufacturer" sLayer { getpropShell("ro.product.manufacturer") },
            )
            field("BRAND",
                "Build.BRAND" jLayer { Build.BRAND },
                "ro.product.brand" nLayer { NativeBridge.getSystemProperty("ro.product.brand") },
                "ro.product.system.brand" nLayer { NativeBridge.getSystemProperty("ro.product.system.brand") },
                "ro.product.vendor.brand" nLayer { NativeBridge.getSystemProperty("ro.product.vendor.brand") },
                "getprop ro.product.brand" sLayer { getpropShell("ro.product.brand") },
            )
            field("BOARD",
                "Build.BOARD" jLayer { Build.BOARD },
                "ro.product.board" nLayer { NativeBridge.getSystemProperty("ro.product.board") },
            )
            field("DEVICE",
                "Build.DEVICE" jLayer { Build.DEVICE },
                "ro.product.device" nLayer { NativeBridge.getSystemProperty("ro.product.device") },
                "ro.product.system.device" nLayer { NativeBridge.getSystemProperty("ro.product.system.device") },
                "ro.product.vendor.device" nLayer { NativeBridge.getSystemProperty("ro.product.vendor.device") },
            )
            field("MODEL",
                "Build.MODEL" jLayer { Build.MODEL },
                "ro.product.model" nLayer { NativeBridge.getSystemProperty("ro.product.model") },
                "ro.product.system.model" nLayer { NativeBridge.getSystemProperty("ro.product.system.model") },
                "ro.product.vendor.model" nLayer { NativeBridge.getSystemProperty("ro.product.vendor.model") },
            )
            field("PRODUCT",
                "Build.PRODUCT" jLayer { Build.PRODUCT },
                "ro.product.name" nLayer { NativeBridge.getSystemProperty("ro.product.name") },
            )
            field("HARDWARE",
                "Build.HARDWARE" jLayer { Build.HARDWARE },
                "ro.hardware" nLayer { NativeBridge.getSystemProperty("ro.hardware") },
                "ro.boot.hardware" nLayer { NativeBridge.getSystemProperty("ro.boot.hardware") },
            )
            field("SOC_MODEL",
                "Build.SOC_MODEL" jLayer { Build.SOC_MODEL },
                "ro.soc.model" nLayer { NativeBridge.getSystemProperty("ro.soc.model") },
            )
            field("SOC_MANUFACTURER",
                "Build.SOC_MANUFACTURER" jLayer { Build.SOC_MANUFACTURER },
                "ro.soc.manufacturer" nLayer { NativeBridge.getSystemProperty("ro.soc.manufacturer") },
            )
            field("FINGERPRINT",
                "Build.FINGERPRINT" jLayer { Build.FINGERPRINT },
                "ro.build.fingerprint" nLayer { NativeBridge.getSystemProperty("ro.build.fingerprint") },
                "ro.system.build.fingerprint" nLayer { NativeBridge.getSystemProperty("ro.system.build.fingerprint") },
                "ro.vendor.build.fingerprint" nLayer { NativeBridge.getSystemProperty("ro.vendor.build.fingerprint") },
                "ro.product.build.fingerprint" nLayer { NativeBridge.getSystemProperty("ro.product.build.fingerprint") },
                "ro.bootimage.build.fingerprint" nLayer { NativeBridge.getSystemProperty("ro.bootimage.build.fingerprint") },
            )
            field("HOST",
                "Build.HOST" jLayer { Build.HOST },
                "ro.build.host" nLayer { NativeBridge.getSystemProperty("ro.build.host") },
            )
            field("ID",
                "Build.ID" jLayer { Build.ID },
                "ro.build.id" nLayer { NativeBridge.getSystemProperty("ro.build.id") },
                "ro.system.build.id" nLayer { NativeBridge.getSystemProperty("ro.system.build.id") },
            )
            field("DISPLAY",
                "Build.DISPLAY" jLayer { Build.DISPLAY },
                "ro.build.display.id" nLayer { NativeBridge.getSystemProperty("ro.build.display.id") },
            )
            field("TIME",
                "Build.TIME" jLayer { Build.TIME.toString() },
                "ro.build.date.utc * 1000" nLayer {
                    NativeBridge.getSystemProperty("ro.build.date.utc")
                        .toLongOrNull()?.let { (it * 1000).toString() } ?: ""
                },
            )
            field("TYPE",
                "Build.TYPE" jLayer { Build.TYPE },
                "ro.build.type" nLayer { NativeBridge.getSystemProperty("ro.build.type") },
            )
            field("TAGS",
                "Build.TAGS" jLayer { Build.TAGS },
                "ro.build.tags" nLayer { NativeBridge.getSystemProperty("ro.build.tags") },
            )
            field("BOOTLOADER",
                "Build.BOOTLOADER" jLayer { Build.BOOTLOADER },
                "ro.bootloader" nLayer { NativeBridge.getSystemProperty("ro.bootloader") },
                "ro.boot.bootloader" nLayer { NativeBridge.getSystemProperty("ro.boot.bootloader") },
            )
            field("RADIO",
                "Build.RADIO" jLayer { Build.getRadioVersion() ?: Build.RADIO },
                "gsm.version.baseband" nLayer { NativeBridge.getSystemProperty("gsm.version.baseband") },
                "ro.build.expect.baseband" nLayer { NativeBridge.getSystemProperty("ro.build.expect.baseband") },
            )
            field("SERIAL",
                "Build.getSerial()" jLayer { reflectGetSerial() },
                "ro.serialno" nLayer { NativeBridge.getSystemProperty("ro.serialno") },
                "ro.boot.serialno" nLayer { NativeBridge.getSystemProperty("ro.boot.serialno") },
            )
            field("SKU",
                "Build.SKU" jLayer { Build.SKU },
                "ro.boot.hardware.sku" nLayer { NativeBridge.getSystemProperty("ro.boot.hardware.sku") },
                "ro.boot.product.hardware.sku" nLayer { NativeBridge.getSystemProperty("ro.boot.product.hardware.sku") },
                "ro.oem.key1" nLayer { NativeBridge.getSystemProperty("ro.oem.key1") },
            )
            field("ODM_SKU",
                "Build.ODM_SKU" jLayer { Build.ODM_SKU },
                "ro.boot.product.vendor.sku" nLayer { NativeBridge.getSystemProperty("ro.boot.product.vendor.sku") },
            )
            field("SUPPORTED_ABIS",
                "Build.SUPPORTED_ABIS" jLayer { Build.SUPPORTED_ABIS.joinToString(",") },
                "ro.product.cpu.abilist" nLayer { NativeBridge.getSystemProperty("ro.product.cpu.abilist") },
            )
        }

        // ============================================================
        // B. Build.VERSION
        // ============================================================
        category("version") {
            field("SDK_INT",
                "Build.VERSION.SDK_INT" jLayer { Build.VERSION.SDK_INT.toString() },
                "Build.VERSION.SDK" jLayer { Build.VERSION.SDK },
                "ro.build.version.sdk" nLayer { NativeBridge.getSystemProperty("ro.build.version.sdk") },
            )
            field("RELEASE",
                "Build.VERSION.RELEASE" jLayer { Build.VERSION.RELEASE },
                "ro.build.version.release" nLayer { NativeBridge.getSystemProperty("ro.build.version.release") },
                "ro.system.build.version.release" nLayer { NativeBridge.getSystemProperty("ro.system.build.version.release") },
            )
            field("INCREMENTAL",
                "Build.VERSION.INCREMENTAL" jLayer { Build.VERSION.INCREMENTAL },
                "ro.build.version.incremental" nLayer { NativeBridge.getSystemProperty("ro.build.version.incremental") },
            )
            field("SECURITY_PATCH",
                "Build.VERSION.SECURITY_PATCH" jLayer { Build.VERSION.SECURITY_PATCH },
                "ro.build.version.security_patch" nLayer { NativeBridge.getSystemProperty("ro.build.version.security_patch") },
            )
            field("CODENAME",
                "Build.VERSION.CODENAME" jLayer { Build.VERSION.CODENAME },
            )
            field("BASE_OS",
                "Build.VERSION.BASE_OS" jLayer { Build.VERSION.BASE_OS },
            )
        }

        // ============================================================
        // C. Settings(Secure/Global/System)
        // ============================================================
        category("settings") {
            field("ANDROID_ID",
                "Settings.Secure.ANDROID_ID" jLayer {
                    Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
                },
            )
            field("ADB_ENABLED",
                "Settings.Global.ADB_ENABLED" jLayer {
                    Settings.Global.getString(context.contentResolver, Settings.Global.ADB_ENABLED)
                },
            )
            field("DEVELOPMENT_SETTINGS_ENABLED",
                "Settings.Global" jLayer {
                    Settings.Global.getString(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
                },
            )
            field("SCREEN_BRIGHTNESS",
                "Settings.System" jLayer {
                    Settings.System.getString(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS)
                },
            )
        }

        // ============================================================
        // D. Display
        // ============================================================
        category("display") {
            field("resolution",
                "DisplayMetrics.{width,height}Pixels" jLayer {
                    val dm = DisplayMetrics()
                    @Suppress("DEPRECATION")
                    (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
                        .getRealMetrics(dm)
                    "${dm.heightPixels}x${dm.widthPixels}"
                },
            )
            // dpi 分层检查 — ghost 框架是 Option B 双 DPI 世界,Java 层故意保留真机值
            // 避免 density split / resource bucket 切换导致字体/控件观感异常(历史教训 commit 4af2565)
            // 拆成 3 个独立字段,每个有不同预期,不放一起做一致性检查
            field("dpi_app_resources_java",
                // Option B 设计:此值 = 真机原值,不应该 = spoof
                "DisplayMetrics.densityDpi" jLayer { context.resources.displayMetrics.densityDpi.toString() },
            )
            field("dpi_native_prop",
                // 风控 native 查这条,应该 = spoof 值
                "ro.sf.lcd_density" nLayer { NativeBridge.getSystemProperty("ro.sf.lcd_density") },
            )
            field("dpi_density_device_stable",
                // GMS 用的 static field
                "DisplayMetrics.DENSITY_DEVICE_STABLE" jLayer {
                    val f = Class.forName("android.util.DisplayMetrics").getDeclaredField("DENSITY_DEVICE_STABLE")
                    f.isAccessible = true
                    f.getInt(null).toString()
                },
            )
            // 跨字段 bucket 一致性:Java vs native dpi 是否跨 Android resource bucket
            // 跨 bucket = app UI 资源会加载错(xhdpi 屏拿 xxhdpi 资源),真正风险
            field("dpi_same_bucket_java_vs_native",
                "Java densityDpi vs ro.sf.lcd_density 同 bucket?" jLayer {
                    val javaDpi = context.resources.displayMetrics.densityDpi
                    val nativeDpi = NativeBridge.getSystemProperty("ro.sf.lcd_density").toIntOrNull() ?: javaDpi
                    val buckets = listOf(0, 160, 240, 320, 480, 640, 99999)
                    fun bucketIdx(d: Int) = buckets.indexOfFirst { d < it }
                    if (bucketIdx(javaDpi) == bucketIdx(nativeDpi)) "same_bucket($javaDpi/$nativeDpi)"
                    else "DIFFERENT_BUCKET(java=$javaDpi native=$nativeDpi)"
                },
            )
            field("display_info_cache_key",
                "cache_key.display_info" nLayer { NativeBridge.getSystemProperty("cache_key.display_info") },
            )
        }

        // ============================================================
        // E. uname + kernel
        // ============================================================
        category("kernel") {
            val uname = NativeBridge.getUname()
            field("uname.sysname",
                "native uname()" nLayer { uname.getOrNull(0) ?: "" },
                "/proc/sys/kernel/ostype" pLayer { NativeBridge.readFile("/proc/sys/kernel/ostype", 256).trim() },
            )
            field("uname.nodename",
                "native uname()" nLayer { uname.getOrNull(1) ?: "" },
                "/proc/sys/kernel/hostname" pLayer { NativeBridge.readFile("/proc/sys/kernel/hostname", 256).trim() },
            )
            field("uname.release",
                "native uname()" nLayer { uname.getOrNull(2) ?: "" },
                "/proc/sys/kernel/osrelease" pLayer { NativeBridge.readFile("/proc/sys/kernel/osrelease", 256).trim() },
                "ro.kernel.version" nLayer { NativeBridge.getSystemProperty("ro.kernel.version") },
                "System.getProperty('os.version')" jLayer { System.getProperty("os.version") ?: "" },
            )
            field("uname.version",
                "native uname()" nLayer { uname.getOrNull(3) ?: "" },
                "/proc/version" pLayer { NativeBridge.readFile("/proc/version", 512).trim() },
            )
            field("uname.machine",
                "native uname()" nLayer { uname.getOrNull(4) ?: "" },
                "os.arch" jLayer { System.getProperty("os.arch") ?: "" },
            )
            field("boot_id",
                "/proc/sys/kernel/random/boot_id" pLayer {
                    NativeBridge.readFile("/proc/sys/kernel/random/boot_id", 64).trim()
                },
            )
        }

        // ============================================================
        // F. CPU / Memory / Disk
        // ============================================================
        category("hw") {
            field("/proc/cpuinfo.Hardware",
                "proc cpuinfo" pLayer { extractProcLine("/proc/cpuinfo", "Hardware") },
            )
            field("/proc/cpuinfo.Processor",
                "proc cpuinfo" pLayer { extractProcLine("/proc/cpuinfo", "Processor") },
            )
            field("/proc/meminfo.MemTotal",
                "proc meminfo" pLayer { extractProcLine("/proc/meminfo", "MemTotal") },
            )
            field("cpu_freq_max",
                "scaling_max_freq" pLayer {
                    NativeBridge.readFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", 64).trim()
                },
            )
        }

        // ============================================================
        // G. GPU(Java GLES vs Native EGL)— Phase B GLESHook 影响
        // ============================================================
        category("gpu") {
            // Java 层 GLES10.glGetString 必须在有 GL context 才有意义,但 RiskEngine demo 没创建。
            // 我们用 native EGL 创建 pbuffer context 再 query。Java 层提供 GLES10 接口拿到的字符串
            // 实际上只能在 OpenGL view 渲染线程才返回真值,这里 native 是更可靠的路径。
            // 同时再尝试 Java 层 GLES10.glGetString,如有任何返回也记录(可能是空)。
            val gles = NativeBridge.getGlesStrings()
            field("GL_VENDOR",
                "native eglMakeCurrent + glGetString" nLayer { gles.getOrNull(0) ?: "" },
                "Java GLES10.glGetString(GL_VENDOR)" jLayer { javaGlGet(GLES10.GL_VENDOR) },
            )
            field("GL_RENDERER",
                "native EGL + glGetString" nLayer { gles.getOrNull(1) ?: "" },
                "Java GLES10.glGetString(GL_RENDERER)" jLayer { javaGlGet(GLES10.GL_RENDERER) },
            )
            field("GL_VERSION",
                "native EGL + glGetString" nLayer { gles.getOrNull(2) ?: "" },
                "Java GLES10.glGetString(GL_VERSION)" jLayer { javaGlGet(GLES10.GL_VERSION) },
            )
            field("GL_EXTENSIONS.length",
                "native EGL + glGetString" nLayer { (gles.getOrNull(3) ?: "").length.toString() },
                "Java GLES10.glGetString(GL_EXTENSIONS).length" jLayer {
                    (javaGlGet(GLES10.GL_EXTENSIONS) ?: "").length.toString()
                },
            )
            field("ro.hardware.egl",
                "ro.hardware.egl" nLayer { NativeBridge.getSystemProperty("ro.hardware.egl") },
            )
            field("ro.hardware.vulkan",
                "ro.hardware.vulkan" nLayer { NativeBridge.getSystemProperty("ro.hardware.vulkan") },
            )
        }

        // ============================================================
        // H. Telephony
        // ============================================================
        category("telephony") {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            field("simOperator",
                "TelephonyManager.simOperator" jLayer { tm?.simOperator ?: "" },
                "gsm.sim.operator.numeric" nLayer { NativeBridge.getSystemProperty("gsm.sim.operator.numeric") },
            )
            field("simOperatorName",
                "TelephonyManager.simOperatorName" jLayer { tm?.simOperatorName ?: "" },
                "gsm.sim.operator.alpha" nLayer { NativeBridge.getSystemProperty("gsm.sim.operator.alpha") },
            )
            field("simCountryIso",
                "TelephonyManager.simCountryIso" jLayer { tm?.simCountryIso ?: "" },
                "gsm.operator.iso-country" nLayer { NativeBridge.getSystemProperty("gsm.operator.iso-country") },
            )
            field("networkOperator",
                "TelephonyManager.networkOperator" jLayer { tm?.networkOperator ?: "" },
            )
            field("phoneType",
                "TelephonyManager.phoneType" jLayer { tm?.phoneType?.toString() ?: "" },
            )
        }

        // ============================================================
        // I. PackageManager features
        // ============================================================
        category("features") {
            val features = context.packageManager.systemAvailableFeatures
                .mapNotNull { it.name }
                .sorted()
            field("features.count",
                "PackageManager.getSystemAvailableFeatures.size" jLayer { features.size.toString() },
            )
            field("features.hash",
                "PackageManager features SHA1" jLayer {
                    sha1Hex(features.joinToString("\n"))
                },
            )
            // 几个 Pixel-only feature 单独检测(用于发现 Pixel 污染)
            for (name in listOf(
                "com.google.android.feature.PIXEL_2021_EXPERIENCE",
                "com.google.android.feature.PIXEL_EXPERIENCE",
                "com.google.android.feature.NEXT_GENERATION_ASSISTANT",
                "com.google.android.feature.GOOGLE_FI_BUNDLED",
                "com.google.android.feature.QUICK_TAP",
                "com.verizon.hardware.telephony.lte",
                "com.nxp.mifare",
            )) {
                field("has_feature.$name",
                    "PackageManager.hasSystemFeature" jLayer {
                        context.packageManager.hasSystemFeature(name).toString()
                    },
                )
            }
        }

        // ============================================================
        // J. Sensors / Time / Locale / 其他
        // ============================================================
        category("misc") {
            field("timezone",
                "TimeZone.getDefault().id" jLayer { TimeZone.getDefault().id },
                "persist.sys.timezone" nLayer { NativeBridge.getSystemProperty("persist.sys.timezone") },
            )
            field("locale",
                "Locale.getDefault().toLanguageTag()" jLayer { Locale.getDefault().toLanguageTag() },
                "persist.sys.locale" nLayer { NativeBridge.getSystemProperty("persist.sys.locale") },
            )
            field("ro.build.description",
                "ro.build.description" nLayer { NativeBridge.getSystemProperty("ro.build.description") },
            )
            field("ro.boot.boot_devices",
                "ro.boot.boot_devices" nLayer { NativeBridge.getSystemProperty("ro.boot.boot_devices") },
            )
            field("ro.boot.bootdevice",
                "ro.boot.bootdevice" nLayer { NativeBridge.getSystemProperty("ro.boot.bootdevice") },
            )
            field("ro.boot.vbmeta.digest",
                "ro.boot.vbmeta.digest" nLayer { NativeBridge.getSystemProperty("ro.boot.vbmeta.digest") },
            )
            field("ro.config.ringtone",
                "ro.config.ringtone" nLayer { NativeBridge.getSystemProperty("ro.config.ringtone") },
            )
        }

        // ============================================================
        // K. ghost modifySystemFile / addSystemFile 检测
        //    stat 几个 ghost 重定向的关键 SO,看 size/mtime 是否合理
        // ============================================================
        category("system-files") {
            for (path in listOf(
                "/system/lib64/libc.so",
                "/system/lib64/libart.so",
                "/system/lib64/libandroid.so",
                "/system/lib64/libandroid_runtime.so",
                "/system/framework/framework.jar",
                "/system/framework/services.jar",
                "/vendor/lib64/egl/libEGL_adreno.so",
            )) {
                field("stat $path",
                    "native stat()" nLayer { NativeBridge.statFile(path) },
                )
            }
        }

        // ============================================================
        // 收尾 — 构建 report
        // ============================================================
        val timestamp = System.currentTimeMillis()
        val ts = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date(timestamp))
        return CollectReport(
            timestamp = timestamp,
            timestampHuman = ts,
            sessionId = "${Build.SERIAL.take(6)}_$ts",
            deviceLabel = "${Build.MANUFACTURER}/${Build.MODEL} (${Build.DEVICE})",
            fieldCount = fields.size,
            inconsistentCount = fields.count { !it.consistent },
            fields = fields.toList()
        )
    }

    // ========================================================================
    // DSL helpers
    // ========================================================================
    private var currentCategory: String = "default"
    private fun category(name: String, block: () -> Unit) {
        currentCategory = name
        block()
    }

    private fun field(name: String, vararg sources: SourceValue) {
        fields.add(FieldResult.build(name, currentCategory, sources.toList()))
    }

    // infix helpers:" tag" jLayer { ... } → SourceValue
    private inline infix fun String.jLayer(crossinline block: () -> String?): SourceValue =
        safeCollect(this, "java", block)

    private inline infix fun String.nLayer(crossinline block: () -> String?): SourceValue =
        safeCollect(this, "native", block)

    private inline infix fun String.sLayer(crossinline block: () -> String?): SourceValue =
        safeCollect(this, "shell", block)

    private inline infix fun String.pLayer(crossinline block: () -> String?): SourceValue =
        safeCollect(this, "proc", block)

    private inline fun safeCollect(source: String, layer: String, block: () -> String?): SourceValue {
        return try {
            val v = block()
            SourceValue(source, layer, v?.ifEmpty { null })
        } catch (t: Throwable) {
            SourceValue(source, layer, null, error = t.javaClass.simpleName + ":" + t.message)
        }
    }

    // ========================================================================
    // Utility采集函数
    // ========================================================================
    private fun getpropShell(key: String): String {
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("getprop", key))
            BufferedReader(InputStreamReader(proc.inputStream)).use { it.readLine().orEmpty() }.trim()
        } catch (e: Throwable) {
            ""
        }
    }

    private fun extractProcLine(path: String, prefix: String): String {
        val content = NativeBridge.readFile(path, 16384)
        return content.lineSequence()
            .firstOrNull { it.trimStart().startsWith(prefix) }
            ?.substringAfter(":")
            ?.trim()
            ?: ""
    }

    @SuppressLint("HardwareIds")
    private fun reflectGetSerial(): String {
        return try {
            Build::class.java.getMethod("getSerial").invoke(null) as? String ?: ""
        } catch (e: Throwable) {
            try { Build.SERIAL } catch (e2: Throwable) { "" }
        }
    }

    /** Java GLES10.glGetString — 没 GL context 时返回 null,但仍然记录便于交叉验证。 */
    private fun javaGlGet(name: Int): String? {
        return try {
            GLES10.glGetString(name)
        } catch (t: Throwable) {
            null
        }
    }

    private fun sha1Hex(s: String): String {
        val md = java.security.MessageDigest.getInstance("SHA-1")
        return md.digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}
