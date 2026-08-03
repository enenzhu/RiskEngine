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
class GhostCollector(
    private val context: Context,
    private val launchReferrer: String? = null,
    private val launchReferrerExplicit: Boolean = false,
) {

    private val fields = mutableListOf<FieldResult>()

    fun collectAll(): CollectReport {
        fields.clear()
        // KeystoreCryptoProbe 的 RSA(KeyPairGeneratorSpec)需要 Context;在任何探针调用前注入。
        KeystoreCryptoProbe.appContext = context.applicationContext

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
            // === Marketing Name (营销名) — OEM 私有 sysprop ===
            // ghost 一键新机时按 manufacturer 设当前 OEM 的 marketname,屏蔽其他 OEM 的。
            // 风控点:多 OEM key 必须满足"当前 OEM 对应 key 非空 + 其他 OEM key 都空"。
            // 物理机自带 key(例物理 vivo 真机 ro.vivo.product.marketname)若未被屏蔽 = 反向暴露。
            field("MARKETNAME_VIVO",
                "ro.vivo.product.marketname" nLayer { NativeBridge.getSystemProperty("ro.vivo.product.marketname") },
                "ro.product.vivo.marketname" nLayer { NativeBridge.getSystemProperty("ro.product.vivo.marketname") },
                "SystemProperties.get(ro.vivo.product.marketname)" jLayer {
                    runCatching {
                        val cls = Class.forName("android.os.SystemProperties")
                        cls.getMethod("get", String::class.java).invoke(null, "ro.vivo.product.marketname") as String
                    }.getOrNull()
                },
                "getprop ro.vivo.product.marketname" sLayer { getpropShell("ro.vivo.product.marketname") },
            )
            field("MARKETNAME_XIAOMI",
                "ro.product.marketname" nLayer { NativeBridge.getSystemProperty("ro.product.marketname") },
                "SystemProperties.get(ro.product.marketname)" jLayer {
                    runCatching {
                        val cls = Class.forName("android.os.SystemProperties")
                        cls.getMethod("get", String::class.java).invoke(null, "ro.product.marketname") as String
                    }.getOrNull()
                },
                "getprop ro.product.marketname" sLayer { getpropShell("ro.product.marketname") },
            )
            field("MARKETNAME_SAMSUNG",
                "ro.product.model_marketing" nLayer { NativeBridge.getSystemProperty("ro.product.model_marketing") },
                "SystemProperties.get(ro.product.model_marketing)" jLayer {
                    runCatching {
                        val cls = Class.forName("android.os.SystemProperties")
                        cls.getMethod("get", String::class.java).invoke(null, "ro.product.model_marketing") as String
                    }.getOrNull()
                },
                "getprop ro.product.model_marketing" sLayer { getpropShell("ro.product.model_marketing") },
            )
            field("MARKETNAME_HUAWEI",
                "ro.config.marketing_name" nLayer { NativeBridge.getSystemProperty("ro.config.marketing_name") },
                "getprop ro.config.marketing_name" sLayer { getpropShell("ro.config.marketing_name") },
            )
            field("MARKETNAME_MIUI_MOD_DEVICE",
                "ro.product.mod_device" nLayer { NativeBridge.getSystemProperty("ro.product.mod_device") },
                "getprop ro.product.mod_device" sLayer { getpropShell("ro.product.mod_device") },
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
            // SERIAL — Android 8+ Build.getSerial() 没 READ_PRIVILEGED_PHONE_STATE
            // 权限会返回 "unknown",这是 Google 强制的真机行为,不该跟 ro.serialno
            // 做一致性 check(真机本来就不一致)。只看 native 双源是否一致。
            field("SERIAL",
                "ro.serialno" nLayer { NativeBridge.getSystemProperty("ro.serialno") },
                "ro.boot.serialno" nLayer { NativeBridge.getSystemProperty("ro.boot.serialno") },
            )
            // Build.getSerial() 单独记录(只为信息,不参与一致性)
            field("Build.getSerial() (info-only)",
                "Build.getSerial()" jLayer { reflectGetSerial() },
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
            // Build.USER — DG bytecode 校验 USER ⇔ BRAND;真机原值"android-build"跟任何品牌矛盾
            field("USER",
                "Build.USER" jLayer { Build.USER },
                "ro.build.user" nLayer { NativeBridge.getSystemProperty("ro.build.user") },
            )
            // getRadioVersion() — Android 12+ 直接读 gsm.version.baseband 绕过 Build.RADIO 静态字段;
            // ghost BuildHook 当前只 hook Build.RADIO 字段没 hook getRadioVersion(),Android 12+ 设备暴露
            field("getRadioVersion()",
                "Build.getRadioVersion()" jLayer { Build.getRadioVersion() ?: "" },
                "gsm.version.baseband" nLayer { NativeBridge.getSystemProperty("gsm.version.baseband") },
            )
            // ro.arch — DG native 直读(0x12ec0 地址),目前 __system_property_read_callback hook 已注释
            field("ro.arch",
                "ro.arch" nLayer { NativeBridge.getSystemProperty("ro.arch") },
            )
            // ro.board.platform — SoC 平台,DG 可能查
            field("ro.board.platform",
                "ro.board.platform" nLayer { NativeBridge.getSystemProperty("ro.board.platform") },
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

            // ----------------------------------------------------------------
            // 多源 width/height/dpi 检测 — 验证 wm size + 兜底 hook 完整性
            // wm size 持久化通过 Settings.forced + WindowManager.setForced* API,
            // 风控可以通过多条路径绕过 wm size override 拿真物理屏幕,这里把所有
            // 已知的检测向量全列出来,看 ghost 漏没漏。
            // ----------------------------------------------------------------

            // (1) Resources.getDisplayMetrics 全字段
            field("resources_display_metrics_full",
                "Resources.getDisplayMetrics" jLayer {
                    val dm = context.resources.displayMetrics
                    "${dm.widthPixels}x${dm.heightPixels} density=${dm.density} dpi=${dm.densityDpi} xdpi=${dm.xdpi} ydpi=${dm.ydpi}"
                },
            )

            // (2) Resources.getConfiguration screenWidthDp/HeightDp/densityDpi
            field("resources_configuration",
                "Resources.getConfiguration" jLayer {
                    val cfg = context.resources.configuration
                    "w=${cfg.screenWidthDp}dp h=${cfg.screenHeightDp}dp smallest=${cfg.smallestScreenWidthDp}dp dpi=${cfg.densityDpi}"
                },
            )

            // (3) WindowMetrics.getBounds (Android 11+)
            field("window_metrics_current_bounds",
                "WindowManager.getCurrentWindowMetrics().getBounds()" jLayer {
                    if (Build.VERSION.SDK_INT >= 30) {
                        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                        val b = wm.currentWindowMetrics.bounds
                        "${b.width()}x${b.height()}"
                    } else "N/A_API<30"
                },
            )

            // (4) WindowMetrics.getMaximumWindowMetrics — 物理最大可用区
            field("window_metrics_maximum_bounds",
                "WindowManager.getMaximumWindowMetrics().getBounds()" jLayer {
                    if (Build.VERSION.SDK_INT >= 30) {
                        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                        val b = wm.maximumWindowMetrics.bounds
                        "${b.width()}x${b.height()}"
                    } else "N/A_API<30"
                },
            )

            // (5) WindowMetrics.getDensity (Android 14+)
            field("window_metrics_density",
                "WindowMetrics.getDensity()" jLayer {
                    if (Build.VERSION.SDK_INT >= 34) {
                        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                        wm.currentWindowMetrics.density.toString()
                    } else "N/A_API<34"
                },
            )

            // (6) IWindowManager.getInitialDisplaySize — wm size override 之前的物理真值
            //     ghost client-side hook 拦截,应该返 spoof
            field("iwm_initial_display_size",
                "IWindowManager.getInitialDisplaySize" jLayer {
                    runCatching {
                        val sm = Class.forName("android.os.ServiceManager")
                        val binder = sm.getMethod("getService", String::class.java).invoke(null, "window")
                        val iwm = Class.forName("android.view.IWindowManager\$Stub")
                            .getMethod("asInterface", Class.forName("android.os.IBinder")).invoke(null, binder)
                        val pt = android.graphics.Point()
                        Class.forName("android.view.IWindowManager")
                            .getMethod("getInitialDisplaySize", Int::class.javaPrimitiveType, android.graphics.Point::class.java)
                            .invoke(iwm, 0, pt)
                        "${pt.x}x${pt.y}"
                    }.getOrElse { "ERR:${it.message}" }
                },
            )

            // (7) IWindowManager.getBaseDisplaySize
            field("iwm_base_display_size",
                "IWindowManager.getBaseDisplaySize" jLayer {
                    runCatching {
                        val sm = Class.forName("android.os.ServiceManager")
                        val binder = sm.getMethod("getService", String::class.java).invoke(null, "window")
                        val iwm = Class.forName("android.view.IWindowManager\$Stub")
                            .getMethod("asInterface", Class.forName("android.os.IBinder")).invoke(null, binder)
                        val pt = android.graphics.Point()
                        Class.forName("android.view.IWindowManager")
                            .getMethod("getBaseDisplaySize", Int::class.javaPrimitiveType, android.graphics.Point::class.java)
                            .invoke(iwm, 0, pt)
                        "${pt.x}x${pt.y}"
                    }.getOrElse { "ERR:${it.message}" }
                },
            )

            // (8) IWindowManager.getInitialDisplayDensity
            field("iwm_initial_display_density",
                "IWindowManager.getInitialDisplayDensity" jLayer {
                    runCatching {
                        val sm = Class.forName("android.os.ServiceManager")
                        val binder = sm.getMethod("getService", String::class.java).invoke(null, "window")
                        val iwm = Class.forName("android.view.IWindowManager\$Stub")
                            .getMethod("asInterface", Class.forName("android.os.IBinder")).invoke(null, binder)
                        Class.forName("android.view.IWindowManager")
                            .getMethod("getInitialDisplayDensity", Int::class.javaPrimitiveType)
                            .invoke(iwm, 0).toString()
                    }.getOrElse { "ERR:${it.message}" }
                },
            )

            // (9) IWindowManager.getBaseDisplayDensity
            field("iwm_base_display_density",
                "IWindowManager.getBaseDisplayDensity" jLayer {
                    runCatching {
                        val sm = Class.forName("android.os.ServiceManager")
                        val binder = sm.getMethod("getService", String::class.java).invoke(null, "window")
                        val iwm = Class.forName("android.view.IWindowManager\$Stub")
                            .getMethod("asInterface", Class.forName("android.os.IBinder")).invoke(null, binder)
                        Class.forName("android.view.IWindowManager")
                            .getMethod("getBaseDisplayDensity", Int::class.javaPrimitiveType)
                            .invoke(iwm, 0).toString()
                    }.getOrElse { "ERR:${it.message}" }
                },
            )

            // (10) Settings.Global.DISPLAY_SIZE_FORCED — wm size 持久化痕迹
            //      ghost SettingsProviderHook 拦截 hookpkg uid,应返 null
            field("settings_global_display_size_forced",
                "Settings.Global.getString(DISPLAY_SIZE_FORCED)" jLayer {
                    Settings.Global.getString(context.contentResolver, "display_size_forced") ?: "null"
                },
            )

            // (11) Settings.Secure.DISPLAY_DENSITY_FORCED
            field("settings_secure_display_density_forced",
                "Settings.Secure.getString(DISPLAY_DENSITY_FORCED)" jLayer {
                    Settings.Secure.getString(context.contentResolver, "display_density_forced") ?: "null"
                },
            )

            // (12) /sys/class/graphics/fb0/virtual_size — 内核 framebuffer 真物理 px
            //      多源 fopen / svc syscall / popen 对比
            field("sysfs_fb0_virtual_size",
                "fopen /sys/class/graphics/fb0/virtual_size" pLayer {
                    NativeBridge.readFile("/sys/class/graphics/fb0/virtual_size", 256).trim()
                },
                "svc openat /sys/class/graphics/fb0/virtual_size" pLayer {
                    NativeBridge.readFileViaSyscall("/sys/class/graphics/fb0/virtual_size", 256).trim()
                },
                "popen cat /sys/class/graphics/fb0/virtual_size" pLayer {
                    NativeBridge.execShell("cat /sys/class/graphics/fb0/virtual_size 2>/dev/null", 256).trim()
                },
            )

            // (13) /sys/class/graphics/fb0/mode — 显示模式
            field("sysfs_fb0_mode",
                "fopen /sys/class/graphics/fb0/mode" pLayer {
                    NativeBridge.readFile("/sys/class/graphics/fb0/mode", 512).trim()
                },
                "svc openat /sys/class/graphics/fb0/mode" pLayer {
                    NativeBridge.readFileViaSyscall("/sys/class/graphics/fb0/mode", 512).trim()
                },
                "popen cat /sys/class/graphics/fb0/mode" pLayer {
                    NativeBridge.execShell("cat /sys/class/graphics/fb0/mode 2>/dev/null", 512).trim()
                },
            )

            // (14) /sys/class/graphics/fb0/modes — 可用模式列表
            field("sysfs_fb0_modes",
                "fopen /sys/class/graphics/fb0/modes" pLayer {
                    NativeBridge.readFile("/sys/class/graphics/fb0/modes", 2048).trim().take(500)
                },
                "popen cat /sys/class/graphics/fb0/modes" pLayer {
                    NativeBridge.execShell("cat /sys/class/graphics/fb0/modes 2>/dev/null", 2048).trim().take(500)
                },
            )

            // (15) /sys/class/graphics/fb0/bits_per_pixel
            field("sysfs_fb0_bpp",
                "fopen /sys/class/graphics/fb0/bits_per_pixel" pLayer {
                    NativeBridge.readFile("/sys/class/graphics/fb0/bits_per_pixel", 32).trim()
                },
            )

            // (16) ls /sys/class/graphics/ — 列所有 fb 设备
            field("sysfs_graphics_listing",
                "popen ls /sys/class/graphics" pLayer {
                    NativeBridge.execShell("ls /sys/class/graphics/ 2>/dev/null", 512).trim()
                },
            )

            // (17) dumpsys display — 命令路径,部分 SDK 用(需要权限,通常 app 拿不到完整)
            field("dumpsys_display_size",
                "popen dumpsys display | grep mBaseDisplayInfo" pLayer {
                    NativeBridge.execShell(
                        "dumpsys display 2>/dev/null | grep -iE 'mBaseDisplayInfo|mInitialDisplay|width=|height=' | head -10",
                        2048
                    ).trim().take(500)
                },
            )

            // ----------------------------------------------------------------
            // 截图 API 检测(验证 ghost wm size override 对各种 screenshot 路径的覆盖度)
            // ----------------------------------------------------------------
            // (S1) PixelCopy 截 Window — 应等于 wm size(spoof)
            field("screenshot_pixelcopy_size",
                "PixelCopy.request(window)" jLayer {
                    runCatching {
                        // 注:PixelCopy 需要 Activity Window,Application Context 拿不到
                        // 这里用 Bitmap.createBitmap(decorViewSize) 模拟同样的 surface size
                        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                        val dm = DisplayMetrics()
                        @Suppress("DEPRECATION") wm.defaultDisplay.getRealMetrics(dm)
                        "${dm.widthPixels}x${dm.heightPixels} (PixelCopy 走 Display.getRealMetrics 派生 surface)"
                    }.getOrNull() ?: "n/a"
                },
            )
            // (S2) View.draw 模拟 — Bitmap.createBitmap(view.width, view.height)
            field("screenshot_view_draw_size",
                "Bitmap.createBitmap(decorView.width, height)" jLayer {
                    runCatching {
                        // 无 Activity 时用 Display.getRealMetrics 作代理(decorView 派生自 window)
                        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                        val dm = DisplayMetrics()
                        @Suppress("DEPRECATION") wm.defaultDisplay.getRealMetrics(dm)
                        "${dm.widthPixels}x${dm.heightPixels} (View.draw bitmap = window size)"
                    }.getOrNull() ?: "n/a"
                },
            )
            // (S3) WindowManager.getCurrentWindowMetrics().bounds (Android 11+) — 应等于 wm size
            field("window_current_metrics_bounds",
                "WindowManager.getCurrentWindowMetrics().getBounds()" jLayer {
                    runCatching {
                        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                        val b = wm.currentWindowMetrics.bounds
                        "${b.width()}x${b.height()}"
                    }.getOrNull() ?: "n/a (API<30)"
                },
            )
            // (S4) dumpsys SurfaceFlinger — **预期暴露真 panel**(ghost 没 hook SF binder)
            field("dumpsys_surfaceflinger_display",
                "popen dumpsys SurfaceFlinger --display-id" pLayer {
                    runCatching {
                        // 直接抓 dumpsys 输出里关于 panel 的字段
                        val out = NativeBridge.execShell(
                            "dumpsys SurfaceFlinger --display-id 2>&1 | head -40", 2048).trim()
                        // 提取 resolution 关键行(panel size 通常含 'Physical' / 'mode' / 'WxH')
                        val match = Regex(
                            "(\\d{3,4}\\s*x\\s*\\d{3,4}|Physical[^\\n]+|mode\\s*\\d+:\\s*\\d+x\\d+)",
                            RegexOption.IGNORE_CASE
                        ).find(out)
                        match?.value ?: out.take(200)
                    }.getOrNull() ?: "n/a"
                },
            )
            // (S5) screencap PNG 头 — **预期暴露真 panel**(shell uid 不被 ghost hook)
            field("runtime_exec_screencap_size",
                "popen screencap + PNG IHDR" pLayer {
                    runCatching {
                        // screencap -p 输出 PNG 到 stdout,head 取前 24 字节读 IHDR
                        // PNG header: 8 byte signature + 4 byte chunk length + 4 byte "IHDR" + 4 byte width + 4 byte height
                        // 用 hexdump 抓 IHDR 后的 8 字节 (offset 16-23)
                        val hex = NativeBridge.execShell(
                            "screencap -p 2>/dev/null | head -c 24 | od -An -tx1 | tr -d ' \\n'",
                            128).trim()
                        if (hex.length >= 48) {
                            // 字节 16-19 = width (big-endian), 20-23 = height
                            val w = hex.substring(32, 40).toLong(16).toInt()
                            val h = hex.substring(40, 48).toLong(16).toInt()
                            "${w}x${h}"
                        } else "n/a (hex=$hex)"
                    }.getOrNull() ?: "n/a"
                },
            )

            // (18) wm size / wm density 命令(需要 system 权限,普通 app 拿不到)
            field("wm_size_cmd",
                "popen wm size" pLayer {
                    NativeBridge.execShell("wm size 2>&1", 256).trim()
                },
            )
            field("wm_density_cmd",
                "popen wm density" pLayer {
                    NativeBridge.execShell("wm density 2>&1", 256).trim()
                },
            )

            // ----------------------------------------------------------------
            // Display 对象的特殊路径(老 DisplayHook 覆盖过的 GMS / 风控独立路径)
            // ----------------------------------------------------------------

            // (19) Display.getRealMetrics — 风控主路径(@deprecated 但仍在用)
            field("display_get_real_metrics",
                "Display.getRealMetrics" jLayer {
                    val dm = DisplayMetrics()
                    @Suppress("DEPRECATION")
                    (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
                        .getRealMetrics(dm)
                    "${dm.widthPixels}x${dm.heightPixels} dpi=${dm.densityDpi} density=${dm.density}"
                },
            )

            // (20) Display.getRealSize — Point 版本,GMS getStableDisplaySize 类似
            field("display_get_real_size",
                "Display.getRealSize" jLayer {
                    val pt = android.graphics.Point()
                    @Suppress("DEPRECATION")
                    (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
                        .getRealSize(pt)
                    "${pt.x}x${pt.y}"
                },
            )

            // (21) Display.getMode().getPhysicalWidth/Height — 物理 mode(老 hook 必盖)
            field("display_get_mode_physical",
                "Display.getMode().{physicalWidth,physicalHeight,refreshRate}" jLayer {
                    @Suppress("DEPRECATION")
                    val mode = (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager)
                        .defaultDisplay.mode
                    "${mode.physicalWidth}x${mode.physicalHeight}@${mode.refreshRate}Hz"
                },
            )

            // (22) Display.getSupportedModes — 全部支持 mode 列表
            field("display_get_supported_modes",
                "Display.getSupportedModes" jLayer {
                    @Suppress("DEPRECATION")
                    val modes = (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager)
                        .defaultDisplay.supportedModes
                    modes.joinToString("|") { "${it.physicalWidth}x${it.physicalHeight}@${"%.1f".format(it.refreshRate)}" }
                        .take(400)
                },
            )

            // (23) DisplayManager.getStableDisplaySize — GMS 主路径(getStableDisplaySize hook)
            field("display_manager_stable_display_size",
                "DisplayManager.getStableDisplaySize" jLayer {
                    runCatching {
                        val dmgr = context.getSystemService(Context.DISPLAY_SERVICE)
                        val pt = dmgr.javaClass.getMethod("getStableDisplaySize").invoke(dmgr) as android.graphics.Point
                        "${pt.x}x${pt.y}"
                    }.getOrElse { "ERR:${it.message}" }
                },
            )

            // (24) Display.getName / getDisplayId(辅助识别 default vs 其他 display)
            field("display_identity",
                "Display.id+name+flags" jLayer {
                    @Suppress("DEPRECATION")
                    val d = (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
                    "id=${d.displayId} name=${d.name} flags=${d.flags}"
                },
            )

            // (25) Display.refreshRate / getMode().refreshRate — 跨方法一致性
            field("display_refresh_rate",
                "Display.getRefreshRate" jLayer {
                    @Suppress("DEPRECATION")
                    val d = (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay
                    d.refreshRate.toString()
                },
            )

            // (26) DisplayMetrics.setToDefaults() 之后的 density(老 hook 覆盖此时机注入 DENSITY_DEVICE_STABLE)
            field("display_metrics_set_to_defaults",
                "new DisplayMetrics().setToDefaults() 后 densityDpi" jLayer {
                    val dm = DisplayMetrics()
                    dm.setToDefaults()
                    "${dm.widthPixels}x${dm.heightPixels} dpi=${dm.densityDpi}"
                },
            )

            // (27) Configuration.densityDpi 静态(Resources.getSystem() 全局)
            field("system_resources_configuration",
                "Resources.getSystem().getConfiguration()" jLayer {
                    val cfg = android.content.res.Resources.getSystem().configuration
                    "w=${cfg.screenWidthDp}dp h=${cfg.screenHeightDp}dp dpi=${cfg.densityDpi}"
                },
            )

            // (28) DisplayInfo via DisplayManagerGlobal.getDisplayInfo (反射 hidden API,GMS 用)
            field("display_manager_global_display_info",
                "DisplayManagerGlobal.getDisplayInfo(0).logicalWidth/Height/DensityDpi" jLayer {
                    runCatching {
                        val dmgClass = Class.forName("android.hardware.display.DisplayManagerGlobal")
                        val instance = dmgClass.getMethod("getInstance").invoke(null)
                        val info = dmgClass.getMethod("getDisplayInfo", Int::class.javaPrimitiveType)
                            .invoke(instance, 0)
                        if (info == null) "null"
                        else {
                            val cls = info.javaClass
                            fun fi(n: String): Int = runCatching {
                                cls.getDeclaredField(n).apply { isAccessible = true }.getInt(info)
                            }.getOrDefault(-1)
                            "logical=${fi("logicalWidth")}x${fi("logicalHeight")}@${fi("logicalDensityDpi")} " +
                            "app=${fi("appWidth")}x${fi("appHeight")} " +
                            "physical=${fi("physicalWidth")}x${fi("physicalHeight")} " +
                            "nominal=${fi("smallestNominalAppWidth")}x${fi("largestNominalAppHeight")}"
                        }
                    }.getOrElse { "ERR:${it.message}" }
                },
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
            // CPU 微架构签名:所有不同的 "CPU part"(0xd05=A55, 0xd0b=A76, 0xd44=X1 …)。
            // 这是硬件真值(ghost 若不 spoof /proc/cpuinfo 就暴露真 SoC),用于跨字段比对声称的 SOC_MODEL。
            field("cpuinfo.CPUParts",
                "proc cpuinfo" pLayer { extractAllProcValues("/proc/cpuinfo", "CPU part") },
            )
            field("cpuinfo.CPUImplementer",
                "proc cpuinfo" pLayer { extractAllProcValues("/proc/cpuinfo", "CPU implementer") },
            )
            // ro.board.platform:SoC 平台真值(gs101=Tensor, kalama/taro/pineapple=高通, mt6xxx=联发科)。
            field("ro.board.platform",
                "getprop" sLayer { getpropShell("ro.board.platform") },
            )
            field("ro.hardware.chipname",
                "getprop" sLayer { getpropShell("ro.hardware.chipname") },
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
            // DG accessor:k = sha1(GL_EXTENSIONS),跨 session 唯一 ID。ghost 用同一份 extensions
            // 则所有用户 hash 一致 → 跨用户唯一 ID → 需要 per-device salt
            field("GL_EXTENSIONS.sha1",
                "native EGL + sha1" nLayer { sha1Hex(gles.getOrNull(3) ?: "") },
                "Java GLES10 + sha1" jLayer { sha1Hex(javaGlGet(GLES10.GL_EXTENSIONS) ?: "") },
            )
            // GL_SHADING_LANGUAGE_VERSION (0x8B8C) — DG 可能查
            field("GL_SHADING_LANGUAGE_VERSION",
                "Java GLES10.glGetString(0x8B8C)" jLayer { javaGlGet(0x8B8C) },
            )
            // EGL driver 文件 SHA-1 列表 — DG 标签 sla/sll/slq/slum 通过
            // File.listFiles("/system/lib/egl") + sha1 each。物理设备真实硬件值,ghost 无法 spoof
            field("egl_driver_files",
                "ls /vendor/lib64/egl/" sLayer {
                    listOf("/vendor/lib64/egl", "/vendor/lib/egl", "/system/lib64/egl", "/system/lib/egl")
                        .flatMap { dir -> java.io.File(dir).listFiles()?.toList() ?: emptyList() }
                        .filter { it.name.endsWith(".so") }
                        .joinToString(",") { it.name }
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
            // --- SIM 存在/就绪(TelephonyManagerHook 服务端伪造:
            //     ISub.getSimStateForSlotIndex→SIM_STATE_READY(5)、
            //     ITelephony.hasIccCardUsingSlotIndex→true)---
            field("simState",
                "TelephonyManager.getSimState" jLayer {
                    when (val s = tm?.simState) {
                        null -> ""
                        TelephonyManager.SIM_STATE_ABSENT -> "ABSENT"
                        TelephonyManager.SIM_STATE_READY -> "READY"
                        TelephonyManager.SIM_STATE_PIN_REQUIRED -> "PIN_REQUIRED"
                        TelephonyManager.SIM_STATE_PUK_REQUIRED -> "PUK_REQUIRED"
                        TelephonyManager.SIM_STATE_NETWORK_LOCKED -> "NETWORK_LOCKED"
                        TelephonyManager.SIM_STATE_NOT_READY -> "NOT_READY"
                        TelephonyManager.SIM_STATE_PERM_DISABLED -> "PERM_DISABLED"
                        TelephonyManager.SIM_STATE_CARD_IO_ERROR -> "CARD_IO_ERROR"
                        TelephonyManager.SIM_STATE_CARD_RESTRICTED -> "CARD_RESTRICTED"
                        else -> s.toString()
                    }
                },
            )
            field("hasIccCard",
                "TelephonyManager.hasIccCard" jLayer { tm?.hasIccCard()?.toString() ?: "" },
            )
            // getNetworkCountryIso → ITelephony.getNetworkCountryIsoForPhone 被伪造成 props.simCountryIso。
            // native gsm.operator.iso-country 未被 ghost 伪造 → 有真 SIM 时 java(spoof) vs native(真)
            // 会在本 field 内自动查出不一致(强泄漏信号)。
            field("networkCountryIso",
                "TelephonyManager.networkCountryIso" jLayer { tm?.networkCountryIso ?: "" },
                "gsm.operator.iso-country" nLayer { NativeBridge.getSystemProperty("gsm.operator.iso-country") },
            )
            // getSimCarrierId → ITelephony.getSubscriptionCarrierId 被伪造成 extraData[CarrierId](默认 1)
            field("simCarrierId",
                "TelephonyManager.getSimCarrierId" jLayer {
                    val id = tm?.simCarrierId ?: TelephonyManager.UNKNOWN_CARRIER_ID
                    if (id == TelephonyManager.UNKNOWN_CARRIER_ID) "" else id.toString()
                },
            )
            field("simCarrierIdName",
                "TelephonyManager.getSimCarrierIdName" jLayer { tm?.simCarrierIdName?.toString() ?: "" },
            )
            // getLine1Number → IPhoneSubInfo.getLine1Number 兜底重写(仅原值非空/系统应用才改)。
            // 普通检测器无 READ_PHONE_NUMBERS → safeCollect 捕获 SecurityException,值为空,不参与规则。
            field("line1Number",
                "TelephonyManager.getLine1Number" jLayer { tm?.line1Number ?: "" },
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
        // I-2. Sensors — DG 通过 lasr/rvsr/sei 标签采集传感器元信息
        // ============================================================
        category("sensors") {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as? android.hardware.SensorManager
            val sensors = sm?.getSensorList(android.hardware.Sensor.TYPE_ALL).orEmpty()
            // 总数 — DG 可能统计;真机一般 10-20 个,ghost 当前 SensorManagerHook 伪造数量不全
            field("sensor.count",
                "SensorManager.getSensorList(TYPE_ALL).size" jLayer { sensors.size.toString() },
            )
            // 单个 sensor name 哈希 — DG 看 name 字符串。ghost 用 stringUpper(5) 生成
            // "QFRJU" 类乱码,真实设备应该是 "LSM6DSO Accelerometer" 之类
            field("sensor.names_sha1",
                "SensorList.name 排序 sha1" jLayer {
                    sha1Hex(sensors.map { it.name }.sorted().joinToString("\n"))
                },
            )
            field("sensor.vendors_sha1",
                "SensorList.vendor 排序 sha1" jLayer {
                    sha1Hex(sensors.map { it.vendor }.sorted().joinToString("\n"))
                },
            )
            // 单个加速度计 name(DG lasr 标签),验证是否 "QFRJU" 类乱码
            field("sensor.linear_accel.name",
                "Sensor(TYPE_LINEAR_ACCELERATION).name" jLayer {
                    sm?.getDefaultSensor(android.hardware.Sensor.TYPE_LINEAR_ACCELERATION)?.name ?: ""
                },
            )
            field("sensor.rotation_vector.name",
                "Sensor(TYPE_ROTATION_VECTOR).name" jLayer {
                    sm?.getDefaultSensor(android.hardware.Sensor.TYPE_ROTATION_VECTOR)?.name ?: ""
                },
            )
            field("sensor.accelerometer.vendor",
                "Sensor(TYPE_ACCELEROMETER).vendor" jLayer {
                    sm?.getDefaultSensor(android.hardware.Sensor.TYPE_ACCELEROMETER)?.vendor ?: ""
                },
            )
        }

        // ============================================================
        // I-3. 已加载 native 库 — DG 通过 dl_iterate_phdr 标签 lib 枚举
        // ============================================================
        category("loaded-libs") {
            val maps = NativeBridge.readFile("/proc/self/maps", 524288)
            // 提取所有 mmap 出来的 .so 文件名(去重)
            val soFiles = maps.lineSequence()
                .mapNotNull { line ->
                    Regex("\\s(/[^\\s]+\\.so)$").find(line)?.groupValues?.get(1)
                }
                .toSet()
                .sorted()
            field("loaded_so.count",
                "/proc/self/maps so count" pLayer { soFiles.size.toString() },
            )
            // 关键 LSPosed / Xposed / Magisk 痕迹库,任何一个出现说明 hide_utils 没盖全
            for (suspiciousSo in listOf(
                "liblspd.so", "libriru_lsposed.so", "libzygisk.so", "libxposed_art.so",
                "libplay.so", "libdobby.so", "libsubstrate.so", "libsubstrate-dvm.so",
                "libfrida-agent.so", "libfrida-gadget.so",
            )) {
                field("loaded_so.has_$suspiciousSo",
                    "soFiles.contains" pLayer {
                        soFiles.any { it.contains(suspiciousSo) }.toString()
                    },
                )
            }
            // 全列表 hash — 跨 session 稳定性指标,DG 可用作跨设备 ID
            field("loaded_so.all_sha1",
                "全部 .so 排序后 sha1" pLayer { sha1Hex(soFiles.joinToString("\n")) },
            )

            // ===== native 路径:dl_iterate_phdr 枚举(商业风控主用,绕 /proc/maps)=====
            val dlList = runCatching { NativeBridge.enumerateLoadedSos().toList() }
                .getOrDefault(emptyList())
            val dlNonEmpty = dlList.filter { it.isNotBlank() }.toSet().sorted()
            field("loaded_so.dl_iterate_phdr.count",
                "dl_iterate_phdr (native)" nLayer { dlNonEmpty.size.toString() },
            )
            field("loaded_so.dl_iterate_phdr.sha1",
                "dl_iterate_phdr 排序后 sha1" nLayer { sha1Hex(dlNonEmpty.joinToString("\n")) },
            )

            // ===== 跨源对比:dl_iterate_phdr vs /proc/self/maps =====
            // ghost 通过 KernelSU.redirectIO + dlopen 注入虚拟 vendor SO 时,两条
            // 路径应都看到 vendor SO 名 → SHA 也应跨"新机"协同变化。
            // 但 dlpi_name 风格跟 maps 行格式不同(maps 含 device:inode 等),
            // 直接 SHA 不会等同 — 这里只对 set 做 symmetric diff 看哪些 path 单源出现。
            field("loaded_so.cross_source_diff",
                "dl_only / maps_only path 个数" jLayer {
                    val mapsSet = soFiles.toSet()
                    val dlSet = dlNonEmpty.toSet()
                    val dlOnly = (dlSet - mapsSet).size
                    val mapsOnly = (mapsSet - dlSet).size
                    "dl_only=$dlOnly,maps_only=$mapsOnly,both=${(dlSet intersect mapsSet).size}"
                },
            )

            // ===== ghost #44 vendor SO 注入命中检测 =====
            // 验证 ghost 是否真的让 dl_iterate_phdr 吐出 vendor SO 名。
            for (vendorSo in listOf(
                "libGLES_mali.so", "libGLESv2_adreno.so", "libEGL_adreno.so",
                "libgsl.so", "libsec-ril.so", "libtitanm.so", "libmali.so",
            )) {
                field("loaded_so.dl_has_$vendorSo",
                    "dl_iterate_phdr any.contains" nLayer {
                        dlNonEmpty.any { it.contains(vendorSo) }.toString()
                    },
                    "maps any.contains" pLayer {
                        soFiles.any { it.contains(vendorSo) }.toString()
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
            // ★system_locales / locale_list:风控(如 Castle)读的 locale 列表。应与 locale/persist.sys.locale 一致;
            //   若声称地区(如 jp)却漏出用户真实语言列表(如 en-US,zh-HK)= 穿帮。
            field("system_locales",
                "Settings.System.system_locales" jLayer {
                    android.provider.Settings.System.getString(context.contentResolver, "system_locales") ?: "<null>"
                },
            )
            field("locale_list",
                "LocaleList.getDefault().toLanguageTags()" jLayer {
                    android.os.LocaleList.getDefault().toLanguageTags()
                },
            )
            // ★config_locales:Castle(io.castle.highwind)native VM 走 Configuration.getLocales() 拿的 tag27 源。
            //   与 locale_list(LocaleList.getDefault)是不同 API,必须单独探。声称 jp 却漏 en-US,zh-HK = 穿帮。
            field("config_locales",
                "Resources.getSystem().getConfiguration().getLocales()" jLayer {
                    android.content.res.Resources.getSystem().configuration.locales.toLanguageTags()
                },
                "context.resources.configuration.getLocales()" jLayer {
                    context.resources.configuration.locales.toLanguageTags()
                },
            )
            field("ro.build.description",
                "ro.build.description" nLayer { NativeBridge.getSystemProperty("ro.build.description") },
            )
            // ro.build.date.utc vs Build.TIME — TIME spoof 一致性(文档 §2.1 说 TIME 跨 profile 不变是漏洞)
            field("ro.build.date.utc",
                "ro.build.date.utc * 1000" nLayer {
                    NativeBridge.getSystemProperty("ro.build.date.utc").toLongOrNull()
                        ?.let { (it * 1000).toString() } ?: ""
                },
                "Build.TIME" jLayer { Build.TIME.toString() },
            )
            // ro.bootloader vs Build.BOOTLOADER — Android 12+ getRadioVersion 同款问题
            field("ro.bootloader",
                "ro.bootloader" nLayer { NativeBridge.getSystemProperty("ro.bootloader") },
                "ro.boot.bootloader" nLayer { NativeBridge.getSystemProperty("ro.boot.bootloader") },
                "Build.BOOTLOADER" jLayer { Build.BOOTLOADER },
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

            // ============================================================
            // Verified Boot / 反模拟器(ghost setSysProp 强制 spoof 的硬编码值)
            //   真机典型值:verifiedbootstate=green, flash.locked=1, veritymode=enforcing,
            //               warranty_bit=0, kernel.qemu=0
            //   ghost spoof 后应固定这些值。如果泄露真值,Verified Boot 状态不对 = anchor。
            // ============================================================
            field("ro.boot.verifiedbootstate",
                "ro.boot.verifiedbootstate" nLayer { NativeBridge.getSystemProperty("ro.boot.verifiedbootstate") },
            )
            field("ro.boot.flash.locked",
                "ro.boot.flash.locked" nLayer { NativeBridge.getSystemProperty("ro.boot.flash.locked") },
            )
            field("ro.boot.veritymode",
                "ro.boot.veritymode" nLayer { NativeBridge.getSystemProperty("ro.boot.veritymode") },
            )
            field("ro.boot.warranty_bit",
                "ro.boot.warranty_bit" nLayer { NativeBridge.getSystemProperty("ro.boot.warranty_bit") },
            )
            field("ro.kernel.qemu",
                "ro.kernel.qemu" nLayer { NativeBridge.getSystemProperty("ro.kernel.qemu") },
            )
            field("ro.boot.qemu",
                "ro.boot.qemu" nLayer { NativeBridge.getSystemProperty("ro.boot.qemu") },
            )
            field("ro.boot.hardware.qemu",
                "ro.boot.hardware.qemu" nLayer { NativeBridge.getSystemProperty("ro.boot.hardware.qemu") },
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
        // K2. TEE / Keystore Attestation(Phase E) — ghost spoof 的天花板。
        //     生成 EC key 并请求硬件 attestation,parse cert chain 拿 TEE-enforced
        //     Build IDs(brand/device/manufacturer/model/product/serial)。这些字段
        //     由 TEE 硬件密钥签名,ghost 无法 hook → 跟 Java Build.* 跨源不一致 = anchor。
        //     OEM keybox 攻法 / TrickyStore 等可绕,但绝大多数场景下直接暴露真值。
        // ============================================================
        category("tee-attestation") {
            val tee = collectKeystoreAttestation()
            field("tee.supported",
                "EC + setAttestationChallenge" jLayer {
                    when {
                        tee == null -> "false (attestation API failed)"
                        tee.error != null -> "false (${tee.error})"
                        else -> "true"
                    }
                },
            )
            if (tee != null && tee.error == null) {
                field("tee.cert_chain.length",
                    "X509 chain size" jLayer { tee.chainLength.toString() },
                )
                field("tee.attestation_security_level",
                    "AttestationExtension byte[1]" jLayer { tee.attestationSecurityLevel },
                )
                field("tee.keymaster_security_level",
                    "AttestationExtension keymaster level" jLayer { tee.keymasterSecurityLevel },
                )
                field("tee.attestation_version",
                    "AttestationExtension version" jLayer { tee.attestationVersion?.toString() },
                )
                field("tee.keymaster_version",
                    "AttestationExtension km version" jLayer { tee.keymasterVersion?.toString() },
                )
                // ★★★ 关键:TEE-enforced Build IDs 跟 Java Build.* 跨源对比 ★★★
                field("tee.id.brand vs Build.BRAND",
                    "Build.BRAND" jLayer { Build.BRAND },
                    "TEE hw-enforced attestationIdBrand[710]" jLayer { tee.idBrand },
                )
                field("tee.id.device vs Build.DEVICE",
                    "Build.DEVICE" jLayer { Build.DEVICE },
                    "TEE hw-enforced attestationIdDevice[711]" jLayer { tee.idDevice },
                )
                field("tee.id.product vs Build.PRODUCT",
                    "Build.PRODUCT" jLayer { Build.PRODUCT },
                    "TEE hw-enforced attestationIdProduct[712]" jLayer { tee.idProduct },
                )
                field("tee.id.manufacturer vs Build.MANUFACTURER",
                    "Build.MANUFACTURER" jLayer { Build.MANUFACTURER },
                    "TEE hw-enforced attestationIdManufacturer[716]" jLayer { tee.idManufacturer },
                )
                field("tee.id.model vs Build.MODEL",
                    "Build.MODEL" jLayer { Build.MODEL },
                    "TEE hw-enforced attestationIdModel[717]" jLayer { tee.idModel },
                )
                field("tee.id.serial",
                    "TEE hw-enforced attestationIdSerial[713]" jLayer { tee.idSerial },
                )
                // ★K1:cert chain 验签 + leaf 有效期跨度(伪 leaf 对不上 Google 中间证书=false;有效期 ~1h ≪ 真机数千h)
                field("tee.chain_verified",
                    "leaf→…→root 逐级 verify(parent.pub)" jLayer { tee.chainVerified },
                )
                field("tee.leaf_validity_hours",
                    "leaf notAfter-notBefore(小时;真机 ≫1000,伪 leaf ~1)" jLayer { tee.leafValidityHours?.toString() },
                )
                field("tee.root_pubkey_sha256",
                    "chain root 公钥 SHA256(vs Google hw-attestation root allowlist)" jLayer { tee.rootPubKeySha256 },
                )
                // ★K3:osVersion[705] / osPatchLevel[706] vs Build(硬编码 A13/2024-01 与 spoof 到 A14/15/16 直接矛盾)
                field("att.os_version vs Build.RELEASE",
                    "Build.VERSION.RELEASE(major)" jLayer { Build.VERSION.RELEASE?.substringBefore('.') },
                    "attestation osVersion[705] major" jLayer { tee.osVersion?.let { (it / 10000).toString() } },
                )
                field("att.os_patch_level vs SECURITY_PATCH",
                    "Build.VERSION.SECURITY_PATCH(YYYY-MM)" jLayer { Build.VERSION.SECURITY_PATCH?.take(7) },
                    "attestation osPatchLevel[706](YYYY-MM)" jLayer {
                        tee.osPatchLevel?.let { "%04d-%02d".format(it / 100, it % 100) }
                    },
                )
                // ★K2:RootOfTrust[704] verifiedBootState/deviceLocked vs ro.boot.*(root unlock→attestation orange/false 硬拆 sysprop green/1)
                field("att.verified_boot_state vs ro.boot.verifiedbootstate",
                    "attestation verifiedBootState[704]" jLayer {
                        tee.verifiedBootState?.let { when (it) { 0 -> "green"; 1 -> "yellow"; 2 -> "orange"; 3 -> "red"; else -> "unknown($it)" } }
                    },
                    "ro.boot.verifiedbootstate" nLayer { NativeBridge.getSystemProperty("ro.boot.verifiedbootstate") },
                    "getprop ro.boot.verifiedbootstate" sLayer { getpropShell("ro.boot.verifiedbootstate") },
                )
                field("att.device_locked vs ro.boot.flash.locked",
                    "attestation deviceLocked[704]" jLayer { tee.deviceLocked?.let { if (it) "1" else "0" } },
                    "ro.boot.flash.locked" nLayer { NativeBridge.getSystemProperty("ro.boot.flash.locked") },
                )
                // verifiedBootKey/Hash:随机/跨采集变=锚(真机命中已知 Google/OEM 摘要 + 稳定)
                field("att.verified_boot_key",
                    "RootOfTrust verifiedBootKey(hex)" jLayer { tee.verifiedBootKeyHex },
                )
                field("att.verified_boot_hash",
                    "RootOfTrust verifiedBootHash(hex)" jLayer { tee.verifiedBootHashHex },
                )
                // ★K4:KeyInfo.getSecurityLevel vs attestation_security_level(ghost 内部矛盾:KeyInfo 报 StrongBox 但 attestation 报 TEE=穿帮)
                field("keyinfo.security_level vs attestation_level",
                    "KeyInfo.getSecurityLevel" jLayer { tee.keyInfoSecurityLevel },
                    "attestation_security_level" jLayer { tee.attestationSecurityLevel },
                )
                field("keyinfo.inside_secure_hardware",
                    "KeyInfo.isInsideSecureHardware" jLayer { tee.insideSecureHardware?.toString() },
                )
            }
            // ★K5:strongbox/app_attest/device_id_attestation feature(security_level=StrongBox 却 feature=false 自相矛盾;
            //   Build 冒充旗舰本应有 strongbox 却 false=锚)。放 tee 块外(与 attestation 成败无关,恒采)。
            field("has_feature.strongbox_keystore",
                "hasSystemFeature(strongbox_keystore)" jLayer { context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore").toString() },
            )
            field("has_feature.app_attest_key",
                "hasSystemFeature(keystore.app_attest_key)" jLayer { context.packageManager.hasSystemFeature("android.hardware.keystore.app_attest_key").toString() },
            )
            field("has_feature.device_id_attestation",
                "hasSystemFeature(device_id_attestation)" jLayer { context.packageManager.hasSystemFeature("android.software.device_id_attestation").toString() },
            )
        }

        // ============================================================
        // K'. Keystore 加解密跨设备可移植性(farm app 用 AndroidKeyStore 加密 token,备份/还原/新机后能否解开)
        //    真机:硬件密钥留 TEE、还原后解不开=丢登录态;ghost:常量 seed 软件密钥+固定 IV → 跨设备可解、删 alias 不破。
        //    跨设备(baseline 密文 vs 当前密钥)由 restore-diff 单测;此处测同会话 + 删 alias-regen。
        // ============================================================
        category("keystore-crypto") {
            val enc = KeystoreCryptoProbe.encrypt(KeystoreCryptoProbe.CANARY)
            field("crypto.aes_encrypt_ok",
                "AndroidKeyStore AES/GCM encrypt(canary)" jLayer { (enc != null).toString() },
            )
            field("crypto.aes_self_decrypt_ok",
                "encrypt→decrypt==canary(同会话往返)" jLayer { KeystoreCryptoProbe.selfRoundTripOk().toString() },
            )
            // ★删 alias→重生成→解删前密文:ghost 常量 seed→仍成功(true);真机硬件密钥→失败(false)。
            field("crypto.delete_alias_regen_decrypt_ok",
                "删 alias 重生成后解旧密文" jLayer { KeystoreCryptoProbe.deleteRegenDecryptOk().toString() },
            )
            // 确定性密文:ghost 固定 seed+IV → 同明文同密文(跨设备/跨采集稳定=可移植的间接证据)
            field("crypto.canary_ciphertext_hex",
                "AES/GCM(canary) ciphertext(ghost 常量 seed→跨设备稳定)" jLayer { enc?.first },
            )
            // ★空加密检测:ghost NoEncryptionCipher 让密文==明文 → 跨设备可移植(✓)但'密文==明文'是检测面。
            field("crypto.encryption_is_noop",
                "密文==明文?(true=ghost 空加密:可移植但可被检测)" jLayer {
                    val plainHex = KeystoreCryptoProbe.CANARY.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }
                    enc?.let { (it.first == plainHex).toString() }
                },
            )
            // ★K10 KAT:真 AES/GCM 每次随机 IV → 同明文两次密文不同;false=固定 IV 或空加密=锚。
            field("crypto.two_encrypts_differ",
                "同明文两次加密密文不同?(false=固定IV/空加密)" jLayer { KeystoreCryptoProbe.twoEncryptsDifferOk().toString() },
            )
            // ★K10 KAT:GCM 密文=明文+16B tag;false=长度==明文=无 tag=空加密。
            field("crypto.gcm_tag_length_ok",
                "GCM 密文长度==明文+16(tag)?(false=无tag=空加密)" jLayer { KeystoreCryptoProbe.gcmTagLengthOk().toString() },
            )
            // ★K9:非认证 EC keygen 公钥 SHA-256。
            //   旧 ghost:固定内嵌密钥 → 跨设备/新机相同 = 聚集锚(被 X Castle 等抓)。
            //   本次改动:每设备派生 → 跨设备应**不同**、同设备确定性相同、跨新机应变(= 聚集锚已消除)。
            field("keystore.nonattest_ec_pubkey_sha256",
                "非 challenge EC keygen 公钥 SHA-256(跨设备应不同=per-device 生效;相同=仍固定锚)" jLayer {
                    KeystoreCryptoProbe.nonAttestEcPubKeySha256()
                },
            )
            // ★RSA(PRIVATE_RSA,no-op 加密)同会话往返 —— 验证惰性 RSA 派生 + 自签名占位证书可用。
            field("crypto.rsa_self_roundtrip_ok",
                "RSA encrypt(pubkey)→decrypt(privkey)==canary(惰性派生+自签名证书)" jLayer {
                    KeystoreCryptoProbe.rsaSelfRoundTripOk().toString()
                },
            )
            // ★EC(PRIVATE_EC,真签名)同会话 sign→verify —— 验证每设备派生 EC 密钥 + 自签名证书可签可验。
            field("crypto.ec_sign_verify_ok",
                "EC sign(privkey)→verify(pubkey)(每设备派生密钥+自签名证书)" jLayer {
                    KeystoreCryptoProbe.ecSignVerifyOk().toString()
                },
            )
            // ★★缓存优先(参照真 app SharedPrefUtils):密文/签名存 SharedPreferences 随备份走 →
            //   还原/新机后解缓存的密文=直接验证备份还原保真。cache ok=true=保真;seeded=本次首播种。
            //   AES(常量seed)跨设备恒解;RSA(no-op)恒解;EC(per-device)同设备/还原过、跨新机变。
            field("crypto.aes_cached_decrypt",
                "AES 解缓存密文(备份还原保真;cache=用缓存/seeded=本次播种)" jLayer {
                    KeystoreCryptoProbe.aesCachedDecrypt().toString()
                },
            )
            field("crypto.rsa_cached_decrypt",
                "RSA 解缓存密文(no-op 恒可移植)" jLayer {
                    KeystoreCryptoProbe.rsaCachedDecrypt().toString()
                },
            )
            field("crypto.ec_cached_verify",
                "EC 验缓存签名(同设备/还原应过、跨新机应变)" jLayer {
                    KeystoreCryptoProbe.ecCachedVerify().toString()
                },
            )
            // ★getCertificate 与 getCertificateChain 一致性 —— 验证本次新增的 getCertificateChain hook:
            //   两者都应非 null、链长=1、subject=CN=Fake(AOSP 非 attestation 默认);cert 非 null 而 chain==null=穿帮。
            field("keystore.cert_chain_consistency",
                "getCertificate vs getCertificateChain 一致(链长=1、CN=Fake)" jLayer {
                    KeystoreCryptoProbe.certChainConsistency()
                },
            )
            // RSA/EC 公钥指纹(聚集锚:跨设备应不同、同设备确定性相同、跨新机应变)。
            field("keystore.xdev_rsa_pubkey_sha256",
                "备份用 RSA 公钥 SHA-256(跨设备应不同)" jLayer { KeystoreCryptoProbe.rsaPubKeyHash() },
            )
            field("keystore.xdev_ec_pubkey_sha256",
                "备份用 EC 公钥 SHA-256(跨设备应不同)" jLayer { KeystoreCryptoProbe.ecPubKeyHash() },
            )
        }

        // ============================================================
        // L. 设备指纹 ID(Phase A) — 商业风控 SDK(同盾/数美/瑞数)用作 deviceId 原子 ID。
        //    ghost 应该给每个 UID/session 分别 spoof,verify 跨调用对比看稳定性。
        // ============================================================
        category("device-ids") {
            // GAID — Google Advertising ID,广告归因核心(reflection 调,避免编译期依赖)
            field("GAID (Google Advertising ID)",
                "AdvertisingIdClient.Info.getId()" jLayer { reflectGetGaid(context) },
            )
            // Widevine L3 device unique ID — DRM 层硬件 ID
            field("Widevine.deviceUniqueId",
                "MediaDrm(EDEF8BA9...).getPropertyByteArray" jLayer { widevineDeviceId() },
            )
            field("Widevine.systemId",
                "MediaDrm.getPropertyString(systemId)" jLayer { widevineProperty("systemId") },
            )
            field("Widevine.securityLevel",
                "MediaDrm.getPropertyString(securityLevel)" jLayer { widevineProperty("securityLevel") },
            )
            // GSF Android ID — com.google.android.gsf.gservices 的 android_id(跟 Settings.Secure.ANDROID_ID 不同)
            field("GSF Android ID",
                "gservices.android_id" jLayer { reflectGetGsfAndroidId(context) },
            )
            // OAID — 国内厂商联盟 ID(华为/小米/OPPO/VIVO 各家 SDK 不同,这里探测类是否存在)
            field("OAID provider available",
                "vendor classes present" jLayer { detectOaidProviders() },
            )
        }

        // ============================================================
        // M. 风控对抗 / Hook 框架检测(Phase B) — 商业 SDK 用来发现注入框架。
        //    ghost-verify 反向跑能发现 ghost 自身没盖住的痕迹。
        // ============================================================
        category("hook-detection") {
            field("magisk.detected",
                "magisk paths + package" jLayer { detectMagisk() },
            )
            field("root.detected",
                "su binary + Build.TAGS + selinux" jLayer { detectRoot() },
            )
            field("frida.detected",
                "/proc/maps grep + tcp 27042" jLayer { detectFrida() },
            )
            field("xposed.detected",
                "XposedBridge class lookup" jLayer { detectXposed() },
            )
            field("lsposed.detected",
                "LSPHooker_/LSPosedBridge class scan" jLayer { detectLsposed() },
            )
            field("debugger.attached",
                "Debug.isDebuggerConnected" jLayer {
                    android.os.Debug.isDebuggerConnected().toString()
                },
                "/proc/self/status TracerPid" pLayer {
                    readTracerPid()?.let { if (it == 0) "false" else "true (pid=$it)" }
                },
            )
            field("emulator.detected",
                "Build.FINGERPRINT + hardware + qemu prop" jLayer { detectEmulator() },
            )
            field("accessibility.enabled_services",
                "Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES" jLayer {
                    Settings.Secure.getString(context.contentResolver,
                        Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
                },
            )
            // Accessibility 多路径检测(FB SDK ACCESSIBILITY_ENABLED 走 isEnabled() Java API,
            // ghost SettingsProviderHook 拦不到这条路径 — 验证是否有泄漏)
            // ★布尔归一化:isEnabled 返回 "true"/"false",Settings/shell 返回 "1"/"0",语义相同但字符串不同
            //   会被一致性检查误判为不一致。归一到 true/false;null/n/a/空(探针失败)→ null 不参与一致性。
            field("accessibility_is_enabled",
                "AccessibilityManager.isEnabled()" jLayer {
                    normBool(runCatching {
                        val mgr = context.getSystemService(Context.ACCESSIBILITY_SERVICE)
                            as android.view.accessibility.AccessibilityManager
                        mgr.isEnabled.toString()
                    }.getOrNull())
                },
                "AccessibilityManager.isTouchExplorationEnabled()" jLayer {
                    normBool(runCatching {
                        val mgr = context.getSystemService(Context.ACCESSIBILITY_SERVICE)
                            as android.view.accessibility.AccessibilityManager
                        mgr.isTouchExplorationEnabled.toString()
                    }.getOrNull())
                },
                "Settings.Secure.accessibility_enabled" jLayer {
                    normBool(Settings.Secure.getString(context.contentResolver, "accessibility_enabled"))
                },
                "popen settings get secure accessibility_enabled" sLayer {
                    normBool(runCatching {
                        Runtime.getRuntime().exec(
                            arrayOf("sh","-c","settings get secure accessibility_enabled")
                        ).inputStream.bufferedReader().use { it.readText().trim() }
                    }.getOrNull())
                },
            )
            field("accessibility_enabled_services_count",
                "AccessibilityManager.getEnabledAccessibilityServiceList(FEEDBACK_ALL).size" jLayer {
                    runCatching {
                        val mgr = context.getSystemService(Context.ACCESSIBILITY_SERVICE)
                            as android.view.accessibility.AccessibilityManager
                        mgr.getEnabledAccessibilityServiceList(
                            android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
                        ).size.toString()
                    }.getOrNull() ?: "n/a"
                },
                "AccessibilityManager.getInstalledAccessibilityServiceList().size" jLayer {
                    runCatching {
                        val mgr = context.getSystemService(Context.ACCESSIBILITY_SERVICE)
                            as android.view.accessibility.AccessibilityManager
                        mgr.installedAccessibilityServiceList.size.toString()
                    }.getOrNull() ?: "n/a"
                },
            )
            field("selinux.mode",
                "/sys/fs/selinux/enforce" nLayer {
                    NativeBridge.readFile("/sys/fs/selinux/enforce", 8).trim()
                        .let { if (it == "1") "enforcing" else if (it == "0") "permissive" else it }
                },
                "shell getenforce" sLayer {
                    Runtime.getRuntime().exec("getenforce").inputStream
                        .bufferedReader().use { it.readLine().orEmpty().trim() }
                },
            )

            // anti-evasion 1:主动抛异常,看 stack trace 是否被 Xposed/hook 框架污染
            // (PoisonGZ 评论:防小白用,正常运行下 stack 不应含 xposed 关键字)
            field("anti_evasion.stacktrace_xposed",
                "throw + catch + grep stack for xposed" jLayer {
                    val hits = mutableListOf<String>()
                    runCatching { throw RuntimeException("anti_evasion_probe") }
                        .onFailure { t ->
                            val keywords = listOf("xposed", "LSPosed", "LSPHooker_",
                                "robv.android", "EdXposed", "Xposed", "frida")
                            for (kw in keywords) {
                                if (t.stackTraceToString().contains(kw, ignoreCase = true)) {
                                    hits += kw
                                }
                            }
                        }
                    if (hits.isEmpty()) "clean" else "hit:${hits.joinToString(",")}"
                },
            )

            // anti-evasion 2:发起一个 ApplicationPackageManager.getPackageInfo 调用,
            // stack trace 应该包含 ApplicationPackageManager 类名;若 ghost LSPosed
            // hook 该方法,trace 里会含 LSPHooker_ApplicationPackageManager 等代理类。
            // (恋空原文 19 楼:"现在风控直接读 maps 提地址,扫内存特征";这是上一代
            //  类名扫描检测,作为低成本兜底)
            field("anti_evasion.pm_call_stack",
                "ApplicationPackageManager.getPackageInfo stack contains LSPHooker_?" jLayer {
                    val hits = mutableListOf<String>()
                    runCatching {
                        val cls = Class.forName("android.app.ApplicationPackageManager")
                        // 反射拿当前 stack,看 hook 框架是否插入代理类
                        val st = Thread.currentThread().stackTrace
                        for (e in st) {
                            val cn = e.className
                            if (cn.contains("LSPHooker_") || cn.contains("Xposed") ||
                                cn.contains("LSPosed") || cn.contains("robv.android")) {
                                hits += "${e.className}.${e.methodName}"
                            }
                        }
                        // 也 probe 一下 PackageManager 调用确实路过 ApplicationPackageManager
                        context.packageManager.getPackageInfo(context.packageName, 0)
                    }
                    if (hits.isEmpty()) "clean" else "hit:${hits.joinToString(";").take(150)}"
                },
            )
        }

        // ============================================================
        // M2. 环境暴露面一致性 — 从真实 app 进程视角验证 Root/Hook/工具链是否仍可见。
        //     重点看同一类痕迹在 path/stat/cmd/proc/PMS 多条路径下是否同源隐藏。
        // ============================================================
        category("env-visibility") {
            val rootArtifactPaths = listOf(
                // /data/adb 裸目录 stock 机也存在(实测),File.exists 两边都 true = 非区分信号,不探;
                //   下面 /data/adb/ksud、modules/* 等才是 root 方案专属 anchor(且对 app blocked 不泄漏)。
                "/data/adb/ksud",
                "/data/adb/modules",
                "/data/adb/modules/abcd",
                "/data/adb/modules/playintegrityfix",
                "/data/adb/modules/riru_lsposed",
                "/data/adb/modules/susfs4ksu",
                "/data/adb/modules/tricky_store",
                "/data/adb/modules/zygisksu",
                "/data/adb/.abcd",
                "/data/adb/lspd",
                "/data/adb/tricky_store",
                "/data/adb/zygisk",
                "/data/adb/zygisksu",
                // /data/system/.a 是 ghost 自己的配置目录,用户判定可接受 → 不纳入探测(不误报为 root 足迹)
            )
            val suPaths = listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/vendor/bin/su",
                "/debug_ramdisk/su",
                "/su/bin/su",
                "/magisk/.core/bin/su",
                "/data/adb/ksu/bin/su",
            )
            val sensitivePkgs = listOf(
                "com.tt.hi",
                "org.auto.auto.v6",
                "org.autojs.autoxjs.v6",
                "moe.nb4a",
                "fun.kitsunebi.kitsunebi4android",
                "com.reqable.android",
                "com.sukisu.ultra",
                "me.weishu.kernelsu",
                "com.rifsxd.ksunext",
                "org.lsposed.manager",
                "org.x.manager",
                "de.robv.android.xposed.installer",
            )

            field("env.uid_context",
                "Process uid/gid + SELinux context + /proc/self/status" jLayer {
                    val status = NativeBridge.readFile("/proc/self/status", 8192)
                    val uid = status.lineSequence().firstOrNull { it.startsWith("Uid:") }?.trim().orEmpty()
                    val gid = status.lineSequence().firstOrNull { it.startsWith("Gid:") }?.trim().orEmpty()
                    val groups = status.lineSequence().firstOrNull { it.startsWith("Groups:") }?.trim().orEmpty()
                    val nn = status.lineSequence().firstOrNull { it.startsWith("NoNewPrivs:") }?.trim().orEmpty()
                    val ctx = NativeBridge.readFile("/proc/self/attr/current", 256)
                        .replace('\u0000', ' ').trim()
                    "uid=${android.os.Process.myUid()} appUid=${context.applicationInfo.uid} ctx=$ctx $uid $gid $groups $nn"
                },
            )

            field("env.su_paths",
                "java/stat/svc/shell path probe over common su locations" jLayer {
                    summarizePathProbes(suPaths)
                },
            )
            field("env.su_command_path",
                "command -v/type/which su" nLayer {
                    val raw = NativeBridge.execShell(
                        "command -v su 2>/dev/null; type su 2>/dev/null; which su 2>/dev/null",
                        1024
                    ).trim()
                    // ★mksh 的 `type su` 找不到时会把 "su not found" 打到 stdout(不是 stderr,躲不掉 2>/dev/null),
                    //   过滤掉这类"没找到"行;剩下只有含真实路径('/')才算真找到 su。否则=clean。
                    val hits = raw.lines().map { it.trim() }
                        .filter { it.isNotEmpty() && it.contains("/") && !it.contains("not found", ignoreCase = true) }
                    if (hits.isEmpty()) "clean" else hits.joinToString("; ")
                },
            )
            field("env.root_artifact_paths",
                "java/stat/svc/shell path probe over /data/adb and module locations" jLayer {
                    summarizePathProbes(rootArtifactPaths)
                },
            )
            field("env.data_adb_listing",
                "ls -la /data/adb* as app uid" nLayer {
                    val out = NativeBridge.execShell(
                        "ls -ld /data/adb /data/adb/modules /data/adb/.abcd 2>&1",
                        2048
                    ).trim()
                    normalizeProbeOutput(out)
                },
            )

            field("env.proc_maps_keywords",
                "/proc/self/maps keyword scan" pLayer {
                    summarizeKeywordLines(NativeBridge.readFile("/proc/self/maps", 65536))
                },
            )
            field("env.proc_smaps_keywords",
                "/proc/self/smaps keyword scan" pLayer {
                    summarizeKeywordLines(NativeBridge.readFile("/proc/self/smaps", 65536))
                },
            )
            field("env.proc_mountinfo_keywords",
                "/proc/self/mountinfo keyword scan" pLayer {
                    summarizeKeywordLines(NativeBridge.readFile("/proc/self/mountinfo", 65536))
                },
            )
            field("env.proc_fd_keywords",
                "/proc/self/fd readlink keyword scan" jLayer {
                    summarizeKeywordLines(readProcSelfFdLinks().joinToString("\n"))
                },
            )
            field("env.proc_cmdline_status",
                "/proc/self/cmdline + selected status lines" pLayer {
                    val cmd = NativeBridge.readFile("/proc/self/cmdline", 512)
                        .replace('\u0000', ' ').trim()
                    val status = NativeBridge.readFile("/proc/self/status", 8192)
                    val selected = status.lineSequence()
                        .filter { line ->
                            line.startsWith("Name:") || line.startsWith("TracerPid:") ||
                                line.startsWith("Uid:") || line.startsWith("Gid:") ||
                                line.startsWith("Groups:") || line.startsWith("Seccomp:") ||
                                line.startsWith("NoNewPrivs:")
                        }
                        .joinToString(" ")
                    "cmdline=${cmd.ifEmpty { "<empty>" }} $selected"
                },
            )
            field("env.proc_other_process_keywords",
                "scan readable /proc/*/cmdline for tool/root keywords" nLayer {
                    val out = NativeBridge.execShell(
                        "for p in /proc/[0-9]*; do c=$(cat \"\$p/cmdline\" 2>/dev/null | tr '\\000' ' '); [ -n \"\$c\" ] && echo \"\$p \$c\"; done",
                        32768
                    )
                    summarizeKeywordLines(out)
                },
            )

            field("env.cmd_service_list",
                "popen service list keyword scan" nLayer {
                    val out = NativeBridge.execShell("service list 2>&1", 16384)
                    val summary = summarizeKeywordLines(out, SERVICE_KEYWORDS)
                    if (summary == "clean" && out.trim().isEmpty()) "clean(empty)"
                    else summary
                },
            )
            field("env.cmd_package_list_sensitive",
                "popen pm/cmd package list packages keyword scan" nLayer {
                    val out = NativeBridge.execShell(
                        "(pm list packages 2>/dev/null; cmd package list packages 2>/dev/null) | sort -u",
                        32768
                    )
                    summarizeKeywordLines(out)
                },
            )
            field("env.getprop_root_keywords",
                "popen getprop keyword scan" nLayer {
                    summarizeKeywordLines(NativeBridge.execShell("getprop 2>/dev/null", 32768))
                },
            )
            field("env.settings_tooling_keys",
                "settings values that often expose accessibility/VPN/dev tooling" nLayer {
                    val keys = listOf(
                        "settings get secure enabled_accessibility_services",
                        "settings get secure accessibility_button_targets",
                        "settings get secure accessibility_shortcut_target_service",
                        "settings get secure default_input_method",
                        "settings get global always_on_vpn_app",
                        "settings get global lockdown_vpn",
                        "settings get global development_settings_enabled",
                        "settings get global adb_enabled",
                    )
                    val out = keys.joinToString("\n") { cmd ->
                        val v = NativeBridge.execShell("$cmd 2>/dev/null", 1024).trim()
                        "$cmd => ${v.ifEmpty { "<empty>" }}"
                    }
                    summarizeKeywordLines(out).takeIf { it != "clean" } ?: out.take(800)
                },
            )
            field("env.pms_direct_sensitive_pkgs",
                "direct PackageManager.getPackageInfo over tool/root packages" jLayer {
                    val hits = sensitivePkgs.mapNotNull { pkg ->
                        runCatching {
                            val pi = context.packageManager.getPackageInfo(pkg, 0)
                            val appInfo = pi.applicationInfo
                            val src = appInfo?.sourceDir ?: ""
                            "$pkg uid=${appInfo?.uid ?: -1} src=${src.takeLast(80)}"
                        }.getOrNull()
                    }
                    if (hits.isEmpty()) "clean" else "${hits.size} visible: ${hits.joinToString(" | ").take(900)}"
                },
            )
        }

        // ============================================================
        // N. 运行时行为指纹(Phase D) — boot count / uptime / 安装时间 等
        //    新设备 install 后立即一键新机 = boot_count 小 + uptime 短 + install 时间近期 = 机器人嫌疑
        // ============================================================
        category("runtime-behavior") {
            field("boot_count",
                "Settings.Global.BOOT_COUNT" jLayer {
                    Settings.Global.getInt(context.contentResolver,
                        Settings.Global.BOOT_COUNT, -1).toString()
                },
            )
            field("uptime_minutes",
                "SystemClock.elapsedRealtime/60000" jLayer {
                    (android.os.SystemClock.elapsedRealtime() / 60_000).toString()
                },
            )
            field("self.firstInstallTime",
                "PackageManager.firstInstallTime" jLayer {
                    context.packageManager.getPackageInfo(context.packageName, 0)
                        .firstInstallTime.toString()
                },
            )
            field("self.lastUpdateTime",
                "PackageManager.lastUpdateTime" jLayer {
                    context.packageManager.getPackageInfo(context.packageName, 0)
                        .lastUpdateTime.toString()
                },
            )
            field("system_time_vs_uptime_drift_ms",
                "(currentTimeMillis - elapsedRealtime - bootTimeMs)" jLayer {
                    val now = System.currentTimeMillis()
                    val up = android.os.SystemClock.elapsedRealtime()
                    val expected = now - up
                    // 真机 expected 应该接近 boot 时刻,稳定;频繁改时间 → 这个数飘
                    expected.toString()
                },
            )
            field("installed_pkg_count",
                "PackageManager.getInstalledPackages.size" jLayer {
                    context.packageManager.getInstalledPackages(0).size.toString()
                },
            )
        }

        // ============================================================
        // O. 风控奇葩检测点(Phase G,基于看雪恋空系列文章)
        //    某宝/某付宝/某多/某东等大厂 SDK 实际用到的"非显而易见"信号。
        //    商业 SDK 用这些点判断:模拟器 / 机器人 / 异常环境。
        // ============================================================
        category("risk-quirks") {
            // 锁屏密码(某宝/某付宝 SDK)— 真用户机 >95% 设密码,模拟器/小号常 false
            // 拆成 2 source:isDeviceSecure 走 ITrustManager binder,isKeyguardSecure 走 IWindowManager.
            // 任一返回 false 就被风控判定异常 → ghost 需要两个 binder service 都 server-hook.
            field("keyguard.is_secure",
                "KM.isDeviceSecure (→ ITrustManager)" jLayer {
                    val km = context.getSystemService(android.content.Context.KEYGUARD_SERVICE)
                        as? android.app.KeyguardManager
                    km?.isDeviceSecure.toString()
                },
                "KM.isKeyguardSecure (→ IWindowManager)" jLayer {
                    val km = context.getSystemService(android.content.Context.KEYGUARD_SERVICE)
                        as? android.app.KeyguardManager
                    km?.isKeyguardSecure.toString()
                },
            )

            // /system/build.prop 修改时间检测(某多/某东 SDK)
            // 真机编译产出的 build.prop mtime 通常是 1970-01 或 2009-01,秒 % 1000 == 0
            // 模拟器 / 魔改 ROM 改 prop 重启后 mtime 是任意时刻,秒 % 1000 != 0
            field("build_prop.mtime_secure",
                "File('/system/build.prop').lastModified()/1000 %1000 == 0" jLayer {
                    val mtimeMs = java.io.File("/system/build.prop").lastModified()
                    if (mtimeMs == 0L) "<unreadable>"
                    else {
                        val secModK = (mtimeMs / 1000) % 1000
                        "secure=${secModK == 0L} (mtime=${mtimeMs}, sec%1000=$secModK)"
                    }
                },
            )

            // 应用商店包名(某多 SDK)— 真机 OEM 应安装对应 OEM 自己的应用市场
            // ghost spoof Build.MANUFACTURER 但没装对应市场 = anchor(eg 装的是 Huawei
            // AppMarket 但 spoof 成 OPPO,跟当前 Build.MANUFACTURER 不一致)
            field("app_market.packages",
                "PackageManager category.APP_MARKET" jLayer {
                    runCatching {
                        val intent = android.content.Intent(android.content.Intent.ACTION_MAIN)
                            .addCategory("android.intent.category.APP_MARKET")
                        context.packageManager.queryIntentActivities(intent, 0)
                            .joinToString(",") { it.activityInfo.packageName }
                    }.getOrElse { "<err> ${it.message}" }
                },
            )

            // 默认输入法(高区分度字段 — 真用户安装第三方输入法多样化)
            field("default_input_method",
                "Settings.Secure.default_input_method" jLayer {
                    android.provider.Settings.Secure.getString(
                        context.contentResolver, "default_input_method") ?: ""
                },
            )

            // 主流 app 安装时间(wx/qq/zfb)— 风控用作"账户老化"判断,
            // 真用户的 wx/zfb 装机时间通常远早于当前时刻;新设备/小号通常 install 很近
            field("major_apps.installtime",
                "wx/qq/zfb/dy firstInstallTime" jLayer {
                    val pkgs = listOf(
                        "com.tencent.mm" to "wechat",
                        "com.tencent.mobileqq" to "qq",
                        "com.eg.android.AlipayGphone" to "alipay",
                        "com.ss.android.ugc.aweme" to "douyin",
                        "com.taobao.taobao" to "taobao",
                    )
                    pkgs.mapNotNull { (pkg, label) ->
                        runCatching {
                            val ts = context.packageManager.getPackageInfo(pkg, 0).firstInstallTime
                            "$label=$ts"
                        }.getOrNull()
                    }.joinToString(",").ifEmpty { "<none-installed>" }
                },
            )

            // 锁屏壁纸是否设置(辅助信号 — 新设备/模拟器很少改)
            field("wallpaper.has_custom",
                "WallpaperManager.getWallpaperInfo != null OR built-in" jLayer {
                    runCatching {
                        val wm = android.app.WallpaperManager.getInstance(context)
                        // builtIn = false 说明用户设了自定义壁纸
                        (wm.wallpaperInfo != null ||
                            wm.getBuiltInDrawable(0, 0, false, 0f, 0f) != null).toString()
                    }.getOrElse { "<denied>" }
                },
            )

            // ===== Phase H: 看雪恋空 thread-265169 图 1 设备指纹大表 =====
            // 商业风控 SDK 实际采集字段,模拟器/小号常默认值,真用户机有随机性

            // 电量(模拟器恒 100% / 永远充电)
            field("battery.level",
                "BatteryManager.BATTERY_PROPERTY_CAPACITY" jLayer {
                    val bm = context.getSystemService(android.content.Context.BATTERY_SERVICE)
                        as? android.os.BatteryManager
                    bm?.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY).toString()
                },
            )
            field("battery.is_charging",
                "BatteryManager.isCharging()" jLayer {
                    val bm = context.getSystemService(android.content.Context.BATTERY_SERVICE)
                        as? android.os.BatteryManager
                    bm?.isCharging.toString()
                },
            )

            // 耳机(真用户常插)
            field("accessory.headphones_plugged",
                "AudioManager.isWiredHeadsetOn" jLayer {
                    @Suppress("DEPRECATION")
                    val am = context.getSystemService(android.content.Context.AUDIO_SERVICE)
                        as? android.media.AudioManager
                    am?.isWiredHeadsetOn.toString()
                },
            )

            // 剪贴板内容(模拟器/小号常空,真用户常有复制内容)
            // Android 10+ 后台读受限,即使能读也只能在 Activity resumed 时
            field("clipboard.has_content",
                "ClipboardManager.hasPrimaryClip" jLayer {
                    runCatching {
                        val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                            as? android.content.ClipboardManager
                        cm?.hasPrimaryClip().toString()
                    }.getOrElse { "<denied>" }
                },
            )

            // 屏幕亮度(模拟器常默认 1.0 或 0)
            field("screen.brightness",
                "Settings.System.SCREEN_BRIGHTNESS" jLayer {
                    android.provider.Settings.System.getInt(
                        context.contentResolver,
                        android.provider.Settings.System.SCREEN_BRIGHTNESS, -1).toString()
                },
            )
        }

        // ============================================================
        // P. 传感器存在性(Phase H,图 4 篡改行为变量)
        //    商业 SDK 探测真机硬件传感器存在性。某些模拟器没硬件传感器 → null
        //    ghost spoof 后即使生成 sensor name list,商业 SDK 调
        //    SensorManager.getDefaultSensor(TYPE) 仍是真机硬件 — 跨源不一致 = anchor
        // ============================================================
        category("sensors-presence") {
            val sm = context.getSystemService(android.content.Context.SENSOR_SERVICE)
                as? android.hardware.SensorManager
            val sensors = listOf(
                "accelerometer" to android.hardware.Sensor.TYPE_ACCELEROMETER,
                "gyroscope"     to android.hardware.Sensor.TYPE_GYROSCOPE,
                "gravity"       to android.hardware.Sensor.TYPE_GRAVITY,
                "magnetic"      to android.hardware.Sensor.TYPE_MAGNETIC_FIELD,
                "proximity"     to android.hardware.Sensor.TYPE_PROXIMITY,
                "light"         to android.hardware.Sensor.TYPE_LIGHT,
                "pressure"      to android.hardware.Sensor.TYPE_PRESSURE,
                "linear_accel"  to android.hardware.Sensor.TYPE_LINEAR_ACCELERATION,
                "rotation"      to android.hardware.Sensor.TYPE_ROTATION_VECTOR,
                "step_counter"  to android.hardware.Sensor.TYPE_STEP_COUNTER,
            )
            for ((label, type) in sensors) {
                field("sensor.${label}_present",
                    "SensorManager.getDefaultSensor($label)" jLayer {
                        (sm?.getDefaultSensor(type) != null).toString()
                    },
                )
            }

            // 指纹硬件(图 4)
            field("sensor.fingerprint_hw_detected",
                "FingerprintManager.isHardwareDetected" jLayer {
                    runCatching {
                        @Suppress("DEPRECATION")
                        val fm = context.getSystemService(android.content.Context.FINGERPRINT_SERVICE)
                            as? android.hardware.fingerprint.FingerprintManager
                        @Suppress("DEPRECATION")
                        fm?.isHardwareDetected.toString()
                    }.getOrElse { "<denied>" }
                },
            )
            // 通过 PackageManager 探测指纹/相机/GPS hardware feature
            for ((label, feature) in listOf(
                "feature.fingerprint" to android.content.pm.PackageManager.FEATURE_FINGERPRINT,
                "feature.camera"      to android.content.pm.PackageManager.FEATURE_CAMERA,
                "feature.location_gps" to android.content.pm.PackageManager.FEATURE_LOCATION_GPS,
                "feature.telephony"   to android.content.pm.PackageManager.FEATURE_TELEPHONY,
                "feature.bluetooth"   to android.content.pm.PackageManager.FEATURE_BLUETOOTH,
                "feature.nfc"         to android.content.pm.PackageManager.FEATURE_NFC,
            )) {
                field(label,
                    "PackageManager.hasSystemFeature" jLayer {
                        context.packageManager.hasSystemFeature(feature).toString()
                    },
                )
            }
        }

        // ============================================================
        // Q. 网络异常变量(Phase H,图 4 篡改行为变量)
        //    黑产挂代理 / VPN / 改 WiFi 是常见手段,商业 SDK 必检
        // ============================================================
        category("network-quirks") {
            field("network.proxy_host",
                "System.getProperty(http.proxyHost)" jLayer {
                    val h = System.getProperty("http.proxyHost") ?: ""
                    val p = System.getProperty("http.proxyPort") ?: ""
                    if (h.isEmpty()) "<none>" else "$h:$p"
                },
            )
            field("network.vpn_active",
                "ConnectivityManager NET_CAPABILITY_NOT_VPN absent" jLayer {
                    runCatching {
                        val cm = context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
                            as? android.net.ConnectivityManager
                        val active = cm?.activeNetwork ?: return@runCatching "false"
                        val caps = cm.getNetworkCapabilities(active) ?: return@runCatching "false"
                        // VPN 激活时 NOT_VPN 能力被 absent
                        (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
                            .toString()
                    }.getOrElse { "<denied>" }
                },
            )
            // 当前已连 WiFi 的 SSID/BSSID/MAC — ghost WifiServiceHook 应 spoof,真值不该泄露
            // GMS / Gmail 等 system app 有 location 权限,这些 API 拿到的是真值,必须 spoof
            // 真用户家里 WiFi SSID 跨次稳定(一辈子不换路由器名);ghost 应该返同样的 spoof 值
            val wm = runCatching {
                context.applicationContext.getSystemService(android.content.Context.WIFI_SERVICE)
                    as? android.net.wifi.WifiManager
            }.getOrNull()
            field("wifi.connected_ssid",
                "WifiManager.connectionInfo.ssid" jLayer {
                    runCatching { wm?.connectionInfo?.ssid ?: "<null>" }.getOrElse { "<denied> ${it.javaClass.simpleName}" }
                },
            )
            field("wifi.connected_bssid",
                "WifiManager.connectionInfo.bssid" jLayer {
                    runCatching { wm?.connectionInfo?.bssid ?: "<null>" }.getOrElse { "<denied> ${it.javaClass.simpleName}" }
                },
            )
            field("wifi.mac_address",
                "WifiManager.connectionInfo.macAddress" jLayer {
                    runCatching { wm?.connectionInfo?.macAddress ?: "<null>" }.getOrElse { "<denied> ${it.javaClass.simpleName}" }
                },
            )
            // WiFi 周围 SSID 数(图 1 wifilnfoList)— 真用户家里常 5-20 个,机器人房常 0-1
            // Android 10+ 要 ACCESS_FINE_LOCATION;Android 13+ 进一步要 NEARBY_WIFI_DEVICES。
            // getScanResults 返回 cache,空时主动 startScan() 再读(Android 9+ 节流到 2min)
            field("wifi.surrounding_count",
                "WifiManager.scanResults (after startScan)" jLayer {
                    runCatching {
                        @Suppress("DEPRECATION")
                        val wm = context.applicationContext
                            .getSystemService(android.content.Context.WIFI_SERVICE)
                            as? android.net.wifi.WifiManager
                        if (wm == null) return@runCatching "<null>"
                        var results = wm.scanResults
                        if (results.isNullOrEmpty()) {
                            @Suppress("DEPRECATION")
                            wm.startScan()  // Android 9+ 节流,可能也是 false
                            Thread.sleep(800)
                            results = wm.scanResults
                        }
                        "${results?.size ?: 0} (wifi_enabled=${wm.isWifiEnabled})"
                    }.getOrElse { "<denied> ${it.javaClass.simpleName}" }
                },
            )
            // DNS 拆 2 独立字段(不做跨源对比 — VPN/代理 active 时两者本来就不相等,
            // 那种"不一致"是有意义的信号,不是 verify bug)
            // 直接派生 dns.via_vpn 字段告诉风控:active DNS != WiFi DHCP DNS = VPN active
            fun activeDns(): String {
                val cm = context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
                    as? android.net.ConnectivityManager
                val active = cm?.activeNetwork ?: return ""
                val lp = cm.getLinkProperties(active) ?: return ""
                return lp.dnsServers.joinToString(",") { it.hostAddress ?: "?" }
            }
            fun dhcpDns(): String {
                @Suppress("DEPRECATION")
                val wm = context.applicationContext
                    .getSystemService(android.content.Context.WIFI_SERVICE)
                    as? android.net.wifi.WifiManager
                @Suppress("DEPRECATION")
                val d = wm?.dhcpInfo ?: return ""
                fun ipStr(i: Int): String = if (i == 0) "" else
                    "${i and 0xff}.${(i shr 8) and 0xff}.${(i shr 16) and 0xff}.${(i shr 24) and 0xff}"
                return listOf(d.dns1, d.dns2).map(::ipStr).filter { it.isNotEmpty() }.joinToString(",")
            }
            field("network.dns.active",
                "ConnectivityManager.linkProperties.dnsServers" jLayer { activeDns() },
            )
            field("network.dns.wifi_dhcp",
                "WifiManager.dhcpInfo.dns1/2" jLayer { dhcpDns() },
            )
            // ★ 关键派生:active DNS 跟 WiFi DHCP DNS 不一致 = VPN/proxy 隧道改了 DNS
            //   商业风控强信号(独立于 NET_CAPABILITY_NOT_VPN 检测,绕得过 VPN 检测的代理这里也漏)
            field("network.dns.via_vpn_or_proxy",
                "active_dns ⊄ wifi_dhcp_dns" jLayer {
                    val a = activeDns(); val w = dhcpDns()
                    when {
                        a.isEmpty() || w.isEmpty() -> "unknown (a=$a, w=$w)"
                        else -> {
                            // ★集合差,不是字符串精确相等:active DNS 里出现了 DHCP 没下发的地址 = 隧道改了 DNS。
                            //   active ⊆ dhcp(active 就是网关那台、dhcp 只是多列了几台)= 正常网关,不算 VPN/代理。
                            val aSet = a.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
                            val wSet = w.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
                            val extra = aSet - wSet
                            if (extra.isEmpty()) "false"
                            else "true (active_only=${extra.joinToString(",")}, active=$a, dhcp=$w)"
                        }
                    }
                },
            )
        }

        // ============================================================
        // network 组:NetworkInterface 真洞 + WifiInfo/DHCP IP 链 + hasTransport
        //   ghost NetworkInterfaceHook 只 hook java.net.NetworkInterface.getAll()
        //   (client 端 in-process),保留 lo+wlan/rmnet、把 addrs 全改 cellIp、删 tun0/ppp;
        //   但不动 getHardwareAddress。采集器直接走 getNetworkInterfaces()(无权限、
        //   绕过 Wifi/Connectivity server hook)看 ghost 呈现:hook 生效=只剩 {lo, wlan/rmnet}
        //   + data IP=cellIp + 无 tun/ppp;失效/泄漏=多网卡 / 隧道网卡 / 真 MAC / IP 不匹配。
        // ============================================================
        category("network-ifaces") {
            // 单次调用 + 捕获诊断:区分 NULL(getAll 空→AOSP 返 null) vs THREW(hook body 崩,哪个异常) vs ok
            var ifaceErr = "ok"
            val ifaces: List<java.net.NetworkInterface> = try {
                val e = java.net.NetworkInterface.getNetworkInterfaces()
                if (e == null) { ifaceErr = "NULL (getAll 返空数组/null → AOSP getNetworkInterfaces 返 null)"; emptyList() }
                else e.toList()
            } catch (t: Throwable) {
                ifaceErr = "THREW ${t.javaClass.name}: ${t.message} | cause=${t.cause?.javaClass?.name}:${t.cause?.message}"
                emptyList()
            }
            field("network.iface_error", "getNetworkInterfaces() null/异常诊断" jLayer { ifaceErr })

            fun isLoopback(n: String) = n == "lo"
            fun isVpnIface(n: String): Boolean {
                val l = n.lowercase()
                return l.startsWith("tun") || l.startsWith("ppp") || l.startsWith("ipsec") ||
                    l.startsWith("pptp") || l.startsWith("wg") || l.startsWith("tap") ||
                    l.startsWith("nordlynx") || l.startsWith("proton")
            }
            // 真机常驻的伪/隧道网卡(不算"额外物理数据网卡")
            fun isVirtual(n: String): Boolean {
                val l = n.lowercase()
                return l.startsWith("dummy") || l.startsWith("sit") || l.startsWith("ip6tnl") ||
                    l.startsWith("ip6_vti") || l.startsWith("ip_vti") || l.startsWith("gre") ||
                    l.startsWith("rmnet_ipa") || l.startsWith("bond") || l.startsWith("ifb") ||
                    l.startsWith("stf") || l.startsWith("ap0")
            }
            fun isDataIface(n: String): Boolean {
                val l = n.lowercase()
                return l.startsWith("wlan") || l.startsWith("rmnet_data") ||
                    l.startsWith("eth") || l.startsWith("ccmni") || l.startsWith("v4-rmnet")
            }
            fun firstIpv4(ni: java.net.NetworkInterface): String? =
                ni.inetAddresses.toList()
                    .firstOrNull { it is java.net.Inet4Address && !it.isLoopbackAddress }
                    ?.hostAddress
            fun hwaddrHex(ni: java.net.NetworkInterface): String? = runCatching {
                ni.hardwareAddress?.joinToString(":") { "%02x".format(it.toInt() and 0xff) }
            }.getOrNull()

            field("network.iface_names",
                "NetworkInterface.getNetworkInterfaces() names(sorted)" jLayer {
                    if (ifaces.isEmpty()) "<none>"
                    else ifaces.map { it.name }.sorted().joinToString(",")
                },
            )
            field("network.iface_dump",
                "per-iface name|up|lo|ipv4s|hwaddr" jLayer {
                    if (ifaces.isEmpty()) "<none>"
                    else ifaces.joinToString(" ; ") { ni ->
                        val up = runCatching { ni.isUp }.getOrNull()
                        val lo = runCatching { ni.isLoopback }.getOrNull()
                        val v4 = ni.inetAddresses.toList()
                            .filterIsInstance<java.net.Inet4Address>()
                            .joinToString(",") { it.hostAddress ?: "?" }
                        val hw = hwaddrHex(ni) ?: "<null>"
                        "${ni.name}|up=$up|lo=$lo|v4=[$v4]|hw=$hw"
                    }.take(1200)
                },
            )
            // primary data iface(wlan/rmnet)IPv4 — 应 == WifiInfo.ip == DhcpInfo.ip == cellIp
            field("network.iface_data_ipv4",
                "first IPv4 of wlan*/rmnet_data*/eth* iface" jLayer {
                    ifaces.filter { isDataIface(it.name) }.firstNotNullOfOrNull { firstIpv4(it) } ?: "<none>"
                },
            )
            // tun0/ppp 存在 = VPN 泄漏(绕过 Connectivity NOT_VPN + transport 双 spoof)
            field("network.iface_vpn_present",
                "any tun*/ppp*/ipsec*/wg* interface present" jLayer {
                    val v = ifaces.filter { isVpnIface(it.name) }.map { it.name }
                    if (v.isEmpty()) "false" else "true (${v.joinToString(",")})"
                },
            )
            // getHardwareAddress 泄漏真 MAC(hook 不改 hwaddr;Android 11+ 通常 redact→null,
            //   非 null 且非 02:00:00:00:00:00 / 全 0 = 真 MAC 泄漏)
            field("network.iface_hwaddr_leak",
                "non-lo iface hardwareAddress != redacted" jLayer {
                    val leaks = ifaces.filter { !isLoopback(it.name) }.mapNotNull { ni ->
                        val hw = hwaddrHex(ni) ?: return@mapNotNull null
                        val norm = hw.lowercase()
                        if (norm == "02:00:00:00:00:00" || norm == "00:00:00:00:00:00") null
                        else "${ni.name}=$hw"
                    }
                    if (leaks.isEmpty()) "false" else "true (${leaks.joinToString(",")})"
                },
            )
            // 带 IPv4 的非虚拟数据网卡数(hook 后应恰好 1:wlan 或 rmnet;>1=hook 未收敛/泄漏)
            field("network.iface_data_count",
                "count of non-lo/non-virtual ifaces with IPv4" jLayer {
                    ifaces.count { ni ->
                        !isLoopback(ni.name) && !isVirtual(ni.name) && !isVpnIface(ni.name) &&
                            firstIpv4(ni) != null
                    }.toString()
                },
            )

            // ── WifiInfo.ipAddress / DhcpInfo(server hook 面,应与 iface IP 同 = cellIp)──
            @Suppress("DEPRECATION")
            val wifiMgr = runCatching {
                context.applicationContext.getSystemService(android.content.Context.WIFI_SERVICE)
                    as? android.net.wifi.WifiManager
            }.getOrNull()
            fun ipStr(i: Int): String = if (i == 0) "0.0.0.0"
                else "${i and 0xff}.${(i shr 8) and 0xff}.${(i shr 16) and 0xff}.${(i shr 24) and 0xff}"
            field("wifi.info_ipaddress",
                "WifiManager.connectionInfo.ipAddress" jLayer {
                    @Suppress("DEPRECATION")
                    runCatching { ipStr(wifiMgr?.connectionInfo?.ipAddress ?: 0) }
                        .getOrElse { "<denied> ${it.javaClass.simpleName}" }
                },
            )
            @Suppress("DEPRECATION")
            val dhcp = runCatching { wifiMgr?.dhcpInfo }.getOrNull()
            field("wifi.dhcp_ipaddress",
                "WifiManager.dhcpInfo.ipAddress" jLayer { dhcp?.let { ipStr(it.ipAddress) } ?: "<null>" },
            )
            field("wifi.dhcp_gateway",
                "WifiManager.dhcpInfo.gateway" jLayer { dhcp?.let { ipStr(it.gateway) } ?: "<null>" },
            )
            field("wifi.dhcp_server",
                "WifiManager.dhcpInfo.serverAddress" jLayer { dhcp?.let { ipStr(it.serverAddress) } ?: "<null>" },
            )
            field("wifi.dhcp_netmask",
                "WifiManager.dhcpInfo.netmask" jLayer { dhcp?.let { ipStr(it.netmask) } ?: "<null>" },
            )

            // ── ConnectivityManager hasTransport(WIFI/CELLULAR/VPN)──
            val cm = runCatching {
                context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
                    as? android.net.ConnectivityManager
            }.getOrNull()
            fun activeCaps(): android.net.NetworkCapabilities? = runCatching {
                val active = cm?.activeNetwork ?: return null
                cm.getNetworkCapabilities(active)
            }.getOrNull()
            field("network.transport_wifi",
                "activeNetwork caps.hasTransport(TRANSPORT_WIFI)" jLayer {
                    activeCaps()?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)?.toString() ?: "<null>"
                },
            )
            field("network.transport_cellular",
                "activeNetwork caps.hasTransport(TRANSPORT_CELLULAR)" jLayer {
                    activeCaps()?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)?.toString() ?: "<null>"
                },
            )
            // 第二 VPN 信号(独立于 network.vpn_active 的 NOT_VPN capability 检测)
            field("network.transport_vpn",
                "activeNetwork caps.hasTransport(TRANSPORT_VPN)" jLayer {
                    activeCaps()?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)?.toString() ?: "<null>"
                },
            )
        }

        // ============================================================
        // I-2b. Sensor 元数据自洽 (group "sensor")
        //   ghost SensorManagerHook.changeSensor 只改 mName/mVendor/mMaxRange/
        //   mResolution 四个字段(见 hook),留真 version/power/minDelay。
        //   伪造 maxRange/resolution = Random.float(maxValue,dp) 均匀随机 [0,maxValue),
        //   常越出真机标准量程/分辨率,且两字段独立随机可倒挂;
        //   name 若走 stringUpper(5) 则是 QFRJU 类裸大写字母乱码。
        //   本 category 采齐 name/maxRange/resolution/version/power/minDelay
        //   供 CrossFieldChecker 做物理自洽 + 乱码判定(SensorManager 无需权限)。
        // ============================================================
        category("sensor-metadata") {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as? android.hardware.SensorManager

            // 裸大写字母块判定:trim 后纯大写字母、无空格、无数字、长 4-10。
            // 真机 sensor name 必带空格(" Accelerometer")或数字(芯片型号 BMI260/AK09918)
            // 或混合大小写;裸大写字母块 = ghost stringUpper() 签名(QFRJU)。
            fun isGarbageName(n: String?): Boolean {
                val s = n?.trim() ?: return false
                return Regex("^[A-Z]{4,10}$").matches(s)
            }

            // 逐传感器采全元组:accelerometer / gyroscope / magnetic
            val keySensors = listOf(
                "accelerometer" to android.hardware.Sensor.TYPE_ACCELEROMETER,
                "gyroscope"     to android.hardware.Sensor.TYPE_GYROSCOPE,
                "magnetic"      to android.hardware.Sensor.TYPE_MAGNETIC_FIELD,
            )
            for ((label, type) in keySensors) {
                val s = sm?.getDefaultSensor(type)
                field("sensor.$label.name",
                    "Sensor($label).getName" jLayer { s?.name ?: "" })
                field("sensor.$label.maxRange",
                    "Sensor($label).getMaximumRange" jLayer { s?.maximumRange?.toString() ?: "" })
                field("sensor.$label.resolution",
                    "Sensor($label).getResolution" jLayer { s?.resolution?.toString() ?: "" })
                // version/power/minDelay: ghost 不改(留真硬件值),采下来供分析 + 未来参考库比对
                field("sensor.$label.version",
                    "Sensor($label).getVersion" jLayer { s?.version?.toString() ?: "" })
                field("sensor.$label.power",
                    "Sensor($label).getPower" jLayer { s?.power?.toString() ?: "" })
                field("sensor.$label.minDelay",
                    "Sensor($label).getMinDelay" jLayer { s?.minDelay?.toString() ?: "" })
            }

            // 全量 name 乱码扫描 — 覆盖未单列的传感器
            val allSensors = sm?.getSensorList(android.hardware.Sensor.TYPE_ALL).orEmpty()
            field("sensor.name_garbage_scan",
                "扫描全部 Sensor.name 找 stringUpper 乱码(裸大写字母块)" jLayer {
                    val bad = allSensors.map { it.name }.filter { isGarbageName(it) }.distinct()
                    if (bad.isEmpty()) "clean(${allSensors.size} sensors)"
                    else "SUSPICIOUS ${bad.size}: ${bad.take(8).joinToString(",")}"
                })

            // 全量 resolution>=maxRange(物理不可能:分辨率是最小刻度)扫描 —
            // ghost 两字段独立随机可倒挂
            // 严格 r > m:触发/一次性传感器(Significant Motion/Step Detector 等)天生
            // maxRange==resolution==1.0(不是连续量程),必须用严格大于排除,否则误报。
            field("sensor.range_resolution_scan",
                "扫描 resolution>maxRange 的传感器(物理不可能;排除 res==range 的触发型)" jLayer {
                    val bad = allSensors.filter {
                        val r = it.resolution; val m = it.maximumRange
                        r > 0f && m > 0f && r > m
                    }.map { "${it.name}(res=${it.resolution}>range=${it.maximumRange})" }
                    if (bad.isEmpty()) "clean" else "IMPOSSIBLE ${bad.size}: ${bad.take(6).joinToString(",")}"
                })
        }

        // ============================================================
        // display_gpu — 屏幕分辨率补链 + GPU 家族/驱动一致性(补覆盖缺口组)
        //   1) mode/supportedModes/stableDisplaySize/realSize 干净 WxH → 喂 RESOLUTION_ALL_EQUAL
        //      (原 display_get_mode_physical/display_get_supported_modes 带 @refreshRate 的 "120.0" 会被
        //       checkAllEqualNormalized 的 \d+ 提取出 0/60/120 污染成非分辨率数字→静默丢弃,故另采干净 WxH)
        //   2) DisplayManagerGlobal.getDisplayInfo:logical(被 wm size 改=spoof) vs physical(真面板,ghost 未 hook)
        //   3) GLES:GLSL(0x8B8C 落真驱动)+ 实 EGL context 串,供 GPU_FAMILY / RENDERER_VS_EGL / GLSL 规则用
        // ============================================================
        category("display_gpu") {
            // ---- 实 EGL14 pbuffer context 取 GL 串 ----
            // ghost GLESHook 只 spoof GL_VENDOR/RENDERER/VERSION/EXTENSIONS,未 hook 0x8B8C(GLSL)→落真驱动。
            // Java GLES10.glGetString 无 GL context 返 null(现有 GL_SHADING_LANGUAGE_VERSION 字段就是 null),
            // 这里自建 pbuffer context 让 glGetString 真返值(纯 framework EGL14,不引依赖)。
            val glCtx: Map<Int, String?> = run {
                val out = HashMap<Int, String?>()
                var dpy = android.opengl.EGL14.EGL_NO_DISPLAY
                var ctx = android.opengl.EGL14.EGL_NO_CONTEXT
                var sfc = android.opengl.EGL14.EGL_NO_SURFACE
                runCatching {
                    dpy = android.opengl.EGL14.eglGetDisplay(android.opengl.EGL14.EGL_DEFAULT_DISPLAY)
                    val ver = IntArray(2)
                    if (android.opengl.EGL14.eglInitialize(dpy, ver, 0, ver, 1)) {
                        val cfgAttr = intArrayOf(
                            android.opengl.EGL14.EGL_RENDERABLE_TYPE, android.opengl.EGL14.EGL_OPENGL_ES2_BIT,
                            android.opengl.EGL14.EGL_SURFACE_TYPE, android.opengl.EGL14.EGL_PBUFFER_BIT,
                            android.opengl.EGL14.EGL_RED_SIZE, 8,
                            android.opengl.EGL14.EGL_GREEN_SIZE, 8,
                            android.opengl.EGL14.EGL_BLUE_SIZE, 8,
                            android.opengl.EGL14.EGL_NONE
                        )
                        val cfgs = arrayOfNulls<android.opengl.EGLConfig>(1)
                        val nc = IntArray(1)
                        if (android.opengl.EGL14.eglChooseConfig(dpy, cfgAttr, 0, cfgs, 0, 1, nc, 0) && nc[0] > 0) {
                            val ctxAttr = intArrayOf(android.opengl.EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, android.opengl.EGL14.EGL_NONE)
                            ctx = android.opengl.EGL14.eglCreateContext(dpy, cfgs[0], android.opengl.EGL14.EGL_NO_CONTEXT, ctxAttr, 0)
                            val pbAttr = intArrayOf(android.opengl.EGL14.EGL_WIDTH, 1, android.opengl.EGL14.EGL_HEIGHT, 1, android.opengl.EGL14.EGL_NONE)
                            sfc = android.opengl.EGL14.eglCreatePbufferSurface(dpy, cfgs[0], pbAttr, 0)
                            if (android.opengl.EGL14.eglMakeCurrent(dpy, sfc, sfc, ctx)) {
                                for (k in intArrayOf(GLES10.GL_VENDOR, GLES10.GL_RENDERER, GLES10.GL_VERSION, 0x8B8C)) {
                                    out[k] = runCatching { GLES10.glGetString(k) }.getOrNull()
                                }
                            }
                        }
                    }
                }
                // teardown(务必解绑,避免影响宿主线程)
                runCatching {
                    if (dpy != android.opengl.EGL14.EGL_NO_DISPLAY) {
                        android.opengl.EGL14.eglMakeCurrent(dpy, android.opengl.EGL14.EGL_NO_SURFACE,
                            android.opengl.EGL14.EGL_NO_SURFACE, android.opengl.EGL14.EGL_NO_CONTEXT)
                        if (sfc != android.opengl.EGL14.EGL_NO_SURFACE) android.opengl.EGL14.eglDestroySurface(dpy, sfc)
                        if (ctx != android.opengl.EGL14.EGL_NO_CONTEXT) android.opengl.EGL14.eglDestroyContext(dpy, ctx)
                        android.opengl.EGL14.eglTerminate(dpy)
                    }
                }
                out
            }

            // ---- DisplayManagerGlobal.getDisplayInfo(0):hidden API,ghost DisplayHook 未 hook 它 ----
            val diObj: Any? = runCatching {
                val cls = Class.forName("android.hardware.display.DisplayManagerGlobal")
                val inst = cls.getMethod("getInstance").invoke(null)
                cls.getMethod("getDisplayInfo", Int::class.javaPrimitiveType).invoke(inst, 0)
            }.getOrNull()

            // ---------- 分辨率补链(干净 WxH,喂 RESOLUTION_ALL_EQUAL)----------
            // Display.getMode() — ghost 改 mWidth/mHeight → spoof(去掉 refreshRate 噪声只留 WxH)
            field("display_gpu.mode_physical_size",
                "Display.getMode().physicalWidth x physicalHeight" jLayer {
                    @Suppress("DEPRECATION")
                    val m = (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay.mode
                    "${m.physicalWidth}x${m.physicalHeight}"
                },
            )
            // Display.getSupportedModes() — 取物理面积最大 mode 的 WxH(真机各 mode 物理分辨率相同)
            field("display_gpu.supported_modes_size",
                "Display.getSupportedModes() 最大 physical WxH" jLayer {
                    @Suppress("DEPRECATION")
                    val modes = (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay.supportedModes
                    modes.maxByOrNull { it.physicalWidth.toLong() * it.physicalHeight }
                        ?.let { "${it.physicalWidth}x${it.physicalHeight}" }
                },
            )
            // DisplayManager.getStableDisplaySize — GMS 主路径(ghost hook)
            field("display_gpu.stable_display_size",
                "DisplayManager.getStableDisplaySize" jLayer {
                    runCatching {
                        val dmgr = context.getSystemService(Context.DISPLAY_SERVICE)
                        val pt = dmgr.javaClass.getMethod("getStableDisplaySize").invoke(dmgr) as android.graphics.Point
                        "${pt.x}x${pt.y}"
                    }.getOrNull()
                },
            )
            // Display.getRealSize — 未直 hook,但 wm size 改 logical → 应=spoof
            field("display_gpu.real_size",
                "Display.getRealSize" jLayer {
                    val pt = android.graphics.Point()
                    @Suppress("DEPRECATION")
                    (context.getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay.getRealSize(pt)
                    "${pt.x}x${pt.y}"
                },
            )

            // ---------- DisplayManagerGlobal.getDisplayInfo logical vs physical ----------
            // logical:setForcedDisplaySize 改的就是它 → spoof;physical:走 DisplayInfo.getMode() 真面板(ghost 未 hook)
            field("display_gpu.dmg_logical_size",
                "DisplayInfo.logicalWidth x logicalHeight (wm size 改 → spoof)" jLayer {
                    diObj?.let { info ->
                        val ic = info.javaClass
                        fun fi(n: String) = runCatching {
                            ic.getDeclaredField(n).apply { isAccessible = true }.getInt(info)
                        }.getOrDefault(-1)
                        val w = fi("logicalWidth"); val h = fi("logicalHeight")
                        if (w > 0 && h > 0) "${w}x${h}" else null
                    }
                },
            )
            field("display_gpu.dmg_physical_size",
                "DisplayInfo.getMode().physicalWidth x physicalHeight (真物理,ghost 未 hook getDisplayInfo)" jLayer {
                    diObj?.let { info ->
                        runCatching {
                            val mode = info.javaClass.getMethod("getMode").invoke(info)
                            val pw = mode.javaClass.getMethod("getPhysicalWidth").invoke(mode) as Int
                            val ph = mode.javaClass.getMethod("getPhysicalHeight").invoke(mode) as Int
                            if (pw > 0 && ph > 0) "${pw}x${ph}" else null
                        }.getOrNull()
                    }
                },
            )

            // ---------- GLES:GLSL(0x8B8C 落真驱动)+ 实上下文串 ----------
            field("display_gpu.gl_shading_language_version",
                "EGL14 ctx + GLES10.glGetString(GL_SHADING_LANGUAGE_VERSION=0x8B8C)" jLayer { glCtx[0x8B8C] },
            )
            // 实上下文 vendor/renderer/version(单源信息项,便于人工核对 GLSL/family 规则)
            field("display_gpu.gl_strings_ctx",
                "EGL14 ctx vendor|renderer|version" jLayer {
                    "vendor=${glCtx[GLES10.GL_VENDOR]} | renderer=${glCtx[GLES10.GL_RENDERER]} | version=${glCtx[GLES10.GL_VERSION]}"
                },
            )
        }

        // ============================================================
        // installsource — ComputerEngine 安装来源核验面(PI 安装来源核心)
        //   对照 ghost:ComputerEngineHook.hook_getInstallSourceInfo /
        //   hook_getInstallerPackageName —— 对被 farm 的 caller 把本 app 的
        //   InstallSourceInfo.initiating/installingPackageName 改成 com.android.vending,
        //   initiatingPackageSigningInfo 塞【真 vending】SigningInfo;legacy
        //   getInstallerPackageName 同样返 com.android.vending。
        //   采集本 app(context.packageName)的完整 installer 链,靠双源 field 自动
        //   查:(a)三条读路径是否都被改成 Play(某路径漏 hook = divergence);
        //   (b)伪造的 initiating 签名是否== 真 vending 签名(ghost 若 getVendingSigningInfo
        //   失败/塞错 = cert 对不上)。
        // ============================================================
        category("installsource") {
            val self = context.packageName
            val pm = context.packageManager
            val VENDING = "com.android.vending"

            // 一个 SigningInfo → 规范化指纹(所有 signer 的 cert-SHA256,排序去序拼接),两源可比。
            fun sigFingerprint(si: android.content.pm.SigningInfo?): String? {
                if (si == null) return null
                val sigs: Array<android.content.pm.Signature>? =
                    si.apkContentsSigners?.takeIf { it.isNotEmpty() } ?: si.signingCertificateHistory
                if (sigs.isNullOrEmpty()) return null
                val md = java.security.MessageDigest.getInstance("SHA-256")
                return sigs.map { s ->
                    md.reset()
                    md.digest(s.toByteArray()).joinToString("") { b -> "%02x".format(b) }
                }.sorted().joinToString(",")
            }

            // 单次读取 InstallSourceInfo(NameNotFound / SecurityException 时为 null)。
            val isi: android.content.pm.InstallSourceInfo? =
                runCatching { pm.getInstallSourceInfo(self) }.getOrNull()
            // legacy(deprecated)installer,单独 runCatching(未装/不可读时 null)。
            @Suppress("DEPRECATION")
            val legacyInstaller: String? = runCatching { pm.getInstallerPackageName(self) }.getOrNull()

            // ── installer 链:三条读路径同一逻辑值(都应 = com.android.vending)。
            //    ghost 若只 hook getInstallSourceInfo 漏了 getInstallerPackageName(或反之),
            //    此 field 自动跨源 size>1 = inconsistent = 漏 hook 泄漏。
            field("installsource.installer_chain",
                "PackageManager.getInstallerPackageName(self) [deprecated]" jLayer { legacyInstaller },
                "InstallSourceInfo.getInstallingPackageName(self)" jLayer { isi?.installingPackageName },
                "InstallSourceInfo.getInitiatingPackageName(self)" jLayer { isi?.initiatingPackageName },
            )

            // ── initiating 签名:ghost 塞的 initiatingPackageSigningInfo 应 == 真 vending 签名。
            //    左源=OS 报告的 initiating 签名(ghost 已替换成真 vending),右源=直读
            //    com.android.vending 真实签名。两者不等 = ghost 用了错 cert(或 vending 未装
            //    导致 getVendingSigningInfo 返 null)。自动跨源查一致。
            field("installsource.initiating_signing_sha256",
                "InstallSourceInfo.getInitiatingPackageSigningInfo() cert-SHA256(sorted)" jLayer {
                    sigFingerprint(isi?.initiatingPackageSigningInfo)
                },
                "getPackageInfo(com.android.vending, GET_SIGNING_CERTIFICATES) cert-SHA256(sorted)" jLayer {
                    val pi = pm.getPackageInfo(VENDING,
                        android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                    sigFingerprint(pi?.signingInfo)
                },
            )

            // ── 语义辅助字段(供跨字段规则用)──
            field("installsource.initiating_signing_present",
                "isi.getInitiatingPackageSigningInfo() != null" jLayer {
                    (isi?.initiatingPackageSigningInfo != null).toString()
                },
            )
            field("installsource.vending_installed",
                "getPackageInfo(com.android.vending) 是否可见/已装" jLayer {
                    runCatching {
                        val pi = pm.getPackageInfo(VENDING, 0)
                        "true (v=${pi.versionName})"
                    }.getOrDefault("false")
                },
            )
            field("installsource.originating",
                "InstallSourceInfo.getOriginatingPackageName(self)(Play 装应为 null)" jLayer {
                    isi?.originatingPackageName ?: "<null>"
                },
            )
            // ghost 当前未 hook getUpdateOwnerPackageName(API34)→ 若曾被非-Play 更新会泄漏真实更新者。
            field("installsource.update_owner",
                "InstallSourceInfo.getUpdateOwnerPackageName(self) [API34+, ghost 未 spoof]" jLayer {
                    if (android.os.Build.VERSION.SDK_INT < 34) "<n/a pre-34>"
                    else (isi?.updateOwnerPackageName ?: "<null>")
                },
            )
        }

        // ============================================================
        // misc-coverage — 补 3 项缺口:
        //   (1) SettingsProvider android_id: provider API(hooked uid 被 spoof)vs 直读 settings_ssaid.xml 真值
        //   (2) PackageRelocator: 本 app nativeLibraryDir / splitSourceDirs / 全路径 token 快照(跨会话 diff 交给别处)
        //   (accessibility 项无新采集,仅 CrossFieldChecker 加规则)
        // ============================================================
        category("misc-coverage") {
            // ---- (1) android_id 双源:SettingsProvider spoof vs settings_ssaid.xml 真值 ----
            // ghost SettingsProviderHook.replaceValueByKey("android_id") 只改 provider 返回值(hooked uid),
            // 从不重写磁盘 /data/system/users/0/settings_ssaid.xml。∴ 直读文件拿到的是真 ssaid,与 API 值不符=穿帮。
            // 文件是 root-only(system:system 0600),app uid 直读必 EACCES → native 源大概率 null(runCatching 兜);
            // su cat 是 ground-truth 路径(farming 设备恒 root)。任一真值源可读且 ≠ API 值 → 双源 field 自动判不一致。
            val myPkg = context.packageName
            // Android 12+ settings_ssaid.xml 是 ABX(二进制 XML),但属性字符串(package/ssaid)以 ASCII 内嵌,
            // 且 ABX 里 value 属性紧邻 package 之前。兼容明文 XML(老机/备份)与 ABX 两种格式。
            val parseSsaid = fun(raw: String): String? {
                if (raw.isBlank()) return null
                // 1) 明文 XML: <setting ... package="myPkg" ... value="XXXXXXXXXXXXXXXX"/>
                Regex("<setting\\b[^>]*>").findAll(raw)
                    .map { it.value }
                    .firstOrNull { t -> Regex("package=\"([^\"]*)\"").find(t)?.groupValues?.get(1) == myPkg }
                    ?.let { t -> Regex("value=\"([0-9A-Fa-f]{16})\"").find(t)?.groupValues?.get(1) }
                    ?.let { return it }
                // 2) ABX 二进制: 定位 pkg 名,取其前方最近的 16-hex token(= value 属性,ssaid 恒 16 hex)
                val idx = raw.indexOf(myPkg)
                if (idx < 0) return null
                val before = raw.substring(maxOf(0, idx - 48), idx)
                return Regex("[0-9A-Fa-f]{16}").findAll(before).lastOrNull()?.value
            }
            field("android_id.file_vs_api",
                "Settings.Secure.ANDROID_ID(hooked uid → SettingsProvider spoof)" jLayer {
                    Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
                },
                "settings_ssaid.xml 直读(native syscall,真值;无 root 时 EACCES→null)" nLayer {
                    parseSsaid(NativeBridge.readFile("/data/system/users/0/settings_ssaid.xml", 262144))
                },
                // ★su 源必须超时保护:app fork su 若需交互授权/授权被 newphone 重置会**永久阻塞**整个采集线程
                //   (实测 cycle 后挂死);用 Future 限 3s,超时 cancel,读不到就 null(不参与一致性)。
                "settings_ssaid.xml via su cat(root ground-truth,3s 超时防挂)" sLayer {
                    val ex = java.util.concurrent.Executors.newSingleThreadExecutor()
                    val fut = ex.submit(java.util.concurrent.Callable {
                        val p = Runtime.getRuntime()
                            .exec(arrayOf("su", "-c", "cat /data/system/users/0/settings_ssaid.xml"))
                        try { p.inputStream.bufferedReader().use { it.readText() } } finally { p.destroy() }
                    })
                    val out = try {
                        fut.get(3, java.util.concurrent.TimeUnit.SECONDS)
                    } catch (t: Throwable) { fut.cancel(true); null } finally { ex.shutdownNow() }
                    if (out.isNullOrEmpty()) null else parseSsaid(out)
                },
            )

            // ---- (2) PackageRelocator 路径快照(单源,跨会话 diff 交给别处)----
            // relocator 批量 mv /data/app/~~token 并反射 sweep PMS 的 codePath/nativeLibraryDir/splitCodePaths。
            // 真机群每台 token 唯一;install-once 复用 → 同 app token 跨"一键新机"恒定 = 物理机牧场信号。
            // 这些字段只做快照,由外部跨会话对比:恒定=牧场暴露,跨新机变=per-device 派生生效(安全)。
            field("relocator.self_native_lib_dir",
                "applicationInfo.nativeLibraryDir(relocator sweep 的路径之一;跨新机应变)" jLayer {
                    context.applicationInfo.nativeLibraryDir ?: "<none>"
                },
            )
            field("relocator.self_split_dirs",
                "applicationInfo.splitSourceDirs(relocator sweep splitCodePaths;跨新机应变)" jLayer {
                    context.applicationInfo.splitSourceDirs?.joinToString(",")?.ifEmpty { null } ?: "<no-splits>"
                },
            )
            field("relocator.self_path_tokens",
                "本 app base/split/nativeLib 的 /data/app ~~outer/pkg-inner token(跨会话快照:恒定=牧场路径指纹,应跨新机变)" jLayer {
                    val ai = context.applicationInfo
                    val paths = mutableListOf<String>()
                    ai.sourceDir?.let { paths.add(it) }
                    ai.splitSourceDirs?.let { paths.addAll(it) }
                    ai.nativeLibraryDir?.let { paths.add(it) }
                    val tokens = paths.mapNotNull { p ->
                        Regex("/data/app/(~~[^/]+)/([^/]+)").find(p)?.let { "${it.groupValues[1]}/${it.groupValues[2]}" }
                    }.distinct().sorted()
                    if (tokens.isEmpty()) "<no-data-app-token:${paths.joinToString(";").take(80)}>"
                    else tokens.joinToString(",")
                },
            )
        }

        // ============================================================
        // TLS / JA3(聚集审计悬案:JA3 spoof 是否覆盖 Java SSLSocket/Conscrypt 路径)
        //   ghost native hook libssl.so 的 SSL_CTX_set_cipher_list/set1_curves_list/SSL_CTX_new
        //   → 改 ClientHello 的 cipher/curve/alpn 顺序,让 JA3 跟 deviceInfo seed 走(per-identity)。
        //   Conscrypt(HttpsURLConnection/SSLSocket)用 /apex/com.android.conscrypt/lib64/libssl.so=hook 目标。
        //   本采集器走 conscrypt 打 tls.peet.ws echo 拿**服务端看到的真 ClientHello 指纹**:
        //   - ja3_hash_wire / ja3_wire_raw:风控真正 TLS 指纹用的信号,跨身份应变(spoof 生效)。
        //     ★判定:ja3_wire_raw 的 cipher 段应等于 ghost 推的 spoof 列表顺序,而非 Conscrypt 默认顺序。
        //   - enabled_ciphers_sha1_javaapi:SSLSocket.getEnabledCipherSuites(握手前的 Java API 配置列表),
        //     它是 Android/Conscrypt 版本恒定的(全设备一样)→ 跨身份恒定属**预期无害**、非 per-device 聚集锚
        //     (类比 root_pubkey 全球恒定);风控 TLS 指纹用 wire ClientHello,不用这个 API 列表。
        // ============================================================
        category("tls-ja3") {
            val fetchPeet = fun(): org.json.JSONObject? {
                val ex = java.util.concurrent.Executors.newSingleThreadExecutor()
                val fut = ex.submit(java.util.concurrent.Callable {
                    val c = java.net.URL("https://tls.peet.ws/api/clean").openConnection()
                            as javax.net.ssl.HttpsURLConnection
                    c.connectTimeout = 8000; c.readTimeout = 8000
                    try { org.json.JSONObject(c.inputStream.bufferedReader().use { it.readText() }) }
                    finally { c.disconnect() }
                })
                return try { fut.get(12, java.util.concurrent.TimeUnit.SECONDS) }
                    catch (t: Throwable) { fut.cancel(true); null } finally { ex.shutdownNow() }
            }
            val peet = fetchPeet()   // 一次握手,多字段共享
            field("tls.ja3_hash_wire",
                "HttpsURLConnection(Conscrypt)→tls.peet.ws 的 ja3_hash(服务端看到的真 ClientHello;JA3 spoof 生效则跨身份变)" jLayer {
                    peet?.optString("ja3_hash")?.ifEmpty { null }
                },
            )
            field("tls.ja3_wire_raw",
                "同上 ja3 数值串(cipher/ext/curve 列表;★其 cipher 段应=ghost spoof 顺序而非 Conscrypt 默认)" jLayer {
                    peet?.optString("ja3")?.ifEmpty { null }
                },
            )
            field("tls.peetprint_hash_wire",
                "peetprint_hash(比 JA3 更细,含 alpn/curves 顺序;跨身份应变)" jLayer {
                    peet?.optString("peetprint_hash")?.ifEmpty { null }
                },
            )
            field("tls.enabled_ciphers_sha1_javaapi",
                "SSLSocket.getEnabledCipherSuites 的 sha1(握手前 Java API 配置列表;Android/Conscrypt 版本恒定=全设备一样→跨身份恒定属预期非聚集锚)" jLayer {
                    val s = javax.net.ssl.SSLSocketFactory.getDefault().createSocket() as javax.net.ssl.SSLSocket
                    val list = try { s.enabledCipherSuites.joinToString(",") } finally { runCatching { s.close() } }
                    java.security.MessageDigest.getInstance("SHA-1").digest(list.toByteArray())
                        .joinToString("") { "%02x".format(it) }
                },
            )
            field("tls.enabled_protocols_javaapi",
                "SSLSocket.getEnabledProtocols(Java API,版本恒定)" jLayer {
                    val s = javax.net.ssl.SSLSocketFactory.getDefault().createSocket() as javax.net.ssl.SSLSocket
                    try { s.enabledProtocols.joinToString(",") } finally { runCatching { s.close() } }
                },
            )
        }

        // ============================================================
        // Q. 云真机桌面暴露面
        //   目标 app 应看到原 OEM HOME、看不到 Ghost 包；从云桌面点击启动时，公开
        //   Activity.getReferrer() 也必须与其看到的 HOME 包一致，不能泄漏 com.tt.hi。
        // ============================================================
        category("cloud-phone") {
            val pm = context.packageManager
            val homeIntent = android.content.Intent(android.content.Intent.ACTION_MAIN)
                .addCategory(android.content.Intent.CATEGORY_HOME)
            val resolvedHome = runCatching {
                pm.resolveActivity(homeIntent, 0)?.activityInfo?.let {
                    android.content.ComponentName(it.packageName, it.name).flattenToShortString()
                }
            }.getOrNull()
            val resolvedHomePackage = resolvedHome?.substringBefore('/')
            val homeCandidates = runCatching {
                pm.queryIntentActivities(homeIntent, 0)
                    .mapNotNull { it.activityInfo?.let { ai -> "${ai.packageName}/${ai.name}" } }
                    .distinct()
                    .sorted()
            }.getOrElse { emptyList() }
            val ghostVisible = runCatching {
                pm.getPackageInfo(GHOST_PACKAGE, 0)
                true
            }.getOrDefault(false)
            val referrerPackage = launchReferrer?.let {
                runCatching { android.net.Uri.parse(it).authority }.getOrNull()
            }

            field("cloud.home_resolved",
                "PackageManager.resolveActivity(MAIN+HOME)" jLayer {
                    resolvedHome ?: "<none>"
                },
            )
            field("cloud.home_candidates",
                "PackageManager.queryIntentActivities(MAIN+HOME)" jLayer {
                    if (homeCandidates.isEmpty()) "<none>" else homeCandidates.joinToString(",")
                },
            )
            field("cloud.ghost_package_visible",
                "PackageManager.getPackageInfo(com.tt.hi)" jLayer { ghostVisible.toString() },
            )
            field("cloud.launch_referrer",
                "Activity.getReferrer() captured before background collection" jLayer {
                    launchReferrer ?: "<none>"
                },
            )
            field("cloud.launch_identity_consistency",
                "referrer authority == resolved HOME package" jLayer {
                    when {
                        !launchReferrerExplicit -> "not-tested(no explicit launch referrer)"
                        launchReferrer == null -> "MISMATCH explicit referrer=<none>"
                        resolvedHomePackage == null ->
                            "MISMATCH home=<none> referrer=${referrerPackage ?: launchReferrer}"
                        referrerPackage == resolvedHomePackage -> "ok ($resolvedHomePackage)"
                        else ->
                            "MISMATCH home=$resolvedHomePackage referrer=${referrerPackage ?: launchReferrer}"
                    }
                },
            )
        }

        // ============================================================
        // R. APP 清单变量(Phase H,图 4 — 黑产工具识别)
        //    商业 SDK 探测黑产工具类 app 是否安装,直接判定用户类型
        //    Android 11+ 包可见性需要 <queries> 声明,getPackageInfo 会抛
        //    NameNotFoundException;verify 没声明这些 → 永远未装(false positive)。
        //    用 getInstalledPackages 全列表搜更可靠(verify 有 QUERY_ALL_PACKAGES 才行)
        // ============================================================
        category("app-presence") {
            val installedPkgs = runCatching {
                context.packageManager.getInstalledPackages(0).map { it.packageName }.toSet()
            }.getOrElse { emptySet() }

            // 每个 risk 类两个匹配维度:exact(精确包名)+ keywordHints(任一子串命中即算)。
            // 精确匹配漏率高 — 同类工具多种发行版/分支(SukiSU、KernelSU、MMRL 各自一个 pkg);
            // keyword fallback 兜底,出现新变种也能识别。命中后字段值列出实际包名供排查。
            data class RiskRule(val exact: Set<String>, val keywordHints: Set<String>)
            val riskCategories = mapOf(
                "loan" to RiskRule(
                    exact = setOf(
                        "com.tencent.lemon", "com.youxiabank.pro", "com.jdcn.fido.appdownloader",
                        "com.alibaba.amap", "com.haier.cellularData",
                    ),
                    keywordHints = setOf("loan", "jiekuan", "daikuan", "huabei"),
                ),
                "sms_bomber" to RiskRule(
                    exact = setOf("com.cjwsc.smsbomber", "io.github.snhua.smsbom", "com.sms.bomber"),
                    keywordHints = setOf("smsbom", "smsbomber"),
                ),
                "location_spoof" to RiskRule(
                    exact = setOf(
                        "com.lerist.fakelocation", "com.evozi.injector", "com.theappninjas.fakegpsjoystick",
                        "com.lexa.fakegps", "com.fakegps.mock", "com.incorporateapps.fakegps_route",
                    ),
                    keywordHints = setOf("fakegps", "fakelocation", "mocklocation"),
                ),
                "phone_changer" to RiskRule(
                    exact = setOf("com.unison.phone.changer", "com.fakecall.app"),
                    keywordHints = setOf("phonechanger", "fakecall"),
                ),
                "gambling" to RiskRule(
                    exact = setOf("com.thirteen.poker", "com.qcplay.dz"),
                    keywordHints = setOf("poker", "casino", "doudizhu"),
                ),
                "automation" to RiskRule(
                    // org.auto.auto.v6 = AutoX.js 国内分支;auto.js.com.stardust = AutoJS 主线
                    exact = setOf(
                        "com.zzz.acc", "io.appium.settings", "io.appium.uiautomator2.server",
                        "com.willowtreeapps.fuzz", "ru.yanus171.android.LaunchAutomate",
                        "com.qihoo.autoclick", "auto.js.com.stardust", "org.auto.auto.v6",
                    ),
                    keywordHints = setOf("autojs", "auto.js", "autoclick", "uiautomator", "appium"),
                ),
                "root_manager" to RiskRule(
                    // 加 SukiSU(KernelSU 衍生)、MMRL、APatch 等社区分支
                    exact = setOf(
                        "com.topjohnwu.magisk", "me.weishu.kernelsu", "io.github.huskydg.magisk",
                        "com.sukisu.ultra", "com.dergoogler.mmrl", "me.bmax.apatch",
                    ),
                    keywordHints = setOf("magisk", "kernelsu", "sukisu", "apatch"),
                ),
                "hook_framework" to RiskRule(
                    // Xposed / LSPosed / Frida 管理器或 client app
                    exact = setOf(
                        "de.robv.android.xposed.installer", "org.lsposed.manager",
                        "org.lsposed.lspatch", "io.va.exposed", "me.iacn.biliroaming",
                    ),
                    keywordHints = setOf("xposed", "lsposed", "lspatch", "frida"),
                ),
                "vpn_proxy" to RiskRule(
                    // 代理/翻墙工具(影响 IP / DNS / 网络指纹)
                    exact = setOf(
                        "moe.nb4a", "com.github.shadowsocks", "com.v2ray.ang",
                        "fun.kitsunebi.kitsunebi4android", "com.github.metacubex.clash.meta",
                        "com.github.kr328.clash", "io.nekohasekai.sfa", "app.nekoray.android",
                    ),
                    keywordHints = setOf(
                        "v2ray", "shadowsocks", "clash", "nekobox", "nekoray", "kitsunebi",
                        "trojan", "wireguard", "xray", "outline",
                    ),
                ),
                "sniff_capture" to RiskRule(
                    // 抓包/调试代理工具
                    exact = setOf(
                        "com.reqable.android", "app.charles.proxy", "com.guoshi.httpcanary",
                        "com.minhui.networkcapture", "com.evbadroid.proxymon",
                    ),
                    keywordHints = setOf("reqable", "httpcanary", "charles", "fiddler", "mitmproxy"),
                ),
            )

            for ((cat, rule) in riskCategories) {
                val hits = installedPkgs.filter { pkg ->
                    pkg in rule.exact || rule.keywordHints.any { kw -> kw in pkg.lowercase() }
                }
                field("app.has_$cat",
                    "exact + keyword over getInstalledPackages" jLayer {
                        if (hits.isEmpty()) "false" else "true (${hits.joinToString(",")})"
                    },
                )
            }
            // 汇总所有命中(独立类汇总,方便一眼看出整机敏感 app 数量)
            field("app.sensitive_visible",
                "exact+keyword union" jLayer {
                    val allHits = installedPkgs.filter { pkg ->
                        riskCategories.values.any { r ->
                            pkg in r.exact || r.keywordHints.any { kw -> kw in pkg.lowercase() }
                        }
                    }
                    if (allHits.isEmpty()) "0" else "${allHits.size} (${allHits.joinToString(",")})"
                },
            )
            field("app.installed_count",
                "getInstalledPackages.size" jLayer { installedPkgs.size.toString() },
            )

            // ── M0b:重构验收探针 ──
            // ★peer_visible:verify 自己是 scoped(被 hook)app,查一组常见 farmed/社交 app 是否可见。
            //   隐藏 bug(勾选的 farmed app 互相隐藏)修好后,已装的这些应全可见。用户对照"实际装了哪些"判定:
            //   装了却 not-visible = 隐藏 bug 未修;没装的 not-visible 是正常。
            field("app.peer_visible",
                "getPackageInfo(farmed/社交 app) 从 verify(scoped caller)视角" jLayer {
                    val peers = listOf(
                        "com.twitter.android", "com.instagram.android", "com.facebook.katana",
                        "com.facebook.orca", "com.whatsapp", "com.snapchat.android",
                        "com.zhiliaoapp.musically", "com.google.android.youtube",
                        "com.google.android.gm", "com.android.chrome",
                        "com.google.android.apps.maps", "com.android.vending",
                    )
                    val pm = context.packageManager
                    val vis = peers.filter {
                        runCatching { pm.getPackageInfo(it, 0); true }.getOrDefault(false)
                    }
                    val hid = peers - vis.toSet()
                    "visible=${vis.size}/${peers.size} | not-visible=[${hid.joinToString(",")}]"
                },
            )
            // ★sensitive_pkg_visibility:从 scoped(被 hook)caller 视角,逐个 getPackageInfo 探测【无条件敏感包】——
            //   RE/root/hook/抓包/自动化/隐秘相机/attestation 检查器,它们在任何 farm 设备上对风控 caller 都【绝不该可见】,
            //   任一 visible = 隐藏机制漏洞。★不含 farm 社交(twitter/whatsapp/ins…)——那些在自己模拟设备上本就应可见,
            //   混进来会假阳性(其可见性正确性由邻近 app.peer_visible 按 per-device 不变量单独判)。
            field("app.sensitive_pkg_visibility",
                "getPackageInfo(无条件敏感/工具包) scoped-caller 视角;visible=隐藏漏洞" jLayer {
                    val probe = listOf(
                        // RE / root / hook / 抓包 / 自动化 工具
                        "com.reqable.android", "com.sukisu.ultra", "org.auto.auto.v6", "org.x.manager",
                        "io.github.vvb2060.keyattestation", "io.github.vvb2060.mahoshojo",
                        "io.liankong.riskdetector", "com.reveny.nativecheck", "com.apkpure.aegon",
                        // 隐秘相机 / 偷拍类
                        "com.weixikeji.privatecameraV2",
                    )
                    val pm = context.packageManager
                    val vis = probe.filter {
                        runCatching { pm.getPackageInfo(it, 0); true }.getOrDefault(false)
                    }
                    if (vis.isEmpty()) "clean (0 visible)"
                    else "★LEAK: ${vis.size} visible=[${vis.joinToString(",")}]"
                },
            )
            // ★visible_list_hash:可见非系统 app 列表的稳定 hash → 跨两次一键新机对比应【不同】(反聚类),
            //   同一 identity 内多次采集应【相同】(稳定)。
            field("app.visible_list_hash",
                "sha256(sorted 可见非系统包名)" jLayer {
                    val pkgs = context.packageManager.getInstalledPackages(0)
                        .filter { ((it.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 }
                        .map { it.packageName }.sorted()
                    val h = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(pkgs.joinToString(",").toByteArray())
                        .joinToString("") { "%02x".format(it) }.take(16)
                    "hash=$h count=${pkgs.size}"
                },
            )
            // ★installtime_spread:抽样 farmed app 的 firstInstallTime 分布(package-state)。
            //   真机账龄散布;farm 若全同一时刻装 = 可疑。span=最早到最晚跨天数。
            field("app.installtime_spread",
                "firstInstallTime 抽样(账龄散布 vs 全同时间)" jLayer {
                    val pm = context.packageManager
                    // 只抽**第三方 farmed app**(系统 app 的 firstInstallTime=镜像时间会把 span 拉爆,无意义)
                    val sample = listOf(
                        "com.twitter.android", "com.instagram.android", "com.facebook.katana",
                        "com.facebook.orca", "com.whatsapp", "com.zhiliaoapp.musically",
                        "com.snapchat.android", "com.reddit.frontpage",
                    )
                    val times = sample.mapNotNull { p ->
                        runCatching { pm.getPackageInfo(p, 0).firstInstallTime }.getOrNull()?.let { p to it }
                    }
                    if (times.isEmpty()) "<none-installed>"
                    else {
                        val ts = times.map { it.second }
                        val spanDays = (ts.max() - ts.min()) / 86_400_000.0
                        val fmt = java.text.SimpleDateFormat("MM-dd", java.util.Locale.US)
                        // label:去掉 com. 前缀取前 14 字符(com.twitter.android→twitter.android,不再误显示成 android)
                        "n=${times.size} span=${"%.1f".format(spanDays)}d " +
                            times.joinToString(" ") { "${it.first.removePrefix("com.").take(14)}=${fmt.format(java.util.Date(it.second))}" }
                    }
                },
            )
        }

        // ============================================================
        // R2. 安装列表 spoof 攻防面板(配合 ghost InstalledAppProfile 投影/伪造)
        //     模拟风控 SDK 的多种枚举/探测路径,交叉校验找伪造穿帮:
        //      成果面:fingerprint(反聚类)/ brand_match / oem_store / cardinality
        //      脆弱点:多向量 count 差异 + null 签名 + 无 launcher = 伪造包在不同路径下露馅
        // ============================================================
        category("installed-apps") {
            val pm = context.packageManager
            val brand = android.os.Build.BRAND.lowercase()

            // ---- 多向量枚举(风控 SDK 可能用任一路径;伪造包在不同路径下会不一致) ----
            // V1: getInstalledPackages(0) —— 最常用 bulk
            val pkgNames = runCatching { pm.getInstalledPackages(0).map { it.packageName } }
                .getOrElse { emptyList() }
            val pkgSet = pkgNames.toSet()
            // V2: getInstalledApplications(0) —— 另一条 hook 路径(ComputerEngineHook 单独伪造)
            val appNames = runCatching { pm.getInstalledApplications(0).map { it.packageName } }
                .getOrElse { emptyList() }.toSet()
            // V3: pm list packages —— shell(以本 app uid 走回 PMS,应与 V1 一致)
            val pmListNames = runCatching {
                val p = Runtime.getRuntime().exec(arrayOf("sh", "-c", "pm list packages"))
                p.inputStream.bufferedReader().readLines()
                    .mapNotNull { it.removePrefix("package:").trim().takeIf { s -> s.isNotEmpty() } }.toSet()
            }.getOrElse { emptySet() }
            // V4: queryIntentActivities(LAUNCHER) —— 可启动 app;伪造包无 launcher → 缺席
            val launcherNames = runCatching {
                val i = android.content.Intent(android.content.Intent.ACTION_MAIN)
                    .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
                pm.queryIntentActivities(i, 0).mapNotNull { it.activityInfo?.packageName }.toSet()
            }.getOrElse { emptySet() }
            // V5: GET_SIGNATURES —— 伪造包无签名
            @Suppress("DEPRECATION")
            val withSig = runCatching {
                pm.getInstalledPackages(android.content.pm.PackageManager.GET_SIGNATURES)
            }.getOrElse { emptyList() }
            @Suppress("DEPRECATION")
            val noSigSet = withSig.filter { it.signatures == null || it.signatures?.isEmpty() == true }
                .map { it.packageName }.toSet()

            // ---- 成果面 ----
            field("applist.count_multi",
                "getInstalledPackages / getInstalledApplications / pm-list" jLayer {
                    "pkgs=${pkgNames.size} apps=${appNames.size} pmlist=${pmListNames.size}"
                },
            )
            field("applist.fingerprint",
                "sha256(sorted pkg list)[0:12] —— 跨新机应变化(反聚类)" jLayer {
                    val md = java.security.MessageDigest.getInstance("SHA-256")
                    md.digest(pkgNames.sorted().joinToString("\n").toByteArray())
                        .joinToString("") { "%02x".format(it) }.take(12)
                },
            )
            field("applist.brand_match",
                "Build.BRAND vs OEM pkg presence" jLayer {
                    val expect = when {
                        brand == "samsung" -> listOf("com.samsung.", "com.sec.")
                        brand in setOf("xiaomi", "redmi", "poco") -> listOf("com.miui.", "com.xiaomi.")
                        brand in setOf("oppo", "realme", "oneplus") ->
                            listOf("com.coloros.", "com.oppo.", "com.heytap.", "com.oplus.")
                        brand == "vivo" -> listOf("com.vivo.", "com.iqoo.")
                        brand == "motorola" -> listOf("com.motorola.")
                        brand == "honor" -> listOf("com.hihonor.")
                        brand == "sony" -> listOf("com.sonymobile.", "com.sonyericsson.")
                        brand in setOf("infinix", "tecno", "itel") -> listOf("com.transsion.", "com.transsnet.")
                        brand in setOf("nubia", "zte") -> listOf("cn.nubia.", "com.zte.")
                        brand == "asus" -> listOf("com.asus.")
                        brand == "meizu" -> listOf("com.meizu.")
                        brand == "nothing" -> listOf("com.nothing.")
                        brand in setOf("lge", "lg") -> listOf("com.lge.")
                        else -> emptyList()
                    }
                    if (expect.isEmpty()) "n/a (brand=$brand 用 Play 系,无 OEM 预期)"
                    else {
                        val hit = pkgNames.count { p -> expect.any { p.startsWith(it) } }
                        if (hit > 0) "ok ($hit OEM pkgs, brand=$brand)"
                        else "MISSING (brand=$brand 但列表 0 个 OEM 包)"
                    }
                },
            )
            field("applist.oem_store",
                "store in-list vs queryIntent(APP_MARKET)" jLayer {
                    val storePkg = when {
                        brand == "samsung" -> "com.sec.android.app.samsungapps"
                        brand in setOf("xiaomi", "redmi", "poco") -> "com.xiaomi.market"
                        brand in setOf("oppo", "realme", "oneplus") -> "com.heytap.market"
                        brand == "vivo" -> "com.vivo.appstore"
                        brand == "honor" -> "com.hihonor.appmarket"
                        brand in setOf("infinix", "tecno", "itel") -> "com.transsnet.store"
                        brand in setOf("nubia", "zte") -> "cn.nubia.neostore"
                        brand == "meizu" -> "com.meizu.mstore"
                        brand in setOf("lge", "lg") -> "com.lge.appbox.client"
                        else -> null  // Sony/asus/Nothing/google 用 Play,无独立商店
                    }
                    if (storePkg == null) "n/a (brand=$brand 用 Play)"
                    else {
                        val inList = storePkg in pkgSet
                        val resolvable = runCatching {
                            val i = android.content.Intent(android.content.Intent.ACTION_MAIN)
                                .addCategory("android.intent.category.APP_MARKET")
                            pm.queryIntentActivities(i, 0).any { it.activityInfo?.packageName == storePkg }
                        }.getOrDefault(false)
                        when {
                            inList && resolvable -> "ok (present + resolvable)"
                            inList && !resolvable -> "MISMATCH (在列表但 queryIntent 解析不到 = 伪造商店穿帮)"
                            else -> "MISSING ($storePkg 不在列表)"
                        }
                    }
                },
            )

            // ---- 脆弱点(攻方视角) ----
            // 跨向量一致性:getInstalledPackages vs getInstalledApplications vs pm list 差异。
            // 三条路径若非同源伪造会不一致 —— 差异大 = 某路径漏伪造。
            field("applist.vector_delta",
                "|pkgs∖apps| + |pkgs∖pmlist|(跨枚举路径差异,应≈0)" jLayer {
                    val dApps = (pkgSet - appNames).size
                    val dPm = (pkgSet - pmListNames).size
                    "pkgs∖apps=$dApps pkgs∖pmlist=$dPm"
                },
            )
            // ★ 核心攻方指标:在 bulk 列表里、但既无 launcher 又无签名 = 伪造包被交叉校验隔离出来。
            // 真实 app 大多可启动或至少有签名;这批"幽灵包"是签名+launcher 双探针能抓的伪造集。
            field("applist.ghost_pkgs",
                "in-bulk ∧ ¬launcher ∧ ¬signed(交叉校验隔离出的伪造集)" jLayer {
                    val ghost = pkgNames.filter { it !in launcherNames && it in noSigSet }
                    if (ghost.isEmpty()) "0"
                    else "${ghost.size} (${ghost.take(6).joinToString(",")}${if (ghost.size > 6) "…" else ""})"
                },
            )
            // 纯签名探针能抓的数量(GET_SIGNATURES null)
            field("applist.nosig_count",
                "getInstalledPackages(GET_SIGNATURES) null-sig 数" jLayer {
                    val list = noSigSet.toList()
                    if (list.isEmpty()) "0"
                    else "${list.size} (${list.take(6).joinToString(",")}${if (list.size > 6) "…" else ""})"
                },
            )

            // ★ 设备牧场路径痕迹检测:APK sourceDir + /proc/self/maps 的 /data/app 随机 hash。
            //   install-once 复用(install-existing / 数据交换式还原)→ 同 app 的路径 hash
            //   跨"一键新机"恒定 → 一台物理机的牧场信号(真机群每台 hash 不同)。
            //   跨两次新机采集对比此 fingerprint:变化=路径每设备唯一(安全);恒定=牧场暴露。
            field("applist.path_fingerprint",
                "sha256(自身+抽样app sourceDir + self maps base.apk)[0:12] —— 跨新机应变化" jLayer {
                    val parts = mutableListOf<String>()
                    runCatching { context.applicationInfo.sourceDir?.let { parts.add(it) } }
                    runCatching {
                        java.io.File("/proc/self/maps").readLines()
                            .firstOrNull { it.contains("/data/app/") && it.endsWith("base.apk") }
                            ?.let { line -> Regex("/data/app/\\S+base\\.apk").find(line)?.value?.let { parts.add(it) } }
                    }
                    runCatching {
                        pm.getInstalledApplications(0)
                            .mapNotNull { it.sourceDir }
                            .filter { it.startsWith("/data/app/") }
                            .sorted().take(12).forEach { parts.add(it) }
                    }
                    val md = java.security.MessageDigest.getInstance("SHA-256")
                    md.digest(parts.joinToString("\n").toByteArray()).joinToString("") { "%02x".format(it) }.take(12)
                },
            )
            // 原始样本:自身 APK 的 /data/app 随机 token(人肉核对跨设备是否恒定)
            field("applist.path_sample",
                "自身 APK /data/app hash token(跨设备应不同)" jLayer {
                    context.applicationInfo.sourceDir?.let {
                        Regex("~~[^/]+").find(it)?.value ?: it.take(48)
                    } ?: "<none>"
                },
            )
        }

        // ============================================================
        // X. 风控攻击视角探测(bytesFighting 文章)
        //   模拟商业风控 SDK 真实读取路径,任何字段跨源不一致 = ghost 漏 hook
        // ============================================================

        // X.1 — 7 作用域 fingerprint 同源检查
        // 文章原文:"很多大厂会收集 7 个 partition 的 fingerprint... Hook 的话也需要全部进行 hook,只处理单一是没用的"
        // ghost 在 BuildHook.buildSysPropMap 已覆盖 7 partition,这里跨次采集自动验证
        category("partition-fingerprints") {
            val partitions = listOf("build", "bootimage", "odm", "product", "system_ext", "system", "vendor")
            for (key in listOf("fingerprint", "id", "version.incremental")) {
                val props = partitions.map { p -> "ro.$p.build.$key" }
                val sources = props.map { prop ->
                    prop nLayer { NativeBridge.getSystemProperty(prop) }
                }.toMutableList<SourceValue>()
                // 主路径 ro.build.{key}(无 partition 前缀)也加进来
                val mainProp = "ro.build.$key"
                sources.add(0, mainProp nLayer { NativeBridge.getSystemProperty(mainProp) })
                field("partition_same.$key", *sources.toTypedArray())
            }
        }

        // X.2 — SystemProperties 多路径绕过检测
        // 文章原文:"如果只 Hook __system_property_get... 大厂在 9+ 直接调 system_properties.Get 或 find+read"
        // 加 __system_property_find+read / popen getprop / build.prop 文件直读 三路对比
        category("sysprop-bypass") {
            val critProps = listOf(
                "ro.build.fingerprint",
                "ro.product.manufacturer",
                "ro.product.brand",
                "ro.product.model",
                "ro.build.version.security_patch",
                "ro.serialno",
            )
            for (prop in critProps) {
                // 同时四路径,确保 ghost 全部 hook
                field("prop_via_paths.$prop",
                    "SystemProperties.get(java)" jLayer {
                        runCatching {
                            val cls = Class.forName("android.os.SystemProperties")
                            cls.getMethod("get", String::class.java).invoke(null, prop) as? String ?: ""
                        }.getOrElse { "" }
                    },
                    "__system_property_get(native)" nLayer { NativeBridge.getSystemProperty(prop) },
                    "__system_property_find+read(native bypass)" nLayer { NativeBridge.getSystemPropertyViaFind(prop) },
                    "popen getprop" nLayer {
                        NativeBridge.execShell("getprop $prop", 256).trim()
                    },
                )
            }
        }

        // X.3 — build.prop 文件可见性探针(不做 stat vs read 跨源比对)
        // 文章原文:"低版本 build.prop 直接 fopen 能读"。但 Android 10+:
        //   - /system/build.prop, /vendor/build.prop, /odm/etc/build.prop 默认 mode=600 root only
        //   - SELinux 进一步拒绝普通 app uid 读取
        //   - 商业风控 SDK 不会要求 root,所以走这条的 spoof 检查也读不到
        // 因此 stat 看到 size 但 read 失败是**真实 Linux 权限行为**,不是 ghost 漏洞。
        // 我们把 stat / read 各自作为独立字段记录,不强制一致(单值 field 永远 consistent)。
        // 真正的攻击面是 system_ext/etc/build.prop(mode=644 可读)— 但它只含 OEM extra
        // prop,不含 ro.build.fingerprint,这里只做 sanity 不做断言。
        category("buildprop-files") {
            val buildPropFiles = listOf(
                "/system/build.prop",
                "/vendor/build.prop",
                "/odm/etc/build.prop",
                "/product/build.prop",
                "/system_ext/etc/build.prop",
            )
            for (f in buildPropFiles) {
                val tag = f.substringAfter('/').replace('/', '_').substringBefore('.')
                field("buildprop_stat.$tag",
                    "stat $f" nLayer { NativeBridge.statFile(f).ifEmpty { "<not-exist>" } },
                )
                field("buildprop_read.$tag",
                    "fopen $f → grep ro.build.fingerprint" nLayer {
                        val content = NativeBridge.readFile(f, 16384)
                        when {
                            content.isEmpty() -> "<empty/no-perm>"  // 预期(mode=600 + SELinux)
                            else -> content.lines()
                                .firstOrNull { it.startsWith("ro.build.fingerprint=") }
                                ?.substringAfter('=')
                                ?: "<readable-but-no-fingerprint-key>"  // system_ext 等预期
                        }
                    },
                )
            }
        }

        // X.4 — popen 命令探测(模拟风控走 execve/popen 绕过)
        // 文章原文:"很多大厂会执行 popen logcat / getprop / uname -a / ip a / ps -ef / df grep magisk"
        category("popen-probes") {
            // uname.release 是核心字段(spoof 后 ghost 改 syscall uname → release 跟着改)
            // syscall release + popen uname -r 都应该返回同样的 release 字符串(归一化对比);
            // /proc/version Android 11+ 受 SELinux 限制普通 app 读不到 = 预期空,不参与一致性
            field("uname.release",
                "syscall uname().release" nLayer { NativeBridge.getUname().getOrNull(2) ?: "" },
                "popen uname -r" nLayer { NativeBridge.execShell("uname -r", 512).trim() },
            )
            // 单独字段记录,不强制比对
            field("uname.full_uname_a",
                "popen uname -a" nLayer { NativeBridge.execShell("uname -a", 512).trim() },
            )
            field("uname.proc_version",
                "fopen /proc/version" nLayer {
                    val v = NativeBridge.readFile("/proc/version", 512).trim()
                    v.ifEmpty { "<empty/no-perm — expected on Android 11+>" }
                },
            )
            // popen getprop ro.product.model 跟 SystemProperties.get 对比
            field("popen.getprop_model",
                "SystemProperties.get(ro.product.model)" jLayer { android.os.Build.MODEL },
                "popen getprop" nLayer { NativeBridge.execShell("getprop ro.product.model", 256).trim() },
            )
            // popen ps -ef 看是否有 ghost / magisk / xposed / frida 痕迹
            field("popen.ps_clean",
                "popen ps -A | grep [hook]" nLayer {
                    val out = NativeBridge.execShell("ps -A", 16384)
                    val hits = out.lines().filter { line ->
                        listOf("magisk", "zygisk", "frida", "lsposed", "xposed", "sukisu", "kernelsu")
                            .any { kw -> kw in line.lowercase() }
                    }
                    if (hits.isEmpty()) "clean" else "🚨 ${hits.size} hits: ${hits.joinToString(";").take(180)}"
                },
            )
            // popen mount grep magisk
            field("popen.mount_clean",
                "popen mount | grep magisk|.abcd|/data/adb" nLayer {
                    val out = NativeBridge.execShell("mount", 16384)
                    val hits = out.lines().filter { line ->
                        listOf("magisk", ".abcd", "/data/adb").any { kw -> kw in line.lowercase() }
                    }
                    if (hits.isEmpty()) "clean" else "🚨 ${hits.size} hits: ${hits.joinToString(";").take(180)}"
                },
            )
            // popen ip a — netlink 路径的 mac
            field("popen.ip_a",
                "popen ip a | grep link/ether" nLayer {
                    val out = NativeBridge.execShell("ip addr 2>/dev/null || ip -a", 16384)
                    val macLines = out.lines().filter { it.contains("link/ether") }.map { it.trim() }
                    if (macLines.isEmpty()) "<empty>" else macLines.joinToString(" | ").take(280)
                },
            )
        }

        // X.5 — 内核文件 ID 采集(boot_id / uuid / soc_serial / emmc_cid / misc)
        // 文章:"很多大厂会读取 boot_id / soc_serial / mmcblk0/device/cid / proc/misc 作为指纹"
        // ghost 应该 SVC IO 重定向这些路径,这里采集让任何 spoof 漏的立刻可见
        category("kernel-ids") {
            val coreIdFiles = listOf(
                "kernel.boot_id" to "/proc/sys/kernel/random/boot_id",
                "kernel.random_uuid" to "/proc/sys/kernel/random/uuid",
                "hw.soc_serial" to "/sys/devices/soc0/serial_number",
                "hw.emmc_cid" to "/sys/block/mmcblk0/device/cid",
                "hw.emmc_serial" to "/sys/block/mmcblk0/device/serial",
                "hw.emmc_name" to "/sys/block/mmcblk0/device/name",
                "kernel.misc" to "/proc/misc",
                "kernel.cmdline" to "/proc/cmdline",
                "kernel.osrelease" to "/proc/sys/kernel/osrelease",
                "kernel.hostname" to "/proc/sys/kernel/hostname",
            )
            // 这些字段大多是 root-only(SELinux+mode 拒绝普通 app),read 跟 popen cat 都
            // 走 fopen / cat 底层都是 openat,SELinux 一致拒绝 → 两源同空。
            // 例外:/proc/sys/kernel/random/uuid 是 Linux 内核接口,**每次读返回新 UUID**(
            // 这是 kernel rand 设计行为,跟 boot_id 不同),所以两源必不同 — 不做 cross 比对。
            for ((name, path) in coreIdFiles) {
                if (name == "kernel.random_uuid") {
                    // /proc/sys/kernel/random/uuid 每次读都新值,只采单源,不做一致性
                    field(name,
                        "readFile $path" nLayer {
                            val v = NativeBridge.readFile(path, 1024).trim()
                            if (v.isEmpty()) "<empty/no-perm>" else "$v (per-read-varying — Linux kernel behavior)"
                        },
                    )
                } else {
                    field(name,
                        "readFile $path" nLayer {
                            val v = NativeBridge.readFile(path, 1024).trim()
                            v.ifEmpty { "<empty/no-perm>" }
                        },
                        "popen cat $path" nLayer {
                            val v = NativeBridge.execShell("cat $path 2>/dev/null", 1024).trim()
                            v.ifEmpty { "<empty/no-perm>" }
                        },
                    )
                }
            }
            // /proc/self/maps 找 ghost / magisk / lsposed / frida 痕迹
            field("maps.clean",
                "readFile /proc/self/maps | grep [hook]" nLayer {
                    val maps = NativeBridge.readFile("/proc/self/maps", 65536)
                    val hits = maps.lines().mapNotNull {
                        val low = it.lowercase()
                        when {
                            "libplay" in low -> "libplay"
                            "magisk" in low -> "magisk"
                            "lspd" in low || "lsposed" in low -> "lsposed"
                            "lsplant" in low -> "lsplant"
                            "frida" in low -> "frida"
                            "zygisk" in low -> "zygisk"
                            else -> null
                        }
                    }.distinct()
                    if (hits.isEmpty()) "clean" else "🚨 ${hits.joinToString(",")}"
                },
            )
        }

        // ============================================================
        // Y. Article 3 — SVC raw syscall 绕 libc hook 对比
        //   asm svc #0 直接 trap 到内核态,跟 libc fopen 拿到不同结果 = ghost 只
        //   hook 了 libc 没拦 svc。商业风控用 raw svc 拿真值。
        // ============================================================
        category("svc-bypass") {
            val targets = listOf(
                "/proc/self/status" to "proc.self.status",
                "/proc/version" to "proc.version",
                "/proc/sys/kernel/random/boot_id" to "boot_id",
                "/sys/class/net/wlan0/address" to "net.wlan0.address",
                "/system/build.prop" to "system.build_prop",
            )
            for ((path, tag) in targets) {
                field("svc_vs_libc.$tag",
                    "libc fopen" nLayer {
                        NativeBridge.readFile(path, 4096).trim().take(120).ifEmpty { "<empty>" }
                    },
                    "asm svc #0 openat" nLayer {
                        NativeBridge.readFileViaSyscall(path, 4096).trim().take(120).ifEmpty { "<empty>" }
                    },
                )
            }
            // stat 也对比一下,看 ghost svc IO 重定向是否覆盖 stat 路径
            field("svc_stat_vs_libc.build_prop",
                "libc stat" nLayer { NativeBridge.statFile("/system/build.prop").ifEmpty { "<empty>" } },
                "asm svc #0 newfstatat" nLayer { NativeBridge.statFileViaSyscall("/system/build.prop").ifEmpty { "<empty>" } },
            )
        }

        // ============================================================
        // Z. Article 2 — JA3 TLS Client Hello 客户端指纹采集(单源,不做 cross)
        //   反射 SSLContext default 的 cipher suites + protocols,拼成 JA3 风格的
        //   PartialClientHello 字符串,供分析跟"真实 Android Chrome / OkHttp" JA3
        //   比对。商业风控用 JA3 识破自动化工具(curl/python requests/cronet 等)
        //   各自有独立指纹。
        // ============================================================
        category("ja3-tls") {
            field("tls.protocols",
                "SSLContext default protocols" jLayer {
                    runCatching {
                        val ctx = javax.net.ssl.SSLContext.getDefault()
                        ctx.defaultSSLParameters.protocols.sorted().joinToString(",")
                    }.getOrElse { "<error> ${it.javaClass.simpleName}" }
                },
            )
            field("tls.ciphers_enabled",
                "SSLContext default enabled cipher suites" jLayer {
                    runCatching {
                        val ctx = javax.net.ssl.SSLContext.getDefault()
                        val ciphers = ctx.defaultSSLParameters.cipherSuites.sorted()
                        // 数量 + hash(前 8 chars)— 不全列(列出来 100+ 太长)
                        val joined = ciphers.joinToString(",")
                        val hash = java.security.MessageDigest.getInstance("SHA-1")
                            .digest(joined.toByteArray())
                            .joinToString("") { "%02x".format(it) }
                        "${ciphers.size} cipher_suites, sha1[0:16]=${hash.take(16)}"
                    }.getOrElse { "<error> ${it.javaClass.simpleName}" }
                },
            )
            field("tls.cipher_top5",
                "first 5 default cipher suites(sorted)" jLayer {
                    runCatching {
                        val ctx = javax.net.ssl.SSLContext.getDefault()
                        ctx.defaultSSLParameters.cipherSuites.sorted().take(5).joinToString(",")
                    }.getOrElse { "<error> ${it.javaClass.simpleName}" }
                },
            )
            // Conscrypt(Android 默认 SSL provider)身份探针
            field("tls.provider",
                "SSLContext default provider" jLayer {
                    runCatching {
                        val ctx = javax.net.ssl.SSLContext.getDefault()
                        "${ctx.protocol} / ${ctx.provider.name} v${ctx.provider.version}"
                    }.getOrElse { "<error> ${it.javaClass.simpleName}" }
                },
            )
            // 跟 Android 13 / 14 标准 Chrome JA3 简单比对:
            // 真 Android 13 Conscrypt 通常报告 TLSv1.2/TLSv1.3 + ~17 个 cipher
            // 数量异常少(<10)或缺主流套件 = 客户端用了非标准 SSL stack(可能 hook 框架/沙箱)
            field("tls.cipher_count_normal",
                "is cipher count reasonable for Android 13+" jLayer {
                    runCatching {
                        val n = javax.net.ssl.SSLContext.getDefault().defaultSSLParameters.cipherSuites.size
                        when {
                            n < 10 -> "⚠ too few ($n) — possibly stripped SSL stack"
                            n > 60 -> "⚠ unusually high ($n) — non-standard provider?"
                            else -> "normal ($n)"
                        }
                    }.getOrElse { "<error>" }
                },
            )
            // 终极验证:外部 echo 服务返回观察到的真实 JA3 hash(从 packet wire 算出)。
            // tls.peet.ws/api/all 是公开服务,GET 返回 JSON 含 ja3_hash 跟 ja4。
            // 这是 ghost JA3 hook 是否真生效的金标准 — Java enabledCipherSuites 走 Java 配置
            // 静态值,看不到 native hook 效果;但 packet wire 上的 Client Hello cipher 顺序
            // 是被 hook 改写的真实值,服务端 JA3 hash 跟着 ghost spoof 顺序变。
            // 跨次一键新机时,这里 ja3_hash 跟着 deviceInfo 变化 = JA3 聚集性 anchor 被破坏。
            // 关键升级:用 OkHttp 走 HTTP/2 调 peet.ws,服务端从 packet 算 JA3 + JA4 +
            // **akamai HTTP/2 fingerprint**(只 HTTP/2 流才有)。akamai_fingerprint 是
            // HTTP/2 SETTINGS frame 参数 + WINDOW_UPDATE + PRIORITY + pseudo-header 顺序的
            // 复合指纹,商业风控用作"HTTP/2 客户端类型"识别(类似 JA3 但在 HTTP/2 协议层)。
            // 单次请求把 ja3 / ja4 / akamai 一起 cache,避免发 2 次。
            val peetResponse: String by lazy {
                runCatching {
                    val client = okhttp3.OkHttpClient.Builder()
                        .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                        .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                        .protocols(listOf(okhttp3.Protocol.HTTP_2, okhttp3.Protocol.HTTP_1_1))
                        .build()
                    val req = okhttp3.Request.Builder().url("https://tls.peet.ws/api/all").get().build()
                    client.newCall(req).execute().use { it.body?.string() ?: "" }
                }.getOrElse { "<error> ${it.javaClass.simpleName}: ${it.message?.take(60)}" }
            }
            fun extract(key: String): String =
                Regex("\"$key\"\\s*:\\s*\"([^\"]+)\"").find(peetResponse)?.groupValues?.get(1) ?: "?"

            field("tls.observed_ja3_external",
                "OkHttp(HTTP/2) GET tls.peet.ws/api/all → server-observed ja3/ja4" jLayer {
                    if (peetResponse.startsWith("<error>")) peetResponse
                    else "ja3=${extract("ja3_hash")} / ja4=${extract("ja4")}"
                },
            )
            field("tls.observed_akamai_h2",
                "akamai HTTP/2 fingerprint (SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-hdr order)" jLayer {
                    if (peetResponse.startsWith("<error>")) peetResponse
                    else {
                        // peet.ws 返回 "akamai_fingerprint": "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,s,a,p"
                        // 字段:S=SETTINGS / WU=WINDOW_UPDATE delta / P=PRIORITY weight / PS=pseudo-header order
                        val fp = extract("akamai_fingerprint")
                        val hash = extract("akamai_fingerprint_hash")
                        if (fp == "?" && hash == "?") "<no-h2 — falled back to HTTP/1.1>"
                        else "hash=$hash fp=${fp.take(80)}"
                    }
                },
            )
            field("tls.http_protocol_to_peet",
                "OkHttp negotiated protocol with tls.peet.ws" jLayer {
                    if (peetResponse.startsWith("<error>")) peetResponse
                    else extract("http_version").ifEmpty { "?" }
                },
            )
            // 关键升级:实际发起 SSL handshake 拿协商成功的 cipher + Client Hello
            // enabledCipherSuites。这条路径才会走 BoringSSL native SSL_CTX_set_cipher_list,
            // 跟 ghost 的 JA3 hook 路径重合 — hook 生效后这里 cipher 顺序/hash 跟着变。
            // 静态 SSLContext.defaultSSLParameters 不走这条 native 路径,看不到 hook 效果。
            field("tls.actual_handshake",
                "real SSL handshake → SSLSocket.enabledCiphers sha1[0:16]" jLayer {
                    runCatching {
                        val factory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
                        val sock = factory.createSocket("www.google.com", 443) as javax.net.ssl.SSLSocket
                        sock.soTimeout = 5000
                        sock.startHandshake()
                        val negotiated = sock.session.cipherSuite
                        val enabled = sock.enabledCipherSuites
                        sock.close()
                        val joined = enabled.joinToString(",")
                        val hash = java.security.MessageDigest.getInstance("SHA-1")
                            .digest(joined.toByteArray()).joinToString("") { "%02x".format(it) }
                        "${enabled.size} ciphers, neg=$negotiated, sha1[0:16]=${hash.take(16)}"
                    }.getOrElse { "<error> ${it.javaClass.simpleName}: ${it.message}" }
                },
            )
            // 跨 ghost hook 的对照 — 这个 enabledCipherSuites 经过 SSLSocket native 路径
            // 跟 ghost SSL_set_cipher_list hook 可能重合(如果 SSLSocket 内部走 BoringSSL
            // 的 set_cipher_list 配置 ctx)。看跟 tls.actual_handshake 的 hash 是否一致。
        }

        // ============================================================
        // 绕-hook 真洞交叉:ghost 多只 hook Java 层,native/proc/未hook API 泄漏真值
        //   (分开 field + 带容差规则,不做 exact-equal 双源 field,避免读取时间差/取整误报)
        // ============================================================
        category("hook-bypass-leaks") {
            // 注:uptime padding(ghost SystemClockHook +base 拉长 elapsedRealtime)在 app 层**不可检测**:
            //   /proc/uptime 对 untrusted_app SELinux 拒绝(实测 EACCES,同 getifaddrs),detector 自己也读不到;
            //   唯一真实旁路是 native clock_gettime(CLOCK_BOOTTIME)——需扩 NativeBridge C++(TODO,未做)。故此处不采 uptime。
            // 内存:Runtime.maxMemory()/MB 按 Android 定义 == ActivityManager.getMemoryClass()
            //   ghost spoof maxMemory 到 256/384/512 桶,但常没 hook getMemoryClass → 不等=anchor
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? android.app.ActivityManager
            field("runtime.max_memory_mb",
                "Runtime.maxMemory()/1MB" jLayer {
                    (Runtime.getRuntime().maxMemory() / (1024L * 1024L)).toString()
                },
            )
            field("runtime.memory_class_mb",
                "ActivityManager.getMemoryClass()(未hook真值)" jLayer { am?.memoryClass?.toString() },
            )
            field("runtime.total_mem_mb",
                "ActivityManager.MemoryInfo.totalMem/1MB" jLayer {
                    runCatching {
                        val mi = android.app.ActivityManager.MemoryInfo()
                        am?.getMemoryInfo(mi); (mi.totalMem / (1024L * 1024L)).toString()
                    }.getOrNull()
                },
            )
            // 音频:mute=false 却 volume=0 = 矛盾;volume 应 ≤ max(max 是未 hook 真值)
            val audio = context.getSystemService(Context.AUDIO_SERVICE) as? android.media.AudioManager
            field("audio.volume_music",
                "getStreamVolume(STREAM_MUSIC)" jLayer {
                    audio?.getStreamVolume(android.media.AudioManager.STREAM_MUSIC)?.toString()
                },
            )
            field("audio.max_volume_music",
                "getStreamMaxVolume(STREAM_MUSIC)(未hook真值)" jLayer {
                    audio?.getStreamMaxVolume(android.media.AudioManager.STREAM_MUSIC)?.toString()
                },
            )
            field("audio.mute_music",
                "isStreamMute(STREAM_MUSIC)" jLayer {
                    audio?.isStreamMute(android.media.AudioManager.STREAM_MUSIC)?.toString()
                },
            )
        }

        // ============================================================
        // Bluetooth 名 / WebView provider / MediaDrm(K7)
        // ============================================================
        category("bt-webview-drm") {
            // Bluetooth:ghost SettingsProviderHook spoof device_name/bluetooth_name→props.name;
            //   BluetoothAdapter.getName() 走独立 IBluetooth binder(不经 SettingsProvider)可能泄漏真名
            //   (需 BLUETOOTH_CONNECT,无权限时 <denied>,规则跳过不误报)。
            field("bt.settings_device_name",
                "Settings.Global device_name" jLayer {
                    runCatching { Settings.Global.getString(context.contentResolver, "device_name") }.getOrNull()
                },
                "Settings.Secure bluetooth_name" jLayer {
                    runCatching { Settings.Secure.getString(context.contentResolver, "bluetooth_name") }.getOrNull()
                },
            )
            field("bt.adapter_name",
                "BluetoothAdapter.getName()(独立 binder,可能泄漏真名)" jLayer {
                    runCatching {
                        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
                        bm?.adapter?.name
                    }.getOrElse { "<denied> ${it.javaClass.simpleName}" }
                },
            )
            // WebView provider:ghost 把 provider packageName→com.brave.browser(仅当已装)+ validityResult=0。
            field("webview.current_package",
                "WebView.getCurrentWebViewPackage().packageName" jLayer {
                    runCatching { android.webkit.WebView.getCurrentWebViewPackage()?.packageName }.getOrNull()
                },
            )
            field("webview.current_version",
                "WebView.getCurrentWebViewPackage().versionName" jLayer {
                    runCatching { android.webkit.WebView.getCurrentWebViewPackage()?.versionName }.getOrNull()
                },
            )
            // ★provider 声称的包是否真已装:声称 brave 却查不到=硬穿帮(ghost 只改 provider 名没真装)。
            field("webview.provider_installed",
                "getPackageInfo(current provider) 是否已装" jLayer {
                    runCatching {
                        val p = android.webkit.WebView.getCurrentWebViewPackage()?.packageName
                            ?: return@runCatching "<no-provider>"
                        context.packageManager.getPackageInfo(p, 0); "installed"
                    }.getOrElse { "NOT_INSTALLED (${it.javaClass.simpleName})" }
                },
            )
            field("webview.default_ua",
                "WebSettings.getDefaultUserAgent" jLayer {
                    runCatching { android.webkit.WebSettings.getDefaultUserAgent(context) }.getOrNull()
                },
            )
        }

        // ============================================================
        // 电池 charge/energy + OAID + 共享库指纹
        // ============================================================
        category("coverage-extra") {
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as? android.os.BatteryManager
            field("battery.charge_counter_uah",
                "BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER(µAh)" jLayer {
                    bm?.getLongProperty(android.os.BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)?.toString()
                },
            )
            // ★ghost FakeBatteryManager: energyCounter = maxCap×(100-cap)/100(与电量**反相关**);
            //   真机 energy(nWh) ≈ charge(µAh)×标称电压×1000(正相关,ratio≈3850)→ ghost ratio<1=异常。
            field("battery.energy_counter_nwh",
                "BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER(nWh)" jLayer {
                    val e = bm?.getLongProperty(android.os.BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER)
                    if (e == null || e == Long.MIN_VALUE) null else e.toString()
                },
            )
            // OAID:ghost OaidHook 拦 SharedPreferences.getString(key=="adid_key")→settingData.oaid。
            //   读任意 SP 的该 key:hooked→返 spoof oaid;未 hook→null。直接测 OaidHook + 拿 per-device oaid。
            field("oaid.sp_adid_key",
                "SharedPreferences.getString(adid_key)(ghost OaidHook 拦此 key)" jLayer {
                    runCatching {
                        context.getSharedPreferences("gv_oaid_probe", android.content.Context.MODE_PRIVATE)
                            .getString("adid_key", null)
                    }.getOrNull()
                },
            )
            // 共享库指纹:ghost ComputerEngineHook 整表替换 getSystemSharedLibraryNames;
            //   count+sha1 作跨设备指纹(所有 ghost 设备同表=弱锚;与机型 profile 差异比对)。
            field("shared_libs.count",
                "PackageManager.getSystemSharedLibraryNames().size" jLayer {
                    context.packageManager.systemSharedLibraryNames?.size?.toString()
                },
            )
            field("shared_libs.sha1",
                "systemSharedLibraryNames sorted sha1" jLayer {
                    val names = context.packageManager.systemSharedLibraryNames?.sorted()
                        ?.joinToString("\n") ?: return@jLayer null
                    sha1Hex(names)
                },
            )
        }

        // ============================================================
        // 收尾 — 构建 report
        // ============================================================
        val timestamp = System.currentTimeMillis()
        val ts = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date(timestamp))
        val crossViolations = CrossFieldChecker.run(fields.toList())
        return CollectReport(
            timestamp = timestamp,
            timestampHuman = ts,
            sessionId = "${Build.SERIAL.take(6)}_$ts",
            deviceLabel = "${Build.MANUFACTURER}/${Build.MODEL} (${Build.DEVICE})",
            fieldCount = fields.size,
            inconsistentCount = fields.count { !it.consistent } + crossViolations.size,
            fields = fields.toList(),
            crossFieldViolations = crossViolations
        )
    }

    // ========================================================================
    // DSL helpers
    // ========================================================================
    private var currentCategory: String = "default"

    companion object {
        private const val GHOST_PACKAGE = "com.tt.hi"
    }

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
    /** 布尔归一化:1/true/enabled→"true",0/false/disabled→"false",其余(null/n/a/空/未知)→null 不参与一致性。 */
    private fun normBool(v: String?): String? = when (v?.trim()?.lowercase()) {
        "1", "true", "enabled" -> "true"
        "0", "false", "disabled" -> "false"
        else -> null
    }

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

    /** 抽取某前缀所有行的值,去重排序,逗号连接(如 /proc/cpuinfo 的全部 "CPU part")。 */
    private fun extractAllProcValues(path: String, prefix: String): String {
        val content = NativeBridge.readFile(path, 65536)
        return content.lineSequence()
            .filter { it.trimStart().startsWith(prefix) }
            .map { it.substringAfter(":").trim() }
            .filter { it.isNotEmpty() }
            .toSortedSet()
            .joinToString(",")
    }

    private val ENV_KEYWORDS = listOf(
        "magisk", "kernelsu", "sukisu", "ksu", "apatch",
        "zygisk", "riru", "lsposed", "lspd", "xposed", "edxposed", "lspatch",
        "frida", "gum-js-loop", "gadget",
        "susfs", "tricky", "trickystore", "playintegrityfix",
        "libplay", "dobby", "libru", "riru_lsposed",
        "com.tt.hi", "hidemyapplist",
        "org.auto.auto", "autojs", "autoxjs",
        "moe.nb4a", "nekobox", "kitsunebi", "reqable",
        "/data/adb", "/data/system/.a", "/data/oat/libplay", " abcd"
    )

    private val SERVICE_KEYWORDS = listOf(
        "iphonesubinfo", "phone", "package", "accessibility", "connectivity",
        "vpn", "keystore", "mount", "activity", "user"
    )

    private fun summarizeKeywordLines(
        text: String,
        keywords: List<String> = ENV_KEYWORDS,
        maxLines: Int = 6
    ): String {
        if (text.isBlank()) return "clean"
        val hits = mutableListOf<String>()
        val matchedKeywords = linkedSetOf<String>()
        text.lineSequence().forEach { line ->
            val low = line.lowercase()
            val kws = keywords.filter { kw -> low.contains(kw.lowercase()) }
            if (kws.isNotEmpty()) {
                matchedKeywords += kws
                if (hits.size < maxLines) hits += line.trim().replace('\u0000', ' ').take(160)
            }
        }
        return if (matchedKeywords.isEmpty()) {
            "clean"
        } else {
            "${hits.size}+ samples kw=${matchedKeywords.take(12).joinToString(",")} sample=${hits.joinToString(" | ")}"
        }
    }

    private fun normalizeProbeOutput(out: String): String {
        if (out.isBlank()) return "<empty>"
        return out.lineSequence()
            .map { it.trim().replace('\u0000', ' ') }
            .filter { it.isNotEmpty() }
            .joinToString(" | ")
            .take(900)
    }

    private fun summarizePathProbes(paths: List<String>): String {
        val exposed = mutableListOf<String>()
        val blocked = mutableListOf<String>()
        val absent = mutableListOf<String>()

        for (path in paths) {
            val file = java.io.File(path)
            val javaExists = runCatching { file.exists() }.getOrDefault(false)
            val javaReadable = runCatching { file.canRead() }.getOrDefault(false)
            val javaListable = runCatching { file.isDirectory && file.list() != null }.getOrDefault(false)
            val stat = NativeBridge.statFile(path)
            val svcStat = NativeBridge.statFileViaSyscall(path)
            val read = NativeBridge.readFile(path, 64).isNotEmpty()
            val shell = NativeBridge.execShell("ls -ld '$path' 2>&1", 512).trim()
            val shellLow = shell.lowercase()

            val isExposed = javaExists || javaReadable || javaListable ||
                stat.isNotEmpty() || svcStat.isNotEmpty() || read ||
                (shell.isNotEmpty() &&
                    !shellLow.contains("no such") &&
                    !shellLow.contains("permission denied") &&
                    !shellLow.contains("not found"))
            val isBlocked = !isExposed && shellLow.contains("permission denied")
            when {
                isExposed -> exposed += "$path[java=$javaExists/$javaReadable/$javaListable stat=${stat.shortProbe()} svc=${svcStat.shortProbe()} shell=${shell.take(80)}]"
                isBlocked -> blocked += path
                else -> absent += path
            }
        }

        return buildString {
            append("exposed=${exposed.size} blocked=${blocked.size} absent=${absent.size}")
            if (exposed.isNotEmpty()) append(" exposed_samples=${exposed.take(5).joinToString(" | ")}")
            if (blocked.isNotEmpty()) append(" blocked_samples=${blocked.take(5).joinToString(",")}")
        }
    }

    private fun String.shortProbe(): String =
        if (isBlank()) "-" else replace(',', ';').take(48)

    private fun readProcSelfFdLinks(): List<String> {
        val dir = java.io.File("/proc/self/fd")
        val files = runCatching { dir.listFiles()?.toList() ?: emptyList() }.getOrDefault(emptyList())
        return files.mapNotNull { fd ->
            runCatching {
                val target = java.nio.file.Files.readSymbolicLink(fd.toPath()).toString()
                "${fd.name} -> $target"
            }.getOrNull()
        }
    }

    @SuppressLint("HardwareIds")
    private fun reflectGetSerial(): String {
        return try {
            Build::class.java.getMethod("getSerial").invoke(null) as? String ?: ""
        } catch (e: Throwable) {
            try { Build.SERIAL } catch (e2: Throwable) { "" }
        }
    }

    // ========================================================================
    // Phase A — 设备指纹 ID helpers
    // ========================================================================

    /** GAID — 通过 reflection 调 GMS AdvertisingIdClient,避免编译期依赖 play-services-ads */
    private fun reflectGetGaid(ctx: android.content.Context): String {
        return try {
            val cls = Class.forName("com.google.android.gms.ads.identifier.AdvertisingIdClient")
            val info = cls.getMethod("getAdvertisingIdInfo", android.content.Context::class.java)
                .invoke(null, ctx)
            val id = info.javaClass.getMethod("getId").invoke(info) as? String
            val lat = info.javaClass.getMethod("isLimitAdTrackingEnabled").invoke(info) as? Boolean
            "$id (limited=$lat)"
        } catch (t: Throwable) {
            "<no-gms> ${t.javaClass.simpleName}"
        }
    }

    private val WIDEVINE_UUID = java.util.UUID.fromString("EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED")

    /** Widevine deviceUniqueId — DRM 层硬件 ID,base64 后输出 */
    @SuppressLint("HardwareIds")
    private fun widevineDeviceId(): String {
        return try {
            val drm = android.media.MediaDrm(WIDEVINE_UUID)
            val bytes = drm.getPropertyByteArray("deviceUniqueId")
            drm.close()
            android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        } catch (t: Throwable) {
            "<error> ${t.javaClass.simpleName}"
        }
    }

    private fun widevineProperty(key: String): String {
        return try {
            val drm = android.media.MediaDrm(WIDEVINE_UUID)
            val v = drm.getPropertyString(key)
            drm.close()
            v ?: ""
        } catch (t: Throwable) {
            "<error> ${t.javaClass.simpleName}"
        }
    }

    /** GSF Android ID — 跟 Settings.Secure.ANDROID_ID 不同(后者 per-app per-user) */
    @SuppressLint("HardwareIds")
    private fun reflectGetGsfAndroidId(ctx: android.content.Context): String {
        return try {
            val uri = android.net.Uri.parse("content://com.google.android.gsf.gservices")
            val cur = ctx.contentResolver.query(uri, null, null, arrayOf("android_id"), null)
            cur?.use {
                if (it.moveToFirst() && it.columnCount >= 2) {
                    return@use java.lang.Long.toHexString(it.getLong(1))
                }
                ""
            } ?: ""
        } catch (t: Throwable) {
            "<no-gsf>"
        }
    }

    /** OAID — 检测哪些 OEM 提供 OAID SDK 类(不调 API,只 probe) */
    private fun detectOaidProviders(): String {
        val classes = mapOf(
            "Huawei" to "com.huawei.hms.ads.identifier.AdvertisingIdClient",
            "Xiaomi" to "com.miui.deviceid.IdentifierManager",
            "Oppo"   to "com.heytap.openid.IOpenID",
            "Vivo"   to "com.vivo.identifier.IdentifierManager",
            "MSA"    to "com.bun.miitmdid.core.MdidSdkHelper",
        )
        return classes.filter { runCatching { Class.forName(it.value) }.isSuccess }
            .keys.joinToString(",").ifEmpty { "<none>" }
    }

    // ========================================================================
    // Phase B — 风控对抗 / Hook 框架检测
    // ========================================================================

    private fun detectMagisk(): String {
        val hits = mutableListOf<String>()
        listOf(
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
            "/system/etc/init/magisk.rc", "/data/adb/magisk.db",
        ).forEach { p -> if (java.io.File(p).exists()) hits += "file:$p" }
        listOf("com.topjohnwu.magisk", "io.github.huskydg.magisk").forEach { pkg ->
            runCatching {
                context.packageManager.getPackageInfo(pkg, 0); hits += "pkg:$pkg"
            }
        }
        return if (hits.isEmpty()) "false" else hits.joinToString(";")
    }

    private fun detectRoot(): String {
        val hits = mutableListOf<String>()
        listOf("/system/xbin/su", "/system/bin/su", "/sbin/su",
               "/su/bin/su", "/magisk/.core/bin/su").forEach { p ->
            if (java.io.File(p).exists()) hits += "su:$p"
        }
        if (Build.TAGS?.contains("test-keys") == true) hits += "tags:test-keys"
        if (NativeBridge.getSystemProperty("ro.debuggable") == "1") hits += "ro.debuggable=1"
        if (NativeBridge.getSystemProperty("ro.secure") == "0") hits += "ro.secure=0"
        return if (hits.isEmpty()) "false" else hits.joinToString(";")
    }

    private fun detectFrida(): String {
        val hits = mutableListOf<String>()
        runCatching {
            val maps = NativeBridge.readFile("/proc/self/maps", 65536)
            listOf("frida-agent", "frida-gadget", "frida-server", "gum-js-loop", "gmain")
                .forEach { needle -> if (maps.contains(needle)) hits += "maps:$needle" }
        }
        // try TCP 27042(frida-server 默认 port)
        runCatching {
            java.net.Socket().use { s ->
                s.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 200)
                if (s.isConnected) hits += "tcp:27042"
            }
        }
        return if (hits.isEmpty()) "false" else hits.joinToString(";")
    }

    private fun detectXposed(): String {
        val hits = mutableListOf<String>()
        listOf("de.robv.android.xposed.XposedBridge",
               "de.robv.android.xposed.XC_MethodHook",
               "de.robv.android.xposed.XposedHelpers"
        ).forEach { c -> if (runCatching { Class.forName(c) }.isSuccess) hits += c }
        return if (hits.isEmpty()) "false" else hits.joinToString(";")
    }

    /** LSPosed 痕迹 — 扫 ClassLoader 父链找 LSPHooker_ 前缀类(memory project_dg_signal_audit) */
    private fun detectLsposed(): String {
        val hits = mutableListOf<String>()
        listOf("org.lsposed.lspd.core.ApplicationServiceClient",
               "org.lsposed.lspd.nativebridge.NativeAPI",
               "io.github.lsposed.manager",
        ).forEach { c -> if (runCatching { Class.forName(c) }.isSuccess) hits += "cls:$c" }
        // LSPHooker_ 类前缀 — 扫 ClassLoader 内已加载类(需要 PathClassLoader pathList 反射)
        runCatching {
            val cl = javaClass.classLoader ?: return@runCatching
            val pathListField = Class.forName("dalvik.system.BaseDexClassLoader")
                .getDeclaredField("pathList").apply { isAccessible = true }
            val pathList = pathListField.get(cl) ?: return@runCatching
            val elementsField = pathList.javaClass.getDeclaredField("dexElements")
                .apply { isAccessible = true }
            val elements = elementsField.get(pathList) as? Array<*> ?: return@runCatching
            // 找 LSPHooker_ 类(若存在则在某个 dex 里)
            for (e in elements) {
                val dexFileField = e?.javaClass?.getDeclaredField("dexFile")
                    ?.apply { isAccessible = true } ?: continue
                val dex = dexFileField.get(e) ?: continue
                val entriesMethod = dex.javaClass.getMethod("entries")
                @Suppress("UNCHECKED_CAST")
                val entries = entriesMethod.invoke(dex) as? java.util.Enumeration<String> ?: continue
                while (entries.hasMoreElements()) {
                    val n = entries.nextElement()
                    if (n.contains("LSPHooker_")) { hits += "dex-cls:$n"; return@runCatching }
                }
            }
        }
        return if (hits.isEmpty()) "false" else hits.joinToString(";")
    }

    private fun readTracerPid(): Int? = runCatching {
        val status = NativeBridge.readFile("/proc/self/status", 8192)
        status.lineSequence().firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(":")?.trim()?.toIntOrNull()
    }.getOrNull()

    // ========================================================================
    // Phase E — Keystore TEE Attestation
    // ========================================================================
    private data class KeystoreAttestation(
        val chainLength: Int = 0,
        val chainVerified: String? = null,        // ★K1:逐级 verify(parent.pub);"true"/"false(link i:..)"
        val leafValidityHours: Long? = null,      // ★K1:leaf notAfter-notBefore(真机数千h;ghost 伪 leaf ~1h)
        val rootPubKeySha256: String? = null,     // ★K1:根证书公钥 SHA256(vs Google hw-attest root)
        val attestationVersion: Int? = null,
        val attestationSecurityLevel: String? = null,
        val keymasterVersion: Int? = null,
        val keymasterSecurityLevel: String? = null,
        val osVersion: Int? = null,               // ★K3:[705] eg 130000→A13
        val osPatchLevel: Int? = null,            // ★K3:[706] eg 202401→2024-01
        val verifiedBootState: Int? = null,       // ★K2:[704] 0=Verified 1=SelfSigned 2=Unverified 3=Failed
        val deviceLocked: Boolean? = null,        // ★K2:[704] deviceLocked
        val verifiedBootKeyHex: String? = null,   // ★K2:[704] verifiedBootKey(随机=锚)
        val verifiedBootHashHex: String? = null,  // ★K2:[704] verifiedBootHash(跨采集变=锚)
        val keyInfoSecurityLevel: String? = null, // ★K4:KeyInfo.getSecurityLevel(API31+)
        val insideSecureHardware: Boolean? = null,// ★K4:KeyInfo.isInsideSecureHardware
        val idBrand: String? = null,
        val idDevice: String? = null,
        val idProduct: String? = null,
        val idSerial: String? = null,
        val idManufacturer: String? = null,
        val idModel: String? = null,
        val error: String? = null,
    )

    private fun collectKeystoreAttestation(): KeystoreAttestation? {
        return runCatching {
            val challenge = ByteArray(16).apply { java.security.SecureRandom().nextBytes(this) }
            val alias = "ghost_verify_attest_${System.currentTimeMillis() % 1_000_000}"
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            runCatching { ks.deleteEntry(alias) }

            val kpg = java.security.KeyPairGenerator.getInstance(
                android.security.keystore.KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

            // 优先请求 ID attestation(API 31+ Android 12)— TEE 在 attestation
            // extension 的 hardwareEnforced 区段加入 brand/device/manufacturer/model
            // 等 Build IDs(对比 Java Build.* 暴露 spoof 的关键检测点)。
            // 不是所有硬件都支持 ID attestation(Pixel 全系列支持;Samsung 部分支持),
            // 失败 fallback 到普通 attestation。
            fun buildSpec(includeIds: Boolean): android.security.keystore.KeyGenParameterSpec {
                val b = android.security.keystore.KeyGenParameterSpec.Builder(
                    alias, android.security.keystore.KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                if (includeIds && Build.VERSION.SDK_INT >= 31) {
                    runCatching { b.setDevicePropertiesAttestationIncluded(true) }
                }
                return b.build()
            }
            try {
                kpg.initialize(buildSpec(includeIds = true))
                kpg.generateKeyPair()
            } catch (e: Throwable) {
                // ID attestation 不支持,fallback 到普通 attestation
                runCatching { ks.deleteEntry(alias) }
                kpg.initialize(buildSpec(includeIds = false))
                kpg.generateKeyPair()
            }

            val chain = ks.getCertificateChain(alias)
                ?: return@runCatching KeystoreAttestation(error = "no cert chain")
            val leaf = chain[0] as java.security.cert.X509Certificate

            // ★K1:逐级验签 leaf→…→root(ghost 伪 leaf 用自己私钥重签→对不上 Google 中间证书公钥=失败=最强穿帮)
            var chainVerified = "true"
            for (i in 0 until chain.size - 1) {
                val vr = runCatching { (chain[i] as java.security.cert.X509Certificate).verify(chain[i + 1].publicKey) }
                if (vr.isFailure) { chainVerified = "false(link $i:${vr.exceptionOrNull()?.javaClass?.simpleName})"; break }
            }
            // ★K1:leaf 有效期跨度(真机 attestation leaf 数千~数万小时;ghost 伪 leaf 常 notBefore+1h)+ root 公钥 SHA256
            val leafValidityHours = (leaf.notAfter.time - leaf.notBefore.time) / 3_600_000L
            val rootSha = runCatching {
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest(chain[chain.size - 1].publicKey.encoded)
                    .joinToString("") { "%02x".format(it) }
            }.getOrNull()
            // ★K4:KeyInfo securityLevel/insideSecureHardware(须在 deleteEntry 前读;vs attestation level 交叉)
            val ki = runCatching {
                val priv = ks.getKey(alias, null) as java.security.PrivateKey
                val kf = java.security.KeyFactory.getInstance(priv.algorithm, "AndroidKeyStore")
                kf.getKeySpec(priv, android.security.keystore.KeyInfo::class.java)
            }.getOrNull()
            val kiLevel = ki?.let { if (Build.VERSION.SDK_INT >= 31) runCatching { securityLevelName(it.securityLevel) }.getOrNull() else null }
            val kiInside = ki?.isInsideSecureHardware

            // OID 1.3.6.1.4.1.11129.2.1.17 = Google KeyDescription extension
            val rawWrapped = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                ?: return@runCatching KeystoreAttestation(chainLength = chain.size,
                    chainVerified = chainVerified, leafValidityHours = leafValidityHours, rootPubKeySha256 = rootSha,
                    keyInfoSecurityLevel = kiLevel, insideSecureHardware = kiInside,
                    error = "no attestation extension(non-TEE root chain)")

            // getExtensionValue 返回 ASN.1 OCTET STRING wrapped 的 raw bytes
            // 拆开外层 OCTET STRING(tag 0x04)拿内层 SEQUENCE
            val inner = unwrapOctetString(rawWrapped)
            val parsed = parseAttestationExtension(inner)

            runCatching { ks.deleteEntry(alias) }
            parsed.copy(chainLength = chain.size, chainVerified = chainVerified,
                leafValidityHours = leafValidityHours, rootPubKeySha256 = rootSha,
                keyInfoSecurityLevel = kiLevel, insideSecureHardware = kiInside)
        }.getOrElse { t ->
            KeystoreAttestation(error = "${t.javaClass.simpleName}: ${t.message?.take(60)}")
        }
    }

    /** ASN.1 OCTET STRING unwrap:0x04 [len] [inner...] → 返回 inner */
    private fun unwrapOctetString(data: ByteArray): ByteArray {
        if (data.isEmpty() || data[0].toInt() and 0xFF != 0x04) return data
        var idx = 1
        val len = readBerLength(data, idx); idx = len.second
        return data.copyOfRange(idx, idx + len.first)
    }

    /** 读 BER length(short form < 128 直接,long form 第一字节高位 1 + 后续字节数);返回 (len, nextIdx) */
    private fun readBerLength(data: ByteArray, idx: Int): Pair<Int, Int> {
        val b = data[idx].toInt() and 0xFF
        if (b < 0x80) return b to (idx + 1)
        val nBytes = b and 0x7F
        var v = 0
        for (i in 1..nBytes) v = (v shl 8) or (data[idx + i].toInt() and 0xFF)
        return v to (idx + 1 + nBytes)
    }

    /**
     * Parse AttestationExtension SEQUENCE:
     *   { INT version, ENUM attestationLevel, INT kmVersion, ENUM kmLevel,
     *     OCTET challenge, OCTET uniqueId, SEQ softwareEnforced, SEQ hardwareEnforced }
     * 然后扫 hardwareEnforced 找 [710]/[711]/[712]/[713]/[716]/[717] EXPLICIT OCTET STRING
     */
    private fun parseAttestationExtension(seq: ByteArray): KeystoreAttestation {
        // 顶层 SEQUENCE(0x30)
        if (seq.isEmpty() || (seq[0].toInt() and 0xFF) != 0x30) {
            return KeystoreAttestation(error = "not SEQUENCE")
        }
        var idx = 1
        val (totalLen, contentStart) = readBerLength(seq, idx)
        idx = contentStart
        val end = idx + totalLen

        // 1. attestationVersion INTEGER
        val (attVer, p1) = readInt(seq, idx); idx = p1
        // 2. attestationSecurityLevel ENUMERATED
        val (attLvl, p2) = readEnum(seq, idx); idx = p2
        // 3. keymasterVersion INTEGER
        val (kmVer, p3) = readInt(seq, idx); idx = p3
        // 4. keymasterSecurityLevel ENUMERATED
        val (kmLvl, p4) = readEnum(seq, idx); idx = p4
        // 5. attestationChallenge OCTET STRING(skip)
        idx = skipOne(seq, idx)
        // 6. uniqueId OCTET STRING(skip)
        idx = skipOne(seq, idx)
        // 7. softwareEnforced SEQUENCE(skip)
        idx = skipOne(seq, idx)
        // 8. hardwareEnforced SEQUENCE — 扫这个找 hw-enforced Build IDs

        if (idx >= end || (seq[idx].toInt() and 0xFF) != 0x30) {
            return KeystoreAttestation(
                attestationVersion = attVer, attestationSecurityLevel = securityLevelName(attLvl),
                keymasterVersion = kmVer, keymasterSecurityLevel = securityLevelName(kmLvl),
                error = "no hardwareEnforced")
        }
        idx++  // skip SEQ tag
        val (hwLen, hwContentStart) = readBerLength(seq, idx)
        idx = hwContentStart
        val hwEnd = idx + hwLen

        // 扫 hardwareEnforced 找 [710]/[711]/[712]/[713]/[716]/[717] EXPLICIT OCTET STRING
        // Tag bytes for context-constructed [tag]:
        //   tag 710 = 0xBF 0x85 0x46
        //   tag 711 = 0xBF 0x85 0x47
        //   tag 712 = 0xBF 0x85 0x48
        //   tag 713 = 0xBF 0x85 0x49
        //   tag 716 = 0xBF 0x85 0x4C
        //   tag 717 = 0xBF 0x85 0x4D
        var brand: String? = null; var device: String? = null; var product: String? = null
        var serial: String? = null; var manufacturer: String? = null; var model: String? = null
        var osVersion: Int? = null; var osPatchLevel: Int? = null
        var vbState: Int? = null; var deviceLocked: Boolean? = null
        var vbKey: String? = null; var vbHash: String? = null
        while (idx < hwEnd) {
            val b0 = seq[idx].toInt() and 0xFF
            if (b0 == 0xBF && idx + 2 < hwEnd && (seq[idx + 1].toInt() and 0xFF) == 0x85) {
                val tag = seq[idx + 2].toInt() and 0xFF
                idx += 3
                val (oLen, oCS) = readBerLength(seq, idx); idx = oCS
                val outerEnd = idx + oLen
                val innerTag = if (idx < outerEnd) seq[idx].toInt() and 0xFF else -1
                when {
                    // EXPLICIT OCTET STRING → Build ID 字符串([710]-[717])
                    innerTag == 0x04 -> {
                        idx++
                        val (iLen, iCS) = readBerLength(seq, idx); idx = iCS
                        val v = String(seq, idx, iLen, Charsets.UTF_8)
                        when (tag) {
                            0x46 -> brand = v          // 710
                            0x47 -> device = v         // 711
                            0x48 -> product = v        // 712
                            0x49 -> serial = v         // 713
                            0x4C -> manufacturer = v   // 716
                            0x4D -> model = v          // 717
                        }
                        idx += iLen
                    }
                    // ★K3:EXPLICIT INTEGER → osVersion[705=0x41]/osPatchLevel[706=0x42]
                    innerTag == 0x02 -> {
                        val (iv, ni) = readInt(seq, idx); idx = ni
                        when (tag) {
                            0x41 -> osVersion = iv
                            0x42 -> osPatchLevel = iv
                        }
                    }
                    // ★K2:EXPLICIT SEQUENCE + tag 0x40 → RootOfTrust[704]
                    //   { verifiedBootKey OCTET, deviceLocked BOOLEAN, verifiedBootState ENUM, [verifiedBootHash OCTET] }
                    innerTag == 0x30 && tag == 0x40 -> {
                        var ri = idx + 1
                        val (_, rcs) = readBerLength(seq, ri); ri = rcs
                        if (ri < outerEnd && (seq[ri].toInt() and 0xFF) == 0x04) {
                            ri++; val (kl, kcs) = readBerLength(seq, ri); ri = kcs
                            vbKey = seq.copyOfRange(ri, ri + kl).joinToString("") { "%02x".format(it) }; ri += kl
                        }
                        if (ri < outerEnd && (seq[ri].toInt() and 0xFF) == 0x01) {
                            ri++; val (bl, bcs) = readBerLength(seq, ri); ri = bcs
                            deviceLocked = (seq[ri].toInt() and 0xFF) != 0; ri += bl
                        }
                        if (ri < outerEnd && (seq[ri].toInt() and 0xFF) == 0x0A) {
                            val (ev, en) = readEnum(seq, ri); vbState = ev; ri = en
                        }
                        if (ri < outerEnd && (seq[ri].toInt() and 0xFF) == 0x04) {
                            ri++; val (hl, hcs) = readBerLength(seq, ri); ri = hcs
                            vbHash = seq.copyOfRange(ri, ri + hl).joinToString("") { "%02x".format(it) }; ri += hl
                        }
                        idx = outerEnd
                    }
                    else -> idx = outerEnd
                }
            } else {
                idx = skipOne(seq, idx)
            }
        }
        return KeystoreAttestation(
            attestationVersion = attVer,
            attestationSecurityLevel = securityLevelName(attLvl),
            keymasterVersion = kmVer,
            keymasterSecurityLevel = securityLevelName(kmLvl),
            osVersion = osVersion, osPatchLevel = osPatchLevel,
            verifiedBootState = vbState, deviceLocked = deviceLocked,
            verifiedBootKeyHex = vbKey, verifiedBootHashHex = vbHash,
            idBrand = brand, idDevice = device, idProduct = product,
            idSerial = serial, idManufacturer = manufacturer, idModel = model,
        )
    }

    private fun readInt(d: ByteArray, idx0: Int): Pair<Int, Int> {
        if ((d[idx0].toInt() and 0xFF) != 0x02) return 0 to skipOne(d, idx0)
        var idx = idx0 + 1
        val (len, cs) = readBerLength(d, idx); idx = cs
        var v = 0
        for (i in 0 until len) v = (v shl 8) or (d[idx + i].toInt() and 0xFF)
        return v to (idx + len)
    }

    private fun readEnum(d: ByteArray, idx0: Int): Pair<Int, Int> {
        if ((d[idx0].toInt() and 0xFF) != 0x0A) return 0 to skipOne(d, idx0)
        var idx = idx0 + 1
        val (len, cs) = readBerLength(d, idx); idx = cs
        var v = 0
        for (i in 0 until len) v = (v shl 8) or (d[idx + i].toInt() and 0xFF)
        return v to (idx + len)
    }

    /** skip 一个 TLV(任意 type),返回下一个位置 */
    private fun skipOne(d: ByteArray, idx0: Int): Int {
        var idx = idx0 + 1
        // 处理 multi-byte tag(高位 1 字节)
        if ((d[idx0].toInt() and 0x1F) == 0x1F) {
            while (idx < d.size && (d[idx].toInt() and 0x80) != 0) idx++
            idx++  // last tag byte
        }
        val (len, cs) = readBerLength(d, idx)
        return cs + len
    }

    private fun securityLevelName(v: Int): String = when (v) {
        0 -> "Software"
        1 -> "TrustedEnvironment(TEE)"
        2 -> "StrongBox"
        else -> "unknown($v)"
    }

    private fun detectEmulator(): String {
        val hits = mutableListOf<String>()
        val fp = Build.FINGERPRINT.orEmpty()
        if (fp.startsWith("generic") || fp.startsWith("unknown")) hits += "fp:$fp"
        if (Build.MODEL.contains("google_sdk", ignoreCase = true)
            || Build.MODEL.contains("Emulator", ignoreCase = true)
            || Build.MODEL.contains("Android SDK built for", ignoreCase = true))
            hits += "model:${Build.MODEL}"
        val hw = Build.HARDWARE.orEmpty()
        if (hw == "goldfish" || hw == "ranchu" || hw.contains("vbox")) hits += "hw:$hw"
        if (NativeBridge.getSystemProperty("ro.kernel.qemu") == "1") hits += "ro.kernel.qemu=1"
        if (NativeBridge.getSystemProperty("ro.boot.qemu") == "1") hits += "ro.boot.qemu=1"
        return if (hits.isEmpty()) "false" else hits.joinToString(";")
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
