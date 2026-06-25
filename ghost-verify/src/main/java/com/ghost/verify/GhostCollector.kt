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
            }
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
                "active_dns != wifi_dhcp_dns" jLayer {
                    val a = activeDns(); val w = dhcpDns()
                    when {
                        a.isEmpty() || w.isEmpty() -> "unknown (a=$a, w=$w)"
                        a == w -> "false"
                        else -> "true (active=$a, dhcp=$w)"
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
        val attestationVersion: Int? = null,
        val attestationSecurityLevel: String? = null,
        val keymasterVersion: Int? = null,
        val keymasterSecurityLevel: String? = null,
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
            // OID 1.3.6.1.4.1.11129.2.1.17 = Google KeyDescription extension
            val rawWrapped = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                ?: return@runCatching KeystoreAttestation(chainLength = chain.size,
                    error = "no attestation extension(non-TEE root chain)")

            // getExtensionValue 返回 ASN.1 OCTET STRING wrapped 的 raw bytes
            // 拆开外层 OCTET STRING(tag 0x04)拿内层 SEQUENCE
            val inner = unwrapOctetString(rawWrapped)
            val parsed = parseAttestationExtension(inner)

            runCatching { ks.deleteEntry(alias) }
            parsed.copy(chainLength = chain.size)
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
        while (idx < hwEnd) {
            val b0 = seq[idx].toInt() and 0xFF
            if (b0 == 0xBF && idx + 2 < hwEnd && (seq[idx + 1].toInt() and 0xFF) == 0x85) {
                val tag = seq[idx + 2].toInt() and 0xFF
                idx += 3
                val (oLen, oCS) = readBerLength(seq, idx); idx = oCS
                val outerEnd = idx + oLen
                // EXPLICIT OCTET STRING:inner 0x04 + len + bytes
                if (idx < outerEnd && (seq[idx].toInt() and 0xFF) == 0x04) {
                    idx++
                    val (iLen, iCS) = readBerLength(seq, idx); idx = iCS
                    val v = String(seq, idx, iLen, Charsets.UTF_8)
                    when (tag) {
                        0x46 -> brand = v   // 710
                        0x47 -> device = v  // 711
                        0x48 -> product = v // 712
                        0x49 -> serial = v  // 713
                        0x4C -> manufacturer = v  // 716
                        0x4D -> model = v   // 717
                    }
                    idx += iLen
                } else {
                    idx = outerEnd
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
