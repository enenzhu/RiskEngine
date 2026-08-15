package com.ghost.verify

import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.pm.FeatureInfo
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.nfc.NfcAdapter
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs
import kotlin.math.sqrt

/** 一个可直接并入 GhostCollector 的聚集性采集字段。 */
data class ClusteringProbeField(
    val category: String,
    val name: String,
    val sources: List<SourceValue>,
)

/**
 * 从普通三方风控 SDK 权限边界读取 Pixel 6 物理锚。
 *
 * 约束:
 * - Camera 只读 characteristics，不 open camera。
 * - Sensor 只短时监听 accel/gyro/magnetic，不改变采样配置或系统状态。
 * - /proc、/sys 同时走 libc 与 raw svc，失败保留为 unavailable，不让整次采集失败。
 */
object ClusteringProbe {
    private const val PRIVATE_SENSOR_TYPE_BASE = 0x10000

    fun collect(context: Context): List<ClusteringProbeField> = buildList {
        addAll(section("cluster-uptime") { collectUptime() })
        addAll(section("cluster-features") { collectFeatures(context) })
        addAll(section("cluster-nfc") { collectNfc(context) })
        addAll(section("cluster-camera") { collectCamera(context) })
        addAll(section("cluster-sensors") { collectSensors(context) })
        addAll(section("cluster-cpu") { collectCpu() })
        addAll(section("cluster-memory") { collectMemory(context) })
    }

    private fun collectUptime(): List<ClusteringProbeField> = buildList {
        val category = "cluster-uptime"
        val wallMs = System.currentTimeMillis()
        val clocks = runCatching { NativeBridge.getClockSnapshot() }.getOrNull()
        fun clock(index: Int): Long? = clocks?.getOrNull(index)?.takeIf { it >= 0L }
        fun nsToMs(v: Long?) = v?.div(1_000_000L)

        val libcBootMs = nsToMs(clock(0))
        val rawBootMs = nsToMs(clock(1))
        val libcMonoMs = nsToMs(clock(2))
        val rawMonoMs = nsToMs(clock(3))
        val libcRawMs = nsToMs(clock(4))
        val rawRawMs = nsToMs(clock(5))

        add(valueField(category, "uptime.java_elapsed_ms", "SystemClock.elapsedRealtime", "java",
            SystemClock.elapsedRealtime().toString()))
        add(valueField(category, "uptime.java_elapsed_nanos_ms", "SystemClock.elapsedRealtimeNanos", "java",
            (SystemClock.elapsedRealtimeNanos() / 1_000_000L).toString()))
        add(valueField(category, "uptime.native_boottime_libc_ms", "clock_gettime(CLOCK_BOOTTIME)", "native",
            libcBootMs?.toString()))
        add(valueField(category, "uptime.native_boottime_raw_ms", "svc clock_gettime(CLOCK_BOOTTIME)", "native-svc",
            rawBootMs?.toString()))
        add(valueField(category, "uptime.native_monotonic_libc_ms", "clock_gettime(CLOCK_MONOTONIC)", "native",
            libcMonoMs?.toString()))
        add(valueField(category, "uptime.native_monotonic_raw_ms", "svc clock_gettime(CLOCK_MONOTONIC)", "native-svc",
            rawMonoMs?.toString()))
        add(valueField(category, "uptime.native_monotonic_raw_libc_ms", "clock_gettime(CLOCK_MONOTONIC_RAW)", "native",
            libcRawMs?.toString()))
        add(valueField(category, "uptime.native_monotonic_raw_svc_ms", "svc clock_gettime(CLOCK_MONOTONIC_RAW)", "native-svc",
            rawRawMs?.toString()))
        add(valueField(category, "uptime.sysinfo_libc_s", "sysinfo().uptime", "native",
            clock(6)?.toString()))
        add(valueField(category, "uptime.sysinfo_raw_s", "svc sysinfo().uptime", "native-svc",
            clock(7)?.toString()))

        val procLibc = NativeBridge.readFile("/proc/uptime", 128).trim()
        val procRaw = NativeBridge.readFileViaSyscall("/proc/uptime", 128).trim()
        add(multiField(category, "uptime.proc_uptime_ms", listOf(
            source("fopen /proc/uptime", "proc") { parseProcUptimeMs(procLibc)?.toString() },
            source("svc open/read /proc/uptime", "proc-svc") { parseProcUptimeMs(procRaw)?.toString() },
        )))

        val statLibc = NativeBridge.readFile("/proc/stat", 64 * 1024)
        val statRaw = NativeBridge.readFileViaSyscall("/proc/stat", 64 * 1024)
        add(multiField(category, "uptime.proc_stat_btime_s", listOf(
            source("fopen /proc/stat btime", "proc") { parseBtime(statLibc)?.toString() },
            source("svc open/read /proc/stat btime", "proc-svc") { parseBtime(statRaw)?.toString() },
        )))

        add(valueField(category, "uptime.boot_epoch_java_s", "wall - Java elapsedRealtime", "derived",
            ((wallMs - SystemClock.elapsedRealtime()) / 1000L).toString()))
        add(valueField(category, "uptime.boot_epoch_libc_s", "wall - libc CLOCK_BOOTTIME", "derived",
            libcBootMs?.let { ((wallMs - it) / 1000L).toString() }))
        add(valueField(category, "uptime.boot_epoch_raw_s", "wall - raw CLOCK_BOOTTIME", "derived",
            rawBootMs?.let { ((wallMs - it) / 1000L).toString() }))
    }

    private fun collectFeatures(context: Context): List<ClusteringProbeField> = buildList {
        val category = "cluster-features"
        val pm = context.packageManager
        val infos = runCatching { pm.systemAvailableFeatures?.toList().orEmpty() }.getOrDefault(emptyList())
        val entries = infos.map(::featureEntry).sorted()
        val named = infos.mapNotNull { it.name }.distinct().sorted()
        val gles = infos.filter { it.name == null }

        val contractViolations = mutableListOf<String>()
        val acceptsMax = mutableListOf<String>()
        for (info in infos) {
            val name = info.name ?: continue
            runCatching {
                if (!pm.hasSystemFeature(name, info.version)) {
                    contractViolations += "$name:listed_v${info.version}_but_query_false"
                }
                if (info.version < Int.MAX_VALUE && pm.hasSystemFeature(name, info.version + 1)) {
                    contractViolations += "$name:reported_v${info.version}_accepts_v${info.version + 1}"
                }
                if (pm.hasSystemFeature(name, Int.MAX_VALUE)) acceptsMax += name
            }.onFailure { contractViolations += "$name:${it.javaClass.simpleName}" }
        }

        val profile = entries.joinToString("\n")
        add(valueField(category, "features.versioned_profile", "FeatureInfo(name/version/GLES/flags)", "java", profile))
        add(valueField(category, "features.versioned_sha256", "FeatureInfo canonical SHA-256", "derived",
            profile.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "features.named_count", "named FeatureInfo count", "java", named.size.toString()))
        add(valueField(category, "features.gles_entry_count", "FeatureInfo(name=null/GLES) count", "java", gles.size.toString()))
        add(valueField(category, "features.gles_versions", "FeatureInfo.reqGlEsVersion", "java",
            gles.map { it.reqGlEsVersion }.sorted().joinToString(",")))
        add(valueField(category, "features.required_flag_count", "FeatureInfo.FLAG_REQUIRED count", "java",
            infos.count { it.flags and FeatureInfo.FLAG_REQUIRED != 0 }.toString()))
        add(valueField(category, "features.version_contract_violation_count", "listed version vs hasSystemFeature(name,version)", "java",
            contractViolations.size.toString()))
        add(valueField(category, "features.version_contract_violations", "feature version contract details", "java",
            contractViolations.sorted().joinToString(";")))
        add(valueField(category, "features.accepts_int_max_count", "hasSystemFeature(name,Int.MAX_VALUE)", "java",
            acceptsMax.size.toString()))
        add(valueField(category, "features.accepts_int_max_names", "features accepting impossible max version", "java",
            acceptsMax.sorted().joinToString(",")))

        val probes = linkedMapOf(
            "feature.has.camera" to "android.hardware.camera",
            "feature.has.camera_level_full" to "android.hardware.camera.level.full",
            "feature.has.camera_raw" to "android.hardware.camera.capability.raw",
            "feature.has.camera_manual_sensor" to "android.hardware.camera.capability.manual_sensor",
            "feature.has.camera_concurrent" to "android.hardware.camera.concurrent",
            "feature.has.nfc" to "android.hardware.nfc",
            "feature.has.nfc_hce" to "android.hardware.nfc.hce",
            "feature.has.nfc_hcef" to "android.hardware.nfc.hcef",
            "feature.has.nfc_ese" to "android.hardware.nfc.ese",
            "feature.has.nfc_uicc" to "android.hardware.nfc.uicc",
            "feature.has.omapi_ese" to "android.hardware.se.omapi.ese",
            "feature.has.omapi_uicc" to "android.hardware.se.omapi.uicc",
            "feature.has.strongbox" to "android.hardware.strongbox_keystore",
            "feature.has.device_unique_attestation" to "android.hardware.device_unique_attestation",
            "feature.has.sensor_barometer" to "android.hardware.sensor.barometer",
            "feature.has.sensor_hifi" to "android.hardware.sensor.hifi_sensors",
        )
        for ((field, feature) in probes) {
            add(safeField(category, field, "hasSystemFeature($feature)", "java") {
                pm.hasSystemFeature(feature).toString()
            })
        }
    }

    @Suppress("DEPRECATION")
    private fun collectNfc(context: Context): List<ClusteringProbeField> = buildList {
        val category = "cluster-nfc"
        val pm = context.packageManager
        val adapter = runCatching { NfcAdapter.getDefaultAdapter(context) }.getOrNull()
        val featureNames = listOf(
            "android.hardware.nfc", "android.hardware.nfc.any", "android.hardware.nfc.hce",
            "android.hardware.nfc.hcef", "android.hardware.nfc.uicc", "android.hardware.nfc.ese",
            "android.hardware.se.omapi.ese", "android.hardware.se.omapi.uicc", "com.nxp.mifare",
        )
        val featureProfile = featureNames.joinToString("|") { "$it=${pm.hasSystemFeature(it)}" }
        val adapterCapabilityProfile = buildList {
            add("present=${adapter != null}")
            if (adapter != null) {
                add("secure_supported=${runCatching { adapter.isSecureNfcSupported }.getOrNull()}")
                add("observe_supported=${reflectBoolean(adapter, "isObserveModeSupported")}")
            }
        }.joinToString("|")
        val profile = "$featureProfile|$adapterCapabilityProfile"
        add(valueField(category, "nfc.permission_granted", "NFC normal permission", "java",
            (context.checkSelfPermission(Manifest.permission.NFC) == PackageManager.PERMISSION_GRANTED).toString()))
        add(valueField(category, "nfc.adapter_present", "NfcAdapter.getDefaultAdapter", "java", (adapter != null).toString()))
        add(valueField(category, "nfc.adapter_enabled", "NfcAdapter.isEnabled", "java",
            adapter?.let { runCatching { it.isEnabled.toString() }.getOrNull() }))
        add(valueField(category, "nfc.profile", "NFC feature + adapter profile", "java", profile))
        add(valueField(category, "nfc.profile_sha256", "NFC profile SHA-256", "derived", sha256(profile)))
    }

    private fun collectCamera(context: Context): List<ClusteringProbeField> = buildList {
        val category = "cluster-camera"
        val permission = context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        add(valueField(category, "camera.permission_granted", "CAMERA runtime permission", "java", permission.toString()))

        val manager = context.getSystemService(CameraManager::class.java)
        if (manager == null) {
            add(valueField(category, "camera.count", "CameraManager", "java", "0"))
            return@buildList
        }
        val ids = runCatching { manager.cameraIdList.sorted() }.getOrElse {
            add(errorField(category, "camera.error", "CameraManager.getCameraIdList", "java", it))
            emptyList()
        }
        add(valueField(category, "camera.ids", "CameraManager.cameraIdList", "java", ids.joinToString(",")))
        add(valueField(category, "camera.count", "CameraManager.cameraIdList.size", "java", ids.size.toString()))

        val topology = mutableListOf<String>()
        val calibration = mutableListOf<String>()
        val versions = mutableListOf<String>()
        val keyProfile = mutableListOf<String>()
        var anyFull = false
        var anyRaw = false
        var anyManual = false

        for (id in ids) {
            val characteristics = runCatching { manager.getCameraCharacteristics(id) }.getOrElse {
                topology += "$id:error=${it.javaClass.simpleName}"
                null
            }
            val c = characteristics ?: continue
            val level = c.getSafe(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)
            val caps = c.getSafe(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES)?.sortedArray()
            anyFull = anyFull || level == CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_FULL ||
                level == CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_3
            anyRaw = anyRaw || caps?.contains(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_RAW) == true
            anyManual = anyManual || caps?.contains(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR) == true

            val map = c.getSafe(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            val streams = runCatching {
                map?.outputFormats?.sorted()?.joinToString(";") { format ->
                    val sizes = map.getOutputSizes(format)?.sortedWith(compareBy({ it.width }, { it.height }))
                        ?.joinToString(",") { "${it.width}x${it.height}" }.orEmpty()
                    "$format=[$sizes]"
                }.orEmpty()
            }.getOrDefault("")
            val physicalIds = runCatching { c.physicalCameraIds.sorted().joinToString(",") }.getOrDefault("")
            topology += listOf(
                "id=$id",
                "facing=${canon(c.getSafe(CameraCharacteristics.LENS_FACING))}",
                "level=${canon(level)}",
                "caps=${canon(caps)}",
                "orientation=${canon(c.getSafe(CameraCharacteristics.SENSOR_ORIENTATION))}",
                "flash=${canon(c.getSafe(CameraCharacteristics.FLASH_INFO_AVAILABLE))}",
                "physical_ids=$physicalIds",
                "focal=${canon(c.getSafe(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS))}",
                "pixel=${canon(c.getSafe(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE))}",
                "active=${canon(c.getSafe(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE))}",
                "physical_size=${canon(c.getSafe(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE))}",
                "max_zoom=${canon(c.getSafe(CameraCharacteristics.SCALER_AVAILABLE_MAX_DIGITAL_ZOOM))}",
                "streams=$streams",
            ).joinToString("|")

            val calibrations = linkedMapOf<String, Any?>(
                "intrinsic" to c.getSafe(CameraCharacteristics.LENS_INTRINSIC_CALIBRATION),
                "distortion" to c.getSafe(CameraCharacteristics.LENS_DISTORTION),
                "pose_rotation" to c.getSafe(CameraCharacteristics.LENS_POSE_ROTATION),
                "pose_translation" to c.getSafe(CameraCharacteristics.LENS_POSE_TRANSLATION),
                "black_level" to c.getSafe(CameraCharacteristics.SENSOR_BLACK_LEVEL_PATTERN),
                "calibration1" to c.getSafe(CameraCharacteristics.SENSOR_CALIBRATION_TRANSFORM1),
                "calibration2" to c.getSafe(CameraCharacteristics.SENSOR_CALIBRATION_TRANSFORM2),
                "color1" to c.getSafe(CameraCharacteristics.SENSOR_COLOR_TRANSFORM1),
                "color2" to c.getSafe(CameraCharacteristics.SENSOR_COLOR_TRANSFORM2),
                "forward1" to c.getSafe(CameraCharacteristics.SENSOR_FORWARD_MATRIX1),
                "forward2" to c.getSafe(CameraCharacteristics.SENSOR_FORWARD_MATRIX2),
            )
            calibrations.filterValues { it != null }.forEach { (name, value) ->
                calibration += "$id:$name=${canon(value)}"
            }
            c.getSafe(CameraCharacteristics.INFO_VERSION)?.takeIf { it.isNotBlank() }?.let {
                versions += "$id=$it"
            }
            keyProfile += "$id=${runCatching { c.keys.map { it.name }.sorted().joinToString(",") }.getOrDefault("")}"
        }

        val concurrent = runCatching {
            manager.concurrentCameraIds.map { it.sorted().joinToString("+") }.sorted()
        }.getOrDefault(emptyList())
        topology += "concurrent=${concurrent.joinToString(",")}"

        val topologyText = topology.sorted().joinToString("\n")
        val calibrationText = calibration.sorted().joinToString("\n")
        val versionText = versions.sorted().joinToString("\n")
        val keysText = keyProfile.sorted().joinToString("\n")
        add(valueField(category, "camera.topology_profile", "CameraCharacteristics operational topology", "java", topologyText))
        add(valueField(category, "camera.topology_sha256", "camera topology SHA-256", "derived",
            topologyText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "camera.calibration_profile", "optional calibration keys", "java", calibrationText))
        add(valueField(category, "camera.calibration_sha256", "camera calibration SHA-256", "derived",
            calibrationText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "camera.info_version_profile", "CameraCharacteristics.INFO_VERSION", "java", versionText))
        add(valueField(category, "camera.info_version_sha256", "camera INFO_VERSION SHA-256", "derived",
            versionText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "camera.keys_sha256", "available characteristic keys SHA-256", "derived",
            keysText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "camera.capability.any_full", "hardware level FULL/LEVEL_3", "java", anyFull.toString()))
        add(valueField(category, "camera.capability.any_raw", "REQUEST_AVAILABLE_CAPABILITIES_RAW", "java", anyRaw.toString()))
        add(valueField(category, "camera.capability.any_manual_sensor", "REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR", "java", anyManual.toString()))
        add(valueField(category, "camera.concurrent_set_count", "CameraManager.concurrentCameraIds", "java", concurrent.size.toString()))
    }

    private fun collectSensors(context: Context): List<ClusteringProbeField> = buildList {
        val category = "cluster-sensors"
        val manager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val sensors = manager?.getSensorList(Sensor.TYPE_ALL).orEmpty()
            .sortedWith(compareBy<Sensor>({ it.type }, { it.stringType }, { it.name }, { it.id }))

        val topology = mutableListOf<String>()
        val metadata = mutableListOf<String>()
        val ids = mutableListOf<String>()
        val privateTypes = mutableListOf<String>()
        val metadataWithoutId = mutableListOf<String>()
        for ((ordinal, sensor) in sensors.withIndex()) {
            val topoWithoutOrdinal = listOf(
                "type=${sensor.type}", "string=${sensor.stringType}", "wake=${sensor.isWakeUpSensor}",
                "report=${sensor.reportingMode}", "dynamic=${sensor.isDynamicSensor}",
                "additional=${sensor.isAdditionalInfoSupported}",
            ).joinToString("|")
            val metaNoId = listOf(
                topoWithoutOrdinal, "name=${sensor.name}", "vendor=${sensor.vendor}", "version=${sensor.version}",
                "range=${fmt(sensor.maximumRange.toDouble())}", "resolution=${fmt(sensor.resolution.toDouble())}",
                "power=${fmt(sensor.power.toDouble())}", "minDelay=${sensor.minDelay}", "maxDelay=${sensor.maxDelay}",
                "fifoReserved=${sensor.fifoReservedEventCount}", "fifoMax=${sensor.fifoMaxEventCount}",
            ).joinToString("|")
            val handle = reflectInt(sensor, "mHandle")
            topology += "$topoWithoutOrdinal|ordinal=$ordinal"
            metadataWithoutId += metaNoId
            metadata += "$metaNoId|id=${sensor.id}|handle=${handle ?: "<hidden>"}"
            ids += "type=${sensor.type}|string=${sensor.stringType}|id=${sensor.id}"
            if (sensor.type >= PRIVATE_SENSOR_TYPE_BASE) {
                privateTypes += "type=${sensor.type}|string=${sensor.stringType}|name=${sensor.name}|vendor=${sensor.vendor}"
            }
        }
        val duplicateCount = metadataWithoutId.groupingBy { it }.eachCount().values.sumOf { (it - 1).coerceAtLeast(0) }
        val googlePrivateMarkers = privateTypes.filter {
            val v = it.lowercase()
            v.contains("google") || v.contains("pixel") || v.contains("double twist") ||
                v.contains("camera v-sync") || v.contains("camera_vsync") || v.contains("binned brightness")
        }

        val topologyText = topology.joinToString("\n")
        val metadataText = metadata.joinToString("\n")
        val publicMetadataText = metadataWithoutId.joinToString("\n")
        val idsText = ids.joinToString("\n")
        val nonZeroIdCount = sensors.count { it.id != 0 }
        val privateText = privateTypes.joinToString("\n")
        add(valueField(category, "sensor.full_profile", "Sensor public metadata + reflected handle", "java", metadataText))
        add(valueField(category, "sensor.topology_sha256", "sensor topology SHA-256", "derived",
            topologyText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "sensor.metadata_sha256", "public sensor metadata excluding id/handle SHA-256", "derived",
            publicMetadataText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "sensor.ids_profile", "Sensor.getId() profile", "java", idsText))
        add(valueField(category, "sensor.nonzero_id_count", "Sensor.getId() != 0 count", "derived",
            nonZeroIdCount.toString()))
        add(valueField(category, "sensor.ids_sha256", "Sensor.getId profile SHA-256", "derived",
            idsText.takeIf { it.isNotEmpty() && nonZeroIdCount > 0 }?.let(::sha256)))
        add(valueField(category, "sensor.private_types_profile", "OEM private sensor types", "java", privateText))
        add(valueField(category, "sensor.private_types_sha256", "private sensor type SHA-256", "derived",
            privateText.takeIf { it.isNotEmpty() }?.let(::sha256)))
        add(valueField(category, "sensor.private_type_count", "type >= 0x10000", "java", privateTypes.size.toString()))
        add(valueField(category, "sensor.google_private_marker_count", "Pixel/Google private sensor markers", "derived",
            googlePrivateMarkers.size.toString()))
        add(valueField(category, "sensor.duplicate_public_tuple_count", "duplicate complete public metadata tuples", "derived",
            duplicateCount.toString()))

        val presence = linkedMapOf(
            "sensor.actual.accelerometer" to Sensor.TYPE_ACCELEROMETER,
            "sensor.actual.gyroscope" to Sensor.TYPE_GYROSCOPE,
            "sensor.actual.magnetic" to Sensor.TYPE_MAGNETIC_FIELD,
            "sensor.actual.pressure" to Sensor.TYPE_PRESSURE,
        )
        for ((field, type) in presence) {
            add(valueField(category, field, "SensorManager.getDefaultSensor($type)", "java",
                (manager?.getDefaultSensor(type) != null).toString()))
        }

        val eventStats = manager?.let { sampleSensors(it) }
        add(valueField(category, "sensor.event_stats", "650ms accel/gyro/magnetic sample statistics", "java", eventStats?.profile))
        add(valueField(category, "sensor.event_stats_sha256", "dynamic sensor stats SHA-256", "derived",
            eventStats?.profile?.let(::sha256)))
        add(valueField(category, "sensor.event_timestamp_delta_abs_max_ms",
            "abs(SystemClock.elapsedRealtimeNanos - SensorEvent.timestamp)", "derived",
            eventStats?.maxTimestampDeltaMs?.toString()))
    }

    private fun collectCpu(): List<ClusteringProbeField> = buildList {
        val category = "cluster-cpu"
        val policyRoot = File("/sys/devices/system/cpu/cpufreq")
        val javaPaths = buildList {
            policyRoot.listFiles()?.filter { it.isDirectory && it.name.matches(Regex("policy\\d+")) }
                ?.forEach { add(it.absolutePath) }
            File("/sys/devices/system/cpu").listFiles()
                ?.filter { it.isDirectory && it.name.matches(Regex("cpu\\d+")) }
                ?.map { File(it, "cpufreq") }
                ?.filter { it.isDirectory }
                ?.forEach { add(it.absolutePath) }
        }.distinct().sorted()
        val shellPaths = NativeBridge.execShell(
            "for d in /sys/devices/system/cpu/cpufreq/policy* /sys/devices/system/cpu/cpu[0-9]*/cpufreq; do [ -d \"\$d\" ] && echo \"\$d\"; done",
            16 * 1024,
        ).lineSequence().map { it.trim() }.filter { it.startsWith("/sys/") }.distinct().sorted().toList()
        add(multiField(category, "cpu.policy_paths", listOf(
            SourceValue("java File.list", "java", javaPaths.joinToString(",").ifEmpty { null }),
            SourceValue("popen shell glob", "shell", shellPaths.joinToString(",").ifEmpty { null }),
        )))

        val paths = (javaPaths + shellPaths).distinct().sorted()
        val staticNames = listOf(
            "affected_cpus", "related_cpus", "cpuinfo_min_freq", "cpuinfo_max_freq",
            "cpuinfo_transition_latency", "scaling_available_frequencies", "scaling_available_governors", "scaling_driver",
        )
        fun profile(raw: Boolean): Pair<String, Int> {
            var readable = 0
            val rows = mutableListOf<String>()
            for (path in paths) {
                val label = path.removePrefix("/sys/devices/system/cpu/")
                val values = staticNames.joinToString("|") { name ->
                    val v = readPath("$path/$name", raw)
                    if (v != null) readable++
                    "$name=${v ?: "<unavailable>"}"
                }
                rows += "$label|$values"
            }
            for (name in listOf("online", "present", "possible", "offline")) {
                val v = readPath("/sys/devices/system/cpu/$name", raw)
                if (v != null) readable++
                rows += "cpu.$name=${v ?: "<unavailable>"}"
            }
            return rows.joinToString("\n") to readable
        }
        val (libcProfile, libcReadable) = profile(false)
        val (rawProfile, rawReadable) = profile(true)
        add(multiField(category, "cpu.policy_static_profile", listOf(
            SourceValue("fopen cpufreq/sysfs", "native", libcProfile.takeIf { libcReadable > 0 }),
            SourceValue("svc open/read cpufreq/sysfs", "native-svc", rawProfile.takeIf { rawReadable > 0 }),
        )))
        add(valueField(category, "cpu.policy_static_sha256", "raw sysfs static profile SHA-256", "derived",
            rawProfile.takeIf { rawReadable > 0 }?.let(::sha256)))
        add(valueField(category, "cpu.policy_readable_static_count", "readable static sysfs files", "derived",
            rawReadable.toString()))

        val samples = mutableListOf<String>()
        repeat(3) { sampleIndex ->
            val row = paths.joinToString("|") { path ->
                val label = path.removePrefix("/sys/devices/system/cpu/")
                val values = listOf("scaling_cur_freq", "scaling_min_freq", "scaling_max_freq", "scaling_governor")
                    .joinToString(",") { name -> "$name=${readPath("$path/$name", true) ?: "<unavailable>"}" }
                "$label={$values}"
            }
            samples += "s$sampleIndex:$row"
            if (sampleIndex < 2) Thread.sleep(80)
        }
        add(valueField(category, "cpu.policy_cur_freq_samples", "3x raw scaling_cur_freq", "native-svc",
            samples.joinToString(";")))
    }

    private fun collectMemory(context: Context): List<ClusteringProbeField> = buildList {
        val category = "cluster-memory"
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val libcMeminfo = parseMeminfo(NativeBridge.readFile("/proc/meminfo", 64 * 1024))
        val procSamples = mutableListOf<Map<String, Long>>()
        val amSamples = mutableListOf<ActivityManager.MemoryInfo>()
        repeat(3) { index ->
            parseMeminfo(NativeBridge.readFileViaSyscall("/proc/meminfo", 64 * 1024))?.let(procSamples::add)
            am?.let {
                val info = ActivityManager.MemoryInfo()
                runCatching { it.getMemoryInfo(info) }.onSuccess { amSamples += info }
            }
            if (index < 2) Thread.sleep(100)
        }

        val selected = listOf(
            "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "Active", "Inactive",
            "Dirty", "AnonPages", "Mapped", "Slab", "SReclaimable", "SUnreclaim", "SwapTotal", "SwapFree",
        )
        val procText = procSamples.mapIndexed { i, sample ->
            "s$i:" + selected.joinToString("|") { "$it=${sample[it] ?: -1}" }
        }.joinToString(";")
        val amText = amSamples.mapIndexed { i, sample ->
            "s$i:total=${sample.totalMem / 1024}|avail=${sample.availMem / 1024}|threshold=${sample.threshold / 1024}|low=${sample.lowMemory}"
        }.joinToString(";")
        val dynamicKeys = selected - setOf("MemTotal", "SwapTotal")
        val procUnique = procSamples.map { s -> dynamicKeys.joinToString("|") { (s[it] ?: -1).toString() } }.toSet().size
        val amUnique = amSamples.map { "${it.availMem}|${it.threshold}|${it.lowMemory}" }.toSet().size
        val amThresholdUnique = amSamples.map { it.threshold }.toSet().size
        val procTotalKb = procSamples.firstOrNull()?.get("MemTotal")
        val amTotalKb = amSamples.firstOrNull()?.totalMem?.div(1024)
        val pairedAvailDelta = procSamples.zip(amSamples).mapNotNull { (proc, ami) ->
            proc["MemAvailable"]?.let { abs(it - ami.availMem / 1024) }
        }.maxOrNull()
        val amMaxStep = amSamples.zipWithNext().maxOfOrNull { (a, b) -> abs(a.availMem - b.availMem) / 1024 }
        val staticProfile = buildString {
            append("procTotalKb=$procTotalKb")
            append("|amTotalKb=$amTotalKb")
            append("|swapTotalKb=${procSamples.firstOrNull()?.get("SwapTotal")}")
            append("|runtimeMaxMb=${Runtime.getRuntime().maxMemory() / 1024 / 1024}")
            append("|memoryClassMb=${am?.memoryClass}")
            append("|largeMemoryClassMb=${am?.largeMemoryClass}")
            append("|lowRam=${am?.isLowRamDevice}")
        }

        add(valueField(category, "memory.meminfo_samples", "3x raw /proc/meminfo selected fields", "proc-svc", procText))
        add(valueField(category, "memory.am_samples", "3x ActivityManager.MemoryInfo", "java", amText))
        add(valueField(category, "memory.meminfo_unique_dynamic_count", "unique dynamic meminfo tuples", "derived", procUnique.toString()))
        add(valueField(category, "memory.am_unique_dynamic_count", "unique ActivityManager tuples", "derived", amUnique.toString()))
        add(valueField(category, "memory.am_threshold_unique_count", "unique ActivityManager threshold values", "derived",
            amThresholdUnique.toString()))
        add(multiField(category, "memory.proc_total_kb", listOf(
            SourceValue("svc open/read /proc/meminfo MemTotal", "proc-svc", procTotalKb?.toString()),
            SourceValue("fopen /proc/meminfo MemTotal", "proc", libcMeminfo?.get("MemTotal")?.toString()),
        )))
        add(valueField(category, "memory.am_total_kb", "ActivityManager totalMem", "java", amTotalKb?.toString()))
        add(valueField(category, "memory.am_proc_avail_max_delta_kb", "max |AM avail - proc MemAvailable|", "derived",
            pairedAvailDelta?.toString()))
        add(valueField(category, "memory.am_avail_max_step_kb", "max 100ms ActivityManager avail jump", "derived",
            amMaxStep?.toString()))
        add(valueField(category, "memory.static_profile", "RAM + heap class profile", "derived", staticProfile))
        add(valueField(category, "memory.static_profile_sha256", "memory static profile SHA-256", "derived", sha256(staticProfile)))
    }

    private data class SensorSample(val values: FloatArray, val timestampDeltaNs: Long)
    private data class SensorStats(val profile: String, val maxTimestampDeltaMs: Long?)

    private fun sampleSensors(manager: SensorManager): SensorStats {
        val wanted = listOf(Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_MAGNETIC_FIELD)
        val samples = ConcurrentHashMap<Int, MutableList<SensorSample>>()
        val thread = HandlerThread("ghost-verify-sensors").apply { start() }
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                val list = samples.getOrPut(event.sensor.type) { mutableListOf() }
                synchronized(list) {
                    if (list.size < 64) {
                        list += SensorSample(
                            event.values.copyOf(),
                            SystemClock.elapsedRealtimeNanos() - event.timestamp,
                        )
                    }
                }
            }
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }
        try {
            val handler = Handler(thread.looper)
            for (type in wanted) {
                manager.getDefaultSensor(type)?.let {
                    runCatching { manager.registerListener(listener, it, SensorManager.SENSOR_DELAY_GAME, 0, handler) }
                }
            }
            Thread.sleep(650)
        } finally {
            runCatching { manager.unregisterListener(listener) }
            thread.quitSafely()
            runCatching { thread.join(500) }
        }

        val rows = mutableListOf<String>()
        val allDeltas = mutableListOf<Long>()
        for (type in wanted) {
            val list = samples[type]?.let { synchronized(it) { it.toList() } }.orEmpty()
            allDeltas += list.map { abs(it.timestampDeltaNs) }
            if (list.isEmpty()) {
                rows += "type=$type|count=0"
                continue
            }
            val width = list.minOf { it.values.size }.coerceAtMost(3)
            val means = DoubleArray(width) { axis -> list.map { it.values[axis].toDouble() }.average() }
            val stds = DoubleArray(width) { axis ->
                sqrt(list.map { sample ->
                    val d = sample.values[axis].toDouble() - means[axis]
                    d * d
                }.average())
            }
            val norms = list.map { sample ->
                sqrt((0 until width).sumOf { axis ->
                    val v = sample.values[axis].toDouble(); v * v
                })
            }
            val normMean = norms.average()
            val normStd = sqrt(norms.map { val d = it - normMean; d * d }.average())
            val deltasMs = list.map { it.timestampDeltaNs / 1_000_000.0 }
            rows += listOf(
                "type=$type", "count=${list.size}",
                "mean=${means.joinToString(",") { fmt(it) }}",
                "std=${stds.joinToString(",") { fmt(it) }}",
                "normMean=${fmt(normMean)}", "normStd=${fmt(normStd)}",
                "timestampDeltaMeanMs=${fmt(deltasMs.average())}",
            ).joinToString("|")
        }
        return SensorStats(
            profile = rows.joinToString(";"),
            maxTimestampDeltaMs = allDeltas.maxOrNull()?.div(1_000_000L),
        )
    }

    private fun parseProcUptimeMs(value: String): Long? =
        value.trim().substringBefore(' ').toDoubleOrNull()?.times(1000.0)?.toLong()

    private fun parseBtime(value: String): Long? = value.lineSequence()
        .firstOrNull { it.startsWith("btime ") }
        ?.substringAfter(' ')?.trim()?.toLongOrNull()

    private fun parseMeminfo(value: String): Map<String, Long>? {
        if (value.isBlank()) return null
        val out = linkedMapOf<String, Long>()
        value.lineSequence().forEach { line ->
            val name = line.substringBefore(':', "").trim()
            val number = Regex("\\d+").find(line.substringAfter(':', ""))?.value?.toLongOrNull()
            if (name.isNotEmpty() && number != null) out[name] = number
        }
        return out.takeIf { it.containsKey("MemTotal") }
    }

    private fun readPath(path: String, raw: Boolean): String? {
        val value = if (raw) NativeBridge.readFileViaSyscall(path, 16 * 1024)
        else NativeBridge.readFile(path, 16 * 1024)
        return value.trim().replace(Regex("\\s+"), " ").takeIf { it.isNotEmpty() }
    }

    private fun featureEntry(info: FeatureInfo): String = if (info.name == null) {
        "<gles>|req=0x${info.reqGlEsVersion.toString(16)}|flags=${info.flags}"
    } else {
        "${info.name}|version=${info.version}|flags=${info.flags}"
    }

    private fun reflectBoolean(target: Any, method: String): Boolean? = runCatching {
        target.javaClass.getMethod(method).invoke(target) as? Boolean
    }.getOrNull()

    private fun reflectInt(target: Any, field: String): Int? = runCatching {
        target.javaClass.getDeclaredField(field).apply { isAccessible = true }.getInt(target)
    }.getOrNull()

    private fun <T> CameraCharacteristics.getSafe(key: CameraCharacteristics.Key<T>): T? =
        runCatching { get(key) }.getOrNull()

    private fun canon(value: Any?): String = when (value) {
        null -> "<null>"
        is FloatArray -> value.joinToString(",") { fmt(it.toDouble()) }
        is DoubleArray -> value.joinToString(",") { fmt(it) }
        is IntArray -> value.joinToString(",")
        is LongArray -> value.joinToString(",")
        is BooleanArray -> value.joinToString(",")
        is Array<*> -> value.joinToString(",") { canon(it) }
        is Collection<*> -> value.joinToString(",") { canon(it) }
        else -> value.toString()
    }

    private fun fmt(value: Double): String = String.format(Locale.US, "%.6f", value)

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

    private fun valueField(
        category: String,
        name: String,
        source: String,
        layer: String,
        value: String?,
    ) = ClusteringProbeField(category, name, listOf(SourceValue(source, layer, value?.takeIf { it.isNotEmpty() })))

    private fun errorField(
        category: String,
        name: String,
        source: String,
        layer: String,
        error: Throwable,
    ) = ClusteringProbeField(category, name, listOf(SourceValue(
        source, layer, null, "${error.javaClass.simpleName}:${error.message}",
    )))

    private fun multiField(category: String, name: String, sources: List<SourceValue>) =
        ClusteringProbeField(category, name, sources)

    private inline fun safeField(
        category: String,
        name: String,
        sourceName: String,
        layer: String,
        block: () -> String?,
    ): ClusteringProbeField = ClusteringProbeField(category, name, listOf(source(sourceName, layer, block)))

    private inline fun source(source: String, layer: String, block: () -> String?): SourceValue = try {
        SourceValue(source, layer, block()?.takeIf { it.isNotEmpty() })
    } catch (t: Throwable) {
        SourceValue(source, layer, null, "${t.javaClass.simpleName}:${t.message}")
    }

    private inline fun section(
        category: String,
        block: () -> List<ClusteringProbeField>,
    ): List<ClusteringProbeField> = try {
        block()
    } catch (t: Throwable) {
        listOf(errorField(
            category = category,
            name = "$category.collection_error",
            source = "section collector",
            layer = "java",
            error = t,
        ))
    }
}
