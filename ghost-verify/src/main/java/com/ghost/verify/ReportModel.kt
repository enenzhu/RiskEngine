package com.ghost.verify

/** 单个采集源的结果。 */
data class SourceValue(
    val source: String,        // eg "Build.MANUFACTURER" / "ro.product.manufacturer" / "getprop"
    val layer: String,         // "java" / "native" / "shell" / "proc"
    val value: String?,        // null 表示采集失败
    val error: String? = null
)

/** 单个字段的多源聚合 + 一致性判定。 */
data class FieldResult(
    val name: String,
    val category: String,
    val sources: List<SourceValue>,
    val consistent: Boolean,
    val canonicalValue: String? = null
) {
    companion object {
        fun build(name: String, category: String, sources: List<SourceValue>): FieldResult {
            val nonNullValues = sources.mapNotNull { it.value?.takeIf { v -> v.isNotEmpty() } }.toSet()
            val consistent = nonNullValues.size <= 1
            return FieldResult(
                name = name,
                category = category,
                sources = sources,
                consistent = consistent,
                canonicalValue = nonNullValues.firstOrNull()
            )
        }
    }
}

/** 跨字段一致性违规 — 多个 field 的 canonicalValue 之间应该满足某种关系但不满足。 */
data class CrossFieldViolation(
    val ruleName: String,        // 规则名(便于 grep)
    val severity: String,        // "high" / "medium" / "low"
    val fields: List<String>,    // 涉及的 field 名
    val values: Map<String, String?>, // 各 field 当前值
    val expected: String,        // 期望关系描述
    val note: String = ""
)

/** 整个采集 session 的根 report。 */
data class CollectReport(
    val timestamp: Long,
    val timestampHuman: String,
    val sessionId: String,
    val deviceLabel: String,
    val fieldCount: Int,
    val inconsistentCount: Int,
    val fields: List<FieldResult>,
    val crossFieldViolations: List<CrossFieldViolation> = emptyList()
)

/** 跨字段一致性规则引擎。 */
object CrossFieldChecker {
    /** 检查所有 cross-field 规则,返回 violation 列表 */
    fun run(fields: List<FieldResult>): List<CrossFieldViolation> {
        val map = fields.associateBy { it.name }
        val violations = mutableListOf<CrossFieldViolation>()

        // === DPI 同源校验:所有 dpi 类 field 理论值都 = ghost spoof dpi(±5 容差) ===
        val dpiFields = listOf(
            "dpi_app_resources_java",
            "dpi_native_prop",
            "dpi_density_device_stable",
            "window_metrics_density",
            "iwm_initial_display_density",
            "iwm_base_display_density",
            "wm_density_cmd",
            "settings_secure_display_density_forced",
        )
        violations += checkAllEqualWithin(map, dpiFields, "DPI_ALL_EQUAL", tolerance = 5,
            note = "所有 dpi 读路径应等于同一值(deviceInfo.dpi)")

        // === Resolution 同源校验 ===
        val resFields = listOf(
            "resolution",
            "wm_size_cmd",
            "iwm_initial_display_size",
            "iwm_base_display_size",
        )
        violations += checkAllEqualNormalized(map, resFields, "RESOLUTION_ALL_EQUAL",
            note = "所有 resolution 读路径应等于同一值(normalize 大小写/排序)")

        // === 截图 API 一致性 ===
        // app 内截图(view.draw / PixelCopy / WindowMetrics)应跟 wm size 一致 — spoof 覆盖
        val screenshotAppFields = listOf(
            "screenshot_pixelcopy_size",
            "screenshot_view_draw_size",
            "window_current_metrics_bounds",
            "resolution",
        )
        violations += checkAllEqualNormalized(map, screenshotAppFields,
            "SCREENSHOT_APP_API_LEAK",
            note = "app 内截图 API(PixelCopy/View.draw/WindowMetrics)应 = wm size; 偏离=ghost spoof 没覆盖到的截图路径")

        // 漏点专项:SF dumpsys / screencap 跟 wm size 不一致是预期(ghost 没 hook system_server SF)
        // 单独标 LEAK 规则记录暴露程度,不阻塞 ship
        val screenshotLeakFields = listOf(
            "dumpsys_surfaceflinger_display",
            "runtime_exec_screencap_size",
        )
        for (leakField in screenshotLeakFields) {
            val leakValue = map[leakField]?.canonicalValue
            val wmRes = map["resolution"]?.canonicalValue
            if (!leakValue.isNullOrBlank() && !wmRes.isNullOrBlank() &&
                !leakValue.contains("n/a", ignoreCase = true) &&
                !leakValue.startsWith("cmd:", ignoreCase = true) &&
                !leakValue.contains("permission denied", ignoreCase = true) &&
                !leakValue.contains("permission denial", ignoreCase = true) &&
                !leakValue.contains("can't dump", ignoreCase = true) &&
                !leakValue.contains("can't find service", ignoreCase = true)) {
                // 提取数字看是否包含 resolution 的两个值
                val resNums = Regex("\\d+").findAll(wmRes).map { it.value }.toList()
                val leakNums = Regex("\\d+").findAll(leakValue).map { it.value }.toList()
                if (resNums.size >= 2 && leakNums.size >= 2) {
                    val resSet = resNums.toSet()
                    val leakSet = leakNums.toSet()
                    val overlap = resSet.intersect(leakSet)
                    if (overlap.size < 2) {
                        violations += CrossFieldViolation(
                            ruleName = "SCREENSHOT_REAL_PHYSICAL_LEAK_${leakField}",
                            severity = "medium",  // 已知 ghost 盲区,不是新发现
                            fields = listOf(leakField, "resolution"),
                            values = mapOf(leakField to leakValue, "resolution" to wmRes),
                            expected = "$leakField 跟 ghost wm size resolution 不一致 = 真物理 panel 泄漏点",
                            note = "ghost SF binder / shell 截图未 hook,风控如调此路径会看到真物理(此为已知盲区)"
                        )
                    }
                }
            }
        }

        // === Build 类同源 ===
        violations += checkAllEqualWithin(map, listOf("MANUFACTURER", "BRAND"),
            "BUILD_BRAND_VS_MANUFACTURER", tolerance = 0,
            allowDifferentValues = true,
            note = "manufacturer 跟 brand 通常不同(子品牌)但都需有值")

        // === fingerprint 拆解一致 ===
        // Build.FINGERPRINT = "BRAND/PRODUCT/DEVICE:RELEASE/ID/INCREMENTAL:TYPE/TAGS"
        val fp = map["FINGERPRINT"]?.canonicalValue
        if (!fp.isNullOrBlank()) {
            val parts = fp.split('/', ':').filter { it.isNotBlank() }
            // 解析顺序:[0]=brand, [1]=product, [2]=device, [3]=release, [4]=id, [5]=incremental, [6]=type, [7]=tags
            val fpMap = mapOf(
                "BRAND" to parts.getOrNull(0),
                "PRODUCT" to parts.getOrNull(1),
                "DEVICE" to parts.getOrNull(2),
                "RELEASE" to parts.getOrNull(3),
                "ID" to parts.getOrNull(4),
            )
            for ((fieldName, fpVal) in fpMap) {
                val actual = map[fieldName]?.canonicalValue
                if (!fpVal.isNullOrBlank() && !actual.isNullOrBlank() && fpVal != actual) {
                    violations += CrossFieldViolation(
                        ruleName = "FINGERPRINT_VS_$fieldName",
                        severity = "high",
                        fields = listOf("FINGERPRINT", fieldName),
                        values = mapOf("FINGERPRINT.$fieldName" to fpVal, fieldName to actual),
                        expected = "Build.FINGERPRINT 拆解后 $fieldName 段应等于 Build.$fieldName",
                        note = "fingerprint=$fp"
                    )
                }
            }
        }

        // === SoC 同源 ===
        violations += checkAllEqualString(map, listOf("SOC_MODEL"), listOf("ro.soc.model"),
            "SOC_MODEL_JAVA_VS_NATIVE", note = "Build.SOC_MODEL vs ro.soc.model")
        violations += checkAllEqualString(map, listOf("SOC_MANUFACTURER"), listOf("ro.soc.manufacturer"),
            "SOC_MANU_JAVA_VS_NATIVE", note = "Build.SOC_MANUFACTURER vs ro.soc.manufacturer")
        violations += checkAllEqualString(map, listOf("HARDWARE"),
            listOf("ro.hardware", "ro.boot.hardware"),
            "HARDWARE_JAVA_VS_NATIVE", tolerance = 0,
            note = "Build.HARDWARE vs ro.hardware vs ro.boot.hardware")

        // === SDK ↔ Release 对应 ===
        // SDK 33→13, 34→14, 35→15, 36→16, 32→12, 31→12, 30→11, 29→10
        val sdkToRelease = mapOf(
            29 to "10", 30 to "11", 31 to "12", 32 to "12",
            33 to "13", 34 to "14", 35 to "15", 36 to "16", 37 to "17",
        )
        val sdkInt = map["SDK_INT"]?.canonicalValue?.toIntOrNull()
        val release = map["RELEASE"]?.canonicalValue
        if (sdkInt != null && release != null) {
            val expectedRelease = sdkToRelease[sdkInt]
            if (expectedRelease != null && !release.startsWith(expectedRelease)) {
                violations += CrossFieldViolation(
                    ruleName = "SDK_VS_RELEASE_MISMATCH",
                    severity = "high",
                    fields = listOf("SDK_INT", "RELEASE"),
                    values = mapOf("SDK_INT" to sdkInt.toString(), "RELEASE" to release),
                    expected = "SDK=$sdkInt 对应 Android $expectedRelease",
                    note = "Android 版本映射不一致"
                )
            }
        }

        // === Locale / Timezone 同源 → 已由 field "locale"/"timezone" 内双源(java + persist.sys.*)自动查,
        //     原 LOCALE_JAVA_VS_NATIVE/TIMEZONE_JAVA_VS_NATIVE 引用的是源标签("Locale.getDefault")非 field 名=死规则,删。

        // === SIM Country ISO 同源 → 移至 telephony 组(用真 field 名 networkCountryIso/simCountryIso)===

        // === 物理对角线合理性 ===
        val resV = map["resolution"]?.canonicalValue
        val dpiV = map["dpi_app_resources_java"]?.canonicalValue?.toIntOrNull()
        if (resV != null && dpiV != null && dpiV > 0) {
            val nums = Regex("\\d+").findAll(resV).map { it.value.toInt() }.toList()
            if (nums.size >= 2) {
                val w = nums.max().toDouble(); val h = nums.min().toDouble()
                val diag = Math.sqrt(w*w + h*h) / dpiV
                if (diag !in 4.0..8.5) {
                    violations += CrossFieldViolation(
                        ruleName = "PHYSICAL_DIAGONAL_OUT_OF_RANGE",
                        severity = "high",
                        fields = listOf("resolution", "dpi_app_resources_java"),
                        values = mapOf("resolution" to resV, "dpi" to dpiV.toString(),
                                       "diagonal" to "%.2f\"".format(diag)),
                        expected = "对角线 ∈ [4.0\", 8.5\"](手机范围)",
                        note = "可能 res 或 dpi 错配"
                    )
                }
            }
        }

        // === Keystore/Attestation 值异常(K1/K5;K2/K3/K4 已是双源 field 自动查一致性)===
        map["tee.chain_verified"]?.canonicalValue?.let { cv ->
            if (cv.isNotBlank() && cv != "true") {
                violations += CrossFieldViolation(
                    ruleName = "ATTEST_CHAIN_NOT_VERIFIED", severity = "high",
                    fields = listOf("tee.chain_verified"),
                    values = mapOf("tee.chain_verified" to cv),
                    expected = "attestation cert chain 应逐级 verify(parent.pub)通过(真机 Google root 签)",
                    note = "★伪 leaf 用自签私钥重签→对不上 Google 中间证书公钥=硬件认证最强穿帮"
                )
            }
        }
        map["tee.leaf_validity_hours"]?.canonicalValue?.toLongOrNull()?.let { h ->
            if (h in 0..720) {  // 真机 attestation leaf 有效期数千~数万小时;≤30 天=可疑伪造
                violations += CrossFieldViolation(
                    ruleName = "ATTEST_LEAF_VALIDITY_TOO_SHORT", severity = "high",
                    fields = listOf("tee.leaf_validity_hours"),
                    values = mapOf("tee.leaf_validity_hours" to h.toString()),
                    expected = "attestation leaf 有效期应 ≫ 30 天(真机数年)",
                    note = "伪 leaf 常 notBefore+1h → 有效期跨度过短=硬件认证穿帮"
                )
            }
        }
        // K5:security_level=StrongBox 却无 strongbox feature=自相矛盾
        val attSecLvl = map["tee.attestation_security_level"]?.canonicalValue
        val hasStrongbox = map["has_feature.strongbox_keystore"]?.canonicalValue
        if (attSecLvl?.contains("StrongBox", ignoreCase = true) == true && hasStrongbox == "false") {
            violations += CrossFieldViolation(
                ruleName = "STRONGBOX_LEVEL_VS_FEATURE", severity = "high",
                fields = listOf("tee.attestation_security_level", "has_feature.strongbox_keystore"),
                values = mapOf("attestation_security_level" to attSecLvl, "has_feature.strongbox_keystore" to hasStrongbox),
                expected = "security_level=StrongBox ⇒ hasSystemFeature(strongbox_keystore)=true",
                note = "报 StrongBox 却无 strongbox feature=自相矛盾锚"
            )
        }

        // === Keystore 空加密检测(NoEncryptionCipher:密文==明文)===
        map["crypto.encryption_is_noop"]?.canonicalValue?.let { noop ->
            if (noop == "true") {
                violations += CrossFieldViolation(
                    ruleName = "KEYSTORE_ENCRYPTION_NOOP", severity = "medium",
                    fields = listOf("crypto.encryption_is_noop"),
                    values = mapOf("crypto.encryption_is_noop" to "true"),
                    expected = "AndroidKeyStore AES/GCM 加密应产出 ≠明文 的密文(+16B GCM tag)",
                    note = "ghost NoEncryptionCipher=空加密(密文==明文)→ 加密数据跨设备可移植(✓ 备份/还原/新机不丢 token)," +
                        "但'密文==明文'本身是检测面:检测器可自测 Keystore 加密是否真加密(真密文≠明文且带 GCM tag)"
                )
            }
        }
        // === K10 KAT 补强:固定 IV / 无 GCM tag(独立于 密文==明文,覆盖"密文≠明文但仍非真 GCM"的变体)===
        map["crypto.two_encrypts_differ"]?.canonicalValue?.let {
            if (it == "false") {
                violations += CrossFieldViolation(
                    ruleName = "KEYSTORE_FIXED_IV_OR_NOOP", severity = "medium",
                    fields = listOf("crypto.two_encrypts_differ"),
                    values = mapOf("crypto.two_encrypts_differ" to "false"),
                    expected = "真 AES/GCM 每次随机 IV → 同明文两次密文应不同",
                    note = "同明文两次加密得同密文 = 固定 IV 或空加密(ghost 常量 IV/NoEncryptionCipher)= 密码学穿帮"
                )
            }
        }
        map["crypto.gcm_tag_length_ok"]?.canonicalValue?.let {
            if (it == "false") {
                violations += CrossFieldViolation(
                    ruleName = "KEYSTORE_NO_GCM_TAG", severity = "medium",
                    fields = listOf("crypto.gcm_tag_length_ok"),
                    values = mapOf("crypto.gcm_tag_length_ok" to "false"),
                    expected = "AES/GCM 密文长度 == 明文 + 16(128-bit auth tag)",
                    note = "密文长度==明文(无 16B tag)= 空加密/剥 tag,真 GCM 必带 tag = 穿帮"
                )
            }
        }

        // ======================= 覆盖缺口补充规则(6 组)=======================
        // ============================================================
        // display_gpu 组:分辨率补链 + DisplayInfo physical 泄漏 + GPU 家族/驱动/GLSL 一致性
        // ============================================================

        // GPU 家族分类:从 GL_VENDOR / GL_RENDERER 的 token 判家族
        fun gpuFamilyOf(s: String?): String? {
            if (s.isNullOrBlank()) return null
            val g = s.lowercase()
            return when {
                "adreno" in g || "qualcomm" in g -> "Qualcomm"
                "mali" in g || "immortalis" in g || g.trim() == "arm" || "arm " in g -> "ARM"
                "powervr" in g || "imagination" in g || "img" in g || "dxt" in g -> "Imagination"
                "xclipse" in g || "samsung" in g -> "Samsung"
                else -> null
            }
        }
        // GL_VERSION 前缀分类(各 vendor driver revision 格式独特)
        fun gpuFamilyFromVersion(s: String?): String? {
            if (s.isNullOrBlank()) return null
            val g = s.lowercase()
            return when {
                "v@" in g -> "Qualcomm"
                Regex("v\\d+\\.r\\d+p\\d+").containsMatchIn(g) -> "ARM"
                "build 1." in g -> "Imagination"
                Regex("\\br\\d+\\.\\d+\\.").containsMatchIn(g) -> "Samsung"
                else -> null
            }
        }

        // === (1) RESOLUTION_ALL_EQUAL 扩展:mode/supportedModes/stable/realSize 干净 WxH 并入 ===
        //   注:原 resFields 里若直接放 display_get_mode_physical/display_get_supported_modes,其 "@120.0Hz"
        //   会被 checkAllEqualNormalized 的 \d+ 提取出 0/60/120 → 非分辨率数字被 min<300 静默丢弃(无 violation)。
        //   这里改用 display_gpu.* 的干净 WxH 版本,才真正把这几条 hook 纳入一致性。
        violations += checkAllEqualNormalized(map, listOf(
            "resolution",
            "display_gpu.mode_physical_size",
            "display_gpu.supported_modes_size",
            "display_gpu.stable_display_size",
            "display_gpu.real_size",
        ), "RESOLUTION_ALL_EQUAL",
            note = "Mode.physical / SupportedModes / getStableDisplaySize / getRealSize 均应=wm size spoof;" +
                "任一 hook body 的 runCatching 静默失败会漏真物理屏 → 此处暴露")

        // === (2) DisplayManagerGlobal.getDisplayInfo:logical(spoof) vs physical(真面板) vs resolution ===
        violations += checkAllEqualNormalized(map, listOf(
            "resolution",
            "display_gpu.dmg_logical_size",
            "display_gpu.dmg_physical_size",
        ), "DISPLAY_INFO_GLOBAL_VS_RESOLUTION",
            note = "DisplayManagerGlobal.getDisplayInfo 是 GMS 直读的 hidden API,ghost DisplayHook 未 hook 它。" +
                "wm size 改 logicalWidth/Height(=spoof),但 physical 走 DisplayInfo.getMode() 落真面板 → " +
                "physical≠resolution=ghost 屏幕 spoof 的真物理泄漏点")

        // === (3) GPU_FAMILY_CONSISTENCY:GL_VENDOR ↔ GL_RENDERER ↔ GL_VERSION 家族一致 ===
        run {
            val vFam = gpuFamilyOf(map["GL_VENDOR"]?.canonicalValue)
            val rFam = gpuFamilyOf(map["GL_RENDERER"]?.canonicalValue)
            val verFam = gpuFamilyFromVersion(map["GL_VERSION"]?.canonicalValue)
            val fams = listOfNotNull(vFam, rFam, verFam).toSet()
            if (fams.size > 1) {
                violations += CrossFieldViolation(
                    ruleName = "GPU_FAMILY_CONSISTENCY", severity = "high",
                    fields = listOf("GL_VENDOR", "GL_RENDERER", "GL_VERSION"),
                    values = mapOf(
                        "GL_VENDOR" to map["GL_VENDOR"]?.canonicalValue,
                        "GL_RENDERER" to map["GL_RENDERER"]?.canonicalValue,
                        "GL_VERSION" to map["GL_VERSION"]?.canonicalValue),
                    expected = "GL_VENDOR 家族 ↔ GL_RENDERER token ↔ GL_VERSION driver 前缀应属同一 GPU 家族",
                    note = "家族判定: vendor=$vFam renderer=$rFam version=$verFam;不一致=ghost 只 spoof 了部分 GL 串,其余落真驱动"
                )
            }
        }

        // === (4) GPU_RENDERER_VS_EGL_DRIVER:renderer 家族 vs egl .so / ro.hardware.egl / 已加载 vendor SO ===
        //   egl 驱动文件名 / ro.hardware.egl / dl_iterate_phdr 已加载 SO 是硬件真值(gap 报告:不可 spoof)。
        //   只在出现"外来家族 token"时才报,避免泛型 .so / 空值误报。
        run {
            val rFam = gpuFamilyOf(map["GL_RENDERER"]?.canonicalValue)
            if (rFam != null) {
                val tokenByFamily = mapOf(
                    "Qualcomm" to listOf("adreno", "libgsl"),
                    "ARM" to listOf("mali"),
                    "Imagination" to listOf("powervr", "pvr", "img"),
                    "Samsung" to listOf("xclipse")
                )
                val expect = tokenByFamily[rFam].orEmpty()
                val foreign = tokenByFamily.filterKeys { it != rFam }.values.flatten()
                val eglProp = map["ro.hardware.egl"]?.canonicalValue?.lowercase()
                val eglFiles = map["egl_driver_files"]?.canonicalValue?.lowercase()
                fun soLoaded(n: String) = map["loaded_so.dl_has_$n"]?.canonicalValue == "true"
                val contradictions = mutableListOf<String>()
                if (!eglProp.isNullOrBlank() && foreign.any { it in eglProp } && expect.none { it in eglProp })
                    contradictions += "ro.hardware.egl=$eglProp"
                if (!eglFiles.isNullOrBlank() && foreign.any { it in eglFiles } && expect.none { it in eglFiles })
                    contradictions += "egl_driver_files 含外来 vendor .so"
                if (rFam != "ARM" && (soLoaded("libmali.so") || soLoaded("libGLES_mali.so")))
                    contradictions += "已加载 libmali/libGLES_mali"
                if (rFam != "Qualcomm" && (soLoaded("libGLESv2_adreno.so") || soLoaded("libEGL_adreno.so") || soLoaded("libgsl.so")))
                    contradictions += "已加载 adreno .so"
                if (contradictions.isNotEmpty()) {
                    violations += CrossFieldViolation(
                        ruleName = "GPU_RENDERER_VS_EGL_DRIVER", severity = "high",
                        fields = listOf("GL_RENDERER", "ro.hardware.egl", "egl_driver_files"),
                        values = mapOf(
                            "GL_RENDERER" to map["GL_RENDERER"]?.canonicalValue,
                            "ro.hardware.egl" to map["ro.hardware.egl"]?.canonicalValue,
                            "egl_driver_files" to map["egl_driver_files"]?.canonicalValue),
                        expected = "GL_RENDERER 家族($rFam)应匹配 egl 驱动 .so / ro.hardware.egl / 已加载 vendor SO(硬件真值不可 spoof)",
                        note = "矛盾: ${contradictions.joinToString("; ")} — renderer 冒充 $rFam 但物理 GPU 驱动属其他家族=硬件锚"
                    )
                }
            }
        }

        // === (5) GLSL_VS_GL_VERSION:GLSL ES 纪元(0x8B8C 真驱动) ↔ GL_VERSION 的 ES 版本(ghost spoof)===
        run {
            fun glEs(v: String?): String? {  // "OpenGL ES 3.2 ..." → "3.2"
                if (v.isNullOrBlank()) return null
                val m = Regex("opengl es\\s+(\\d)\\.(\\d)", RegexOption.IGNORE_CASE).find(v) ?: return null
                return "${m.groupValues[1]}.${m.groupValues[2]}"
            }
            fun glslEs(v: String?): String? {  // "OpenGL ES GLSL ES 3.20"→ES3.2 ; "1.00"→ES2.0
                if (v.isNullOrBlank()) return null
                val m = Regex("glsl es\\s+(\\d)\\.(\\d)", RegexOption.IGNORE_CASE).find(v)
                    ?: Regex("(\\d)\\.(\\d)").find(v) ?: return null
                val major = m.groupValues[1]; val minor = m.groupValues[2]
                return if (major == "1") "2.0" else "$major.$minor"
            }
            val glLvl = glEs(map["GL_VERSION"]?.canonicalValue)
            val glslLvl = glslEs(map["display_gpu.gl_shading_language_version"]?.canonicalValue)
            if (glLvl != null && glslLvl != null && glLvl != glslLvl) {
                violations += CrossFieldViolation(
                    ruleName = "GLSL_VS_GL_VERSION", severity = "high",
                    fields = listOf("GL_VERSION", "display_gpu.gl_shading_language_version"),
                    values = mapOf(
                        "GL_VERSION" to map["GL_VERSION"]?.canonicalValue,
                        "display_gpu.gl_shading_language_version" to map["display_gpu.gl_shading_language_version"]?.canonicalValue),
                    expected = "GLSL ES 纪元应=GL_VERSION 的 ES 版本(ES3.2⇒GLSL3.20 / 3.1⇒3.10 / 3.0⇒3.00 / 2.0⇒1.00)",
                    note = "ghost 恒报 GL_VERSION=OpenGL ES 3.2 却未 hook 0x8B8C(GLSL 落真驱动);真机 ES 版本≠3.2 时矛盾=锚。" +
                        "发现 GL_VERSION→ES$glLvl vs GLSL→ES$glslLvl"
                )
            }
        }

        // ============================================================
        // hw 组:CPU/SoC/厂商 一致性(farm 硬件真身泄漏)
        // ============================================================
        // (A) MANUFACTURER ↔ BRAND 同 OEM:SHARP 厂商配 motorola 品牌 = 设备档案错值/字段混搭
        run {
            val mfg = oemGroup(map["MANUFACTURER"]?.canonicalValue)
            val brand = oemGroup(map["BRAND"]?.canonicalValue)
            if (mfg != null && brand != null && mfg != brand) {
                violations += CrossFieldViolation(
                    ruleName = "MANUFACTURER_VS_BRAND", severity = "high",
                    fields = listOf("MANUFACTURER", "BRAND", "MODEL"),
                    values = mapOf(
                        "MANUFACTURER" to map["MANUFACTURER"]?.canonicalValue,
                        "BRAND" to map["BRAND"]?.canonicalValue,
                        "MODEL" to map["MODEL"]?.canonicalValue),
                    expected = "Build.MANUFACTURER 与 BRAND 应属同一 OEM 组",
                    note = "厂商组=$mfg 品牌组=$brand 矛盾:真机不可能(如 SHARP 厂商+motorola 品牌)=设备档案错值/字段混搭"
                )
            }
        }
        // (B) ro.board.platform 厂商 ↔ SOC_MODEL 厂商:gs101(Tensor)配 SM7550(高通)=SoC 真身泄漏
        run {
            val platVendor = socVendorFromPlatform(map["ro.board.platform"]?.canonicalValue)
            val socVendor = socVendorFromModel(map["SOC_MODEL"]?.canonicalValue)
            if (platVendor != null && socVendor != null && platVendor != socVendor) {
                violations += CrossFieldViolation(
                    ruleName = "SOC_PLATFORM_VENDOR_MISMATCH", severity = "high",
                    fields = listOf("ro.board.platform", "SOC_MODEL"),
                    values = mapOf(
                        "ro.board.platform" to map["ro.board.platform"]?.canonicalValue,
                        "SOC_MODEL" to map["SOC_MODEL"]?.canonicalValue),
                    expected = "ro.board.platform 平台厂商应与 SOC_MODEL 厂商一致",
                    note = "平台厂商=$platVendor SoC厂商=$socVendor 矛盾:ghost 未 spoof ro.board.platform,真 SoC 泄漏"
                )
            }
        }
        // (C) /proc/cpuinfo CPU 微架构 ↔ SOC_MODEL:含旗舰 prime 核但 SoC 为中端 = 真旗舰 CPU 泄漏
        run {
            val parts = (map["cpuinfo.CPUParts"]?.canonicalValue ?: "")
                .split(",").map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
            // 仅 Cortex-X 系(旗舰独占超大核):X1/X2/X3/X4/X925。★剔除 A76(0xd0b)/A710(0xd47)——它们是大量中端 SoC
            //   的主力大核(骁龙7Gen1=A710、骁龙730=A76、天玑700/810=A76),含它们会把合法中端真机误判 farm(误报危害>漏报)。
            val flagshipPrime = setOf("0xd44", "0xd48", "0xd4e", "0xd82", "0xd85") // X1,X2,X3,X4,X925
            val prime = parts.filter { it in flagshipPrime }
            if (prime.isNotEmpty() && socTierFromModel(map["SOC_MODEL"]?.canonicalValue) == "mid") {
                violations += CrossFieldViolation(
                    ruleName = "CPU_ARCH_VS_SOC_TIER", severity = "high",
                    fields = listOf("cpuinfo.CPUParts", "SOC_MODEL", "MODEL"),
                    values = mapOf(
                        "cpuinfo.CPUParts" to map["cpuinfo.CPUParts"]?.canonicalValue,
                        "SOC_MODEL" to map["SOC_MODEL"]?.canonicalValue,
                        "MODEL" to map["MODEL"]?.canonicalValue),
                    expected = "cpuinfo 旗舰 prime 核(X1/X2/X3/X4/A76)不应出现在中端 SoC 型号下",
                    note = "cpuinfo 含旗舰核 $prime 但 SOC_MODEL=${map["SOC_MODEL"]?.canonicalValue}(中端)=真旗舰 CPU 冒充中端型号=farm(如真 Tensor 冒充 SM7550)"
                )
            }
        }
        // ============================================================
        // network 组:NetworkInterface 真洞 + Wifi/DHCP IP 链 + hasTransport
        // ============================================================
        // 从字段值里抽第一个非 0.0.0.0 的 IPv4;抽不到(<none>/<null>/<denied>)返 null 不参与比对
        fun ipv4Of(name: String): String? {
            val v = map[name]?.canonicalValue ?: return null
            if (v.contains("denied", ignoreCase = true) || v.contains("null", ignoreCase = true)) return null
            val m = Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""").find(v)?.value ?: return null
            return if (m == "0.0.0.0") null else m
        }
        // (1) IP 链:wlan/rmnet iface IP == WifiInfo.ipAddress == DhcpInfo.ipAddress(都应 = cellIp)
        run {
            val ipFields = listOf("network.iface_data_ipv4", "wifi.info_ipaddress", "wifi.dhcp_ipaddress")
            val present = ipFields.mapNotNull { f -> ipv4Of(f)?.let { f to it } }
            if (present.size >= 2 && present.map { it.second }.toSet().size > 1) {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_IP_CHAIN_MISMATCH", severity = "high",
                    fields = ipFields,
                    values = ipFields.associateWith { map[it]?.canonicalValue },
                    expected = "wlan/rmnet iface IP == WifiInfo.ipAddress == DhcpInfo.ipAddress(= cellIp)",
                    note = "三处 IP 不一致 = NetworkInterface/Wifi/DHCP 某一路 hook 没对齐 → IP 泄漏/穿帮"
                )
            }
        }
        // (2) tun0/ppp 存在 = VPN 泄漏(绕过 NOT_VPN + transport 双 spoof)
        map["network.iface_vpn_present"]?.canonicalValue?.let { v ->
            if (v.startsWith("true")) {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_VPN_INTERFACE_LEAK", severity = "high",
                    fields = listOf("network.iface_vpn_present", "network.vpn_active", "network.transport_vpn"),
                    values = mapOf(
                        "network.iface_vpn_present" to v,
                        "network.vpn_active" to map["network.vpn_active"]?.canonicalValue,
                        "network.transport_vpn" to map["network.transport_vpn"]?.canonicalValue,
                    ),
                    expected = "无 tun*/ppp*/ipsec*/wg* 网卡(NetworkInterfaceHook 应删隧道网卡)",
                    note = "getNetworkInterfaces() 暴露隧道网卡 = VPN 泄漏,绕过 Connectivity NOT_VPN/transport spoof"
                )
            }
        }
        // (3) getHardwareAddress 泄漏真 MAC(hook 不改 hwaddr)
        map["network.iface_hwaddr_leak"]?.canonicalValue?.let { v ->
            if (v.startsWith("true")) {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_REAL_MAC_LEAK", severity = "high",
                    fields = listOf("network.iface_hwaddr_leak"),
                    values = mapOf("network.iface_hwaddr_leak" to v),
                    expected = "非 lo 网卡 getHardwareAddress 应为 null 或 02:00:00:00:00:00(已 redact)",
                    note = "NetworkInterface.getHardwareAddress 返回真 MAC = 硬件网卡指纹泄漏(hook 只改 addrs 不改 hwaddr)"
                )
            }
        }
        // (4) 意外多物理数据网卡(hook 后应恰好 1:wlan 或 rmnet)
        map["network.iface_data_count"]?.canonicalValue?.toIntOrNull()?.let { c ->
            if (c > 1) {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_MULTI_NIC_LEAK", severity = "medium",
                    fields = listOf("network.iface_data_count", "network.iface_names"),
                    values = mapOf(
                        "network.iface_data_count" to c.toString(),
                        "network.iface_names" to map["network.iface_names"]?.canonicalValue,
                    ),
                    expected = "带 IPv4 的非虚拟数据网卡应 == 1(NetworkInterfaceHook 只保留 wlan 或 rmnet)",
                    note = "多张物理数据网卡同时带 IP = hook 未收敛/泄漏(真机同一时刻通常只走一张)"
                )
            }
        }
        // (5) hasTransport(VPN)==true = 第二 VPN 信号(独立于 NOT_VPN capability)
        map["network.transport_vpn"]?.canonicalValue?.let { v ->
            if (v == "true") {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_TRANSPORT_VPN_ACTIVE", severity = "high",
                    fields = listOf("network.transport_vpn", "network.vpn_active"),
                    values = mapOf(
                        "network.transport_vpn" to v,
                        "network.vpn_active" to map["network.vpn_active"]?.canonicalValue,
                    ),
                    expected = "activeNetwork 不应带 TRANSPORT_VPN(ghost 应伪装成 wifi/cell)",
                    note = "hasTransport(TRANSPORT_VPN)=true = VPN 网络直接暴露(独立于 NOT_VPN capability 检测)"
                )
            }
        }
        // (0) NetworkInterface 缺 loopback = 物理不可能 —— 但只在**枚举成功**时才判。
        //     ★Android 11+ 对 untrusted_app 限制 getifaddrs/netlink(隐私,防 MAC/网卡指纹)→
        //     getNetworkInterfaces() 抛 "getifaddrs failed: EACCES" = 真机任何 app 的正常行为,不是 ghost 穿帮。
        //     故只有 iface_error=="ok"(枚举真拿到网卡)却缺 lo 时,才是 NetworkInterfaceHook 过滤过度的真穿帮。
        run {
            val err = map["network.iface_error"]?.canonicalValue
            if (err == "ok") {
                val names = map["network.iface_names"]?.canonicalValue ?: ""
                val list = names.lowercase().split(",").map { it.trim() }
                    .filter { it.isNotEmpty() && it != "<none>" }
                if (list.isEmpty() || "lo" !in list) {
                    violations += CrossFieldViolation(
                        ruleName = "NETWORK_NO_LOOPBACK", severity = "high",
                        fields = listOf("network.iface_names", "network.iface_error"),
                        values = mapOf("network.iface_names" to names, "network.iface_error" to err),
                        expected = "枚举成功时 getNetworkInterfaces() 必含 loopback(lo)",
                        note = "枚举成功却缺 lo = NetworkInterfaceHook 过滤过度(真机恒含 lo);" +
                            "注:枚举被 EACCES 拦时不报此条(Android 11+ untrusted_app 正常限制,非穿帮)"
                    )
                }
            }
        }

        // (6) transport story 一致性:WIFI/CELLULAR 互斥且与 iface 名对齐
        run {
            val tw = map["network.transport_wifi"]?.canonicalValue
            val tc = map["network.transport_cellular"]?.canonicalValue
            val names = map["network.iface_names"]?.canonicalValue?.lowercase() ?: ""
            // 网卡列表本身为空/<none> 时,根因是 NETWORK_NO_LOOPBACK,不在此重复报"无 wlan 网卡"(措辞误导)
            val hasIfaceList = names.isNotBlank() && names != "<none>" && !names.contains("<none>")
            if (tw == "true" && tc == "true") {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_TRANSPORT_STORY", severity = "medium",
                    fields = listOf("network.transport_wifi", "network.transport_cellular"),
                    values = mapOf("network.transport_wifi" to tw, "network.transport_cellular" to tc),
                    expected = "activeNetwork 的 WIFI/CELLULAR 传输应互斥(恰好一个 true)",
                    note = "同时 WIFI+CELLULAR = transport 伪装不自洽"
                )
            } else if (tw == "true" && hasIfaceList && !names.contains("wlan")) {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_TRANSPORT_STORY", severity = "medium",
                    fields = listOf("network.transport_wifi", "network.iface_names"),
                    values = mapOf("network.transport_wifi" to tw, "network.iface_names" to map["network.iface_names"]?.canonicalValue),
                    expected = "transport=WIFI ⇒ 应存在 wlan* 网卡",
                    note = "声称走 WiFi 但无 wlan 网卡 = Connectivity transport spoof 与 NetworkInterface 不自洽"
                )
            } else if (tc == "true" && hasIfaceList && !names.contains("rmnet") && !names.contains("ccmni")) {
                violations += CrossFieldViolation(
                    ruleName = "NETWORK_TRANSPORT_STORY", severity = "medium",
                    fields = listOf("network.transport_cellular", "network.iface_names"),
                    values = mapOf("network.transport_cellular" to tc, "network.iface_names" to map["network.iface_names"]?.canonicalValue),
                    expected = "transport=CELLULAR ⇒ 应存在 rmnet*/ccmni* 网卡",
                    note = "声称走蜂窝但无 rmnet 网卡 = transport spoof 与 NetworkInterface 不自洽"
                )
            }
        }

        // === Telephony: SIM 国家 ISO 跨字段(修复原 SIM_COUNTRY_ISO_CROSS 死规则)===
        // 原规则查 "TelephonyManager.getSimCountryIso"/"gsm.operator.iso-country" —— 那是 field
        // *源标签*,不是 field 名,map 永不命中。改用真 field 名 networkCountryIso vs simCountryIso。
        // (各自 field 内已自动做 java-vs-native gsm.operator.iso-country 一致性。)
        violations += checkAllEqualString(map,
            listOf("networkCountryIso"),
            listOf("simCountryIso"),
            "SIM_COUNTRY_ISO_CROSS", tolerance = 0,
            note = "getNetworkCountryIso 应 == getSimCountryIso(同一 2-letter ISO);ghost 把两者都伪造成 props.simCountryIso",
            caseInsensitive = true)

        // === Telephony: SIM 就绪 ⇒ 必有运营商(ghost 伪造 SIM_STATE_READY / hasIccCard=true)===
        val simStateV = map["simState"]?.canonicalValue
        val simOperatorV = map["simOperator"]?.canonicalValue
        if (simStateV == "READY" && simOperatorV.isNullOrBlank()) {
            violations += CrossFieldViolation(
                ruleName = "SIM_READY_IMPLIES_OPERATOR", severity = "high",
                fields = listOf("simState", "simOperator"),
                values = mapOf("simState" to simStateV, "simOperator" to simOperatorV),
                expected = "simState==READY ⇒ simOperator(MCCMNC)非空",
                note = "SIM 就绪必有归属运营商;伪造 READY 却漏配 operator=矛盾"
            )
        }
        if (simStateV == "ABSENT" && !simOperatorV.isNullOrBlank()) {
            violations += CrossFieldViolation(
                ruleName = "SIM_ABSENT_BUT_OPERATOR", severity = "high",
                fields = listOf("simState", "simOperator"),
                values = mapOf("simState" to simStateV, "simOperator" to simOperatorV),
                expected = "simState==ABSENT ⇒ simOperator 应为空",
                note = "无 SIM 却有运营商 MCCMNC=矛盾"
            )
        }

        // === Telephony: hasIccCard 与 simState 自洽(ghost 两处独立伪造,须一致)===
        val hasIccV = map["hasIccCard"]?.canonicalValue
        if (hasIccV == "false" && simStateV == "READY") {
            violations += CrossFieldViolation(
                ruleName = "ICC_ABSENT_BUT_SIM_READY", severity = "high",
                fields = listOf("hasIccCard", "simState"),
                values = mapOf("hasIccCard" to hasIccV, "simState" to simStateV),
                expected = "simState==READY ⇒ hasIccCard==true",
                note = "SIM 就绪必有卡;hasIccCard=false 却 READY=两伪造路径不自洽"
            )
        }
        if (hasIccV == "true" && simStateV == "ABSENT") {
            violations += CrossFieldViolation(
                ruleName = "ICC_PRESENT_BUT_SIM_ABSENT", severity = "high",
                fields = listOf("hasIccCard", "simState"),
                values = mapOf("hasIccCard" to hasIccV, "simState" to simStateV),
                expected = "simState==ABSENT ⇒ hasIccCard==false",
                note = "有卡却报 ABSENT=两伪造路径不自洽"
            )
        }

        // === Sensor 元组自洽(group "sensor")===
        // ghost SensorManagerHook 只改 name/vendor/maxRange/resolution,
        // maxRange/resolution 用 Random.float(maxValue,dp) 均匀随机 → 常越出真机物理范围;
        // 真机走此路径全部静默(标准量程 + 极细分辨率 + 真词组 name)。
        run {
            fun parseF(name: String): Float? = map[name]?.canonicalValue?.toFloatOrNull()

            // (1) name 乱码(stringUpper QFRJU 类):裸大写字母块 4-10 长。
            //     扫描所有 sensor.*.name field(含本组新增 + 已有 linear_accel/rotation_vector)
            //     + 全量扫描字段 sensor.name_garbage_scan。
            val garbageRe = Regex("^[A-Z]{4,10}$")
            val garbageHits = mutableListOf<String>()
            for (f in fields) {
                if (f.name.startsWith("sensor.") && f.name.endsWith(".name")) {
                    val v = f.canonicalValue?.trim()
                    if (!v.isNullOrEmpty() && garbageRe.matches(v)) garbageHits += "${f.name}=$v"
                }
            }
            map["sensor.name_garbage_scan"]?.canonicalValue
                ?.takeIf { it.startsWith("SUSPICIOUS") }?.let { garbageHits += "scan:$it" }
            if (garbageHits.isNotEmpty()) {
                violations += CrossFieldViolation(
                    ruleName = "SENSOR_NAME_GARBAGE", severity = "high",
                    fields = listOf("sensor.name_garbage_scan"),
                    values = mapOf("garbage" to garbageHits.joinToString("; ")),
                    expected = "sensor name 应为真机型号/词组(带空格或数字),非裸大写字母乱码",
                    note = "ghost stringUpper(5) 生成 QFRJU 类乱码 name;裸大写字母块=硬穿帮"
                )
            }

            // 标准加速度计满量程(m/s²):2/4/8/16/32 g
            val accelG = listOf(19.61f, 39.23f, 78.45f, 156.91f, 313.81f)

            for (label in listOf("accelerometer", "gyroscope", "magnetic")) {
                val maxR = parseF("sensor.$label.maxRange")
                val res  = parseF("sensor.$label.resolution")

                // (2) resolution >= maxRange = 物理不可能(分辨率是最小可分刻度)
                if (maxR != null && res != null && res > 0f && maxR > 0f && res >= maxR) {
                    violations += CrossFieldViolation(
                        ruleName = "SENSOR_RESOLUTION_EXCEEDS_RANGE", severity = "high",
                        fields = listOf("sensor.$label.maxRange", "sensor.$label.resolution"),
                        values = mapOf("sensor.$label.maxRange" to maxR.toString(),
                                       "sensor.$label.resolution" to res.toString()),
                        expected = "resolution << maxRange(分辨率是最小刻度,必远小于满量程)",
                        note = "ghost maxRange/resolution 独立随机 → 可倒挂;倒挂=物理不可能"
                    )
                }

                // (3) resolution 过粗:ratio > 0.02(满量程 < 50 级)对现代 MEMS(≥12bit,数千级量化)不可能
                if (maxR != null && res != null && res > 0f && maxR > 0f && res / maxR > 0.02f) {
                    violations += CrossFieldViolation(
                        ruleName = "SENSOR_RESOLUTION_TOO_COARSE", severity = "medium",
                        fields = listOf("sensor.$label.maxRange", "sensor.$label.resolution"),
                        values = mapOf("sensor.$label.maxRange" to maxR.toString(),
                                       "sensor.$label.resolution" to res.toString(),
                                       "res/range" to (res / maxR).toString()),
                        expected = "resolution/maxRange 应 ≪ 0.02(12bit MEMS → 数千级量化,真机约 1e-5)",
                        note = "ghost float(1f,11) 生成 [0,1) 随机 resolution → 常过粗"
                    )
                }
            }

            // (4) 加速度计满量程应贴近标准 g 倍数(±8%)
            val accelMax = parseF("sensor.accelerometer.maxRange")
            if (accelMax != null && accelMax > 0f) {
                val near = accelG.any { kotlin.math.abs(accelMax - it) / it <= 0.08f }
                if (!near) {
                    violations += CrossFieldViolation(
                        ruleName = "SENSOR_ACCEL_RANGE_NONSTANDARD", severity = "medium",
                        fields = listOf("sensor.accelerometer.maxRange", "sensor.accelerometer.name"),
                        values = mapOf("sensor.accelerometer.maxRange" to accelMax.toString(),
                                       "sensor.accelerometer.name" to map["sensor.accelerometer.name"]?.canonicalValue),
                        expected = "加速度计满量程应贴近 2/4/8/16/32g = 19.6/39.2/78.5/156.9/313.8 m/s²(±8%)",
                        note = "ghost float(200f,4) 生成 [0,200) 均匀随机 → 极少落在标准 g 倍数上"
                    )
                }
            }

            // (5) 全量 resolution>=maxRange 扫描命中(覆盖未单列传感器)
            map["sensor.range_resolution_scan"]?.canonicalValue
                ?.takeIf { it.startsWith("IMPOSSIBLE") }?.let { s ->
                    violations += CrossFieldViolation(
                        ruleName = "SENSOR_RANGE_RESOLUTION_INVERTED_ANY", severity = "high",
                        fields = listOf("sensor.range_resolution_scan"),
                        values = mapOf("sensor.range_resolution_scan" to s),
                        expected = "任何传感器都不应 resolution>=maxRange",
                        note = "全量扫描发现倒挂传感器(ghost 独立随机两字段)"
                    )
                }
        }

        // === Install source / installer 链一致性(installsource 组)===
        //   installer_chain 多源 field 已自动查 getInstallerPackageName / installing /
        //   initiating 三读路径一致;initiating_signing_sha256 多源 field 已自动查
        //   伪造 initiating 签名 == 真 vending 签名。以下补自动一致性覆盖不到的语义规则。
        run {
            val VENDING = "com.android.vending"
            val chain = map["installsource.installer_chain"]?.canonicalValue
            val vendingInstalled = map["installsource.vending_installed"]?.canonicalValue
            val signingPresent = map["installsource.initiating_signing_present"]?.canonicalValue
            val updateOwner = map["installsource.update_owner"]?.canonicalValue

            // 规则1:installer 链读到非空且 != vending → 真实安装来源泄漏(ghost 未把该读路径改成 Play)。
            if (!chain.isNullOrBlank() && chain != VENDING) {
                violations += CrossFieldViolation(
                    ruleName = "INSTALLER_NOT_VENDING",
                    severity = "high",
                    fields = listOf("installsource.installer_chain"),
                    values = mapOf("installsource.installer_chain" to chain),
                    expected = "farm app 安装来源应 = $VENDING(Play)",
                    note = "installer 链读到非 Play 值 = 真实安装来源泄漏 / ghost 未覆盖到该读路径"
                )
            }

            // 规则2:声称由 Play 安装,但 com.android.vending 根本不在机上 → 逻辑上不可能(anchor)。
            if (chain == VENDING && vendingInstalled != null && vendingInstalled.startsWith("false")) {
                violations += CrossFieldViolation(
                    ruleName = "INSTALLER_VENDING_ABSENT",
                    severity = "high",
                    fields = listOf("installsource.installer_chain", "installsource.vending_installed"),
                    values = mapOf(
                        "installsource.installer_chain" to chain,
                        "installsource.vending_installed" to vendingInstalled),
                    expected = "installer==Play ⇒ com.android.vending 必须已安装",
                    note = "声称 Play 安装但设备无 Play = 不可能 = 伪造锚点"
                )
            }

            // 规则3:声称 Play 装,但 initiatingPackageSigningInfo 缺失 → 真 Play 安装恒带 initiating 签名。
            //   ghost 若 getVendingSigningInfo() 失败(vending 未装/加载晚)仍返包名 = 有名无签 = 穿帮。
            if (chain == VENDING && signingPresent == "false") {
                violations += CrossFieldViolation(
                    ruleName = "INSTALLSOURCE_SIGNING_MISSING",
                    severity = "high",
                    fields = listOf("installsource.installer_chain", "installsource.initiating_signing_present"),
                    values = mapOf(
                        "installsource.installer_chain" to chain,
                        "installsource.initiating_signing_present" to signingPresent),
                    expected = "installer==Play ⇒ InstallSourceInfo.getInitiatingPackageSigningInfo() 非空",
                    note = "真 Play 安装恒带 initiating 签名;缺失 = ghost 只改包名没塞签名 = 穿帮"
                )
            }

            // 规则4:updateOwner(API34,ghost 未 hook)读到非空、非 Play、非哨兵 → 泄漏真实更新者。
            if (!updateOwner.isNullOrBlank() && updateOwner != VENDING && !updateOwner.startsWith("<")) {
                violations += CrossFieldViolation(
                    ruleName = "UPDATE_OWNER_NOT_VENDING",
                    severity = "medium",
                    fields = listOf("installsource.update_owner", "installsource.installer_chain"),
                    values = mapOf(
                        "installsource.update_owner" to updateOwner,
                        "installsource.installer_chain" to chain),
                    expected = "updateOwnerPackageName 应为 Play 或 null(ghost 当前未 spoof 此 API)",
                    note = "getUpdateOwnerPackageName(API34) 未被 ghost hook → 非-Play 更新会泄漏真实更新者"
                )
            }
        }

        // === Accessibility: client AM 报 0 个 enabled service 但 Settings.Secure ENABLED_ACCESSIBILITY_SERVICES 非空 = 两 hook 路径不同步 ===
        // ghost AccessibilityManagerHook 把 getEnabledAccessibilityServiceList spoof 成 empty(client AM 层),
        // SettingsProviderHook 另把 enabled_accessibility_services 抹成 null(provider 层)。二者若不同步
        // (SettingsProvider uid 未命中 / query 路径绕过 / 仅其一生效)→ count==0 但 settings 仍列 service = 穿帮。
        // (isEnabled=false-but-Settings=1 那半已由 4 源 accessibility_is_enabled field 自动交叉覆盖。)
        run {
            val enabledCount = map["accessibility_enabled_services_count"]?.sources
                ?.firstOrNull { it.source.contains("getEnabledAccessibilityServiceList") }?.value
            val settingsServices = map["accessibility.enabled_services"]?.canonicalValue
            if (enabledCount == "0" && !settingsServices.isNullOrBlank() &&
                !settingsServices.contains("n/a", ignoreCase = true) &&
                !settingsServices.startsWith("<error>")
            ) {
                violations += CrossFieldViolation(
                    ruleName = "ACCESSIBILITY_COUNT_VS_SETTINGS_LEAK",
                    severity = "high",
                    fields = listOf("accessibility_enabled_services_count", "accessibility.enabled_services"),
                    values = mapOf(
                        "accessibility_enabled_services_count(enabled)" to "0",
                        "accessibility.enabled_services" to settingsServices
                    ),
                    expected = "client AM 报 0 个 enabled a11y service ⇒ Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES 应为空",
                    note = "AccessibilityManager hook spoof getEnabledAccessibilityServiceList→empty,但 SettingsProvider 路径漏抹→settings 仍列 service=两 hook 不同步穿帮"
                )
            }
        }

        // === 绕-hook 真洞交叉(hook-bypass-leaks 组)===
        // (uptime padding 在 app 层不可检测:/proc/uptime 对 untrusted_app SELinux 拒绝,detector 同样读不到;
        //  唯一旁路 native clock_gettime(CLOCK_BOOTTIME) 需扩 NativeBridge,未做——故无 uptime 规则。)
        // (1) 内存:Runtime.maxMemory()/MB 按 Android 定义 == getMemoryClass();差 >32MB = ghost spoof heap 桶却没 hook getMemoryClass。
        run {
            val mx = map["runtime.max_memory_mb"]?.canonicalValue?.toIntOrNull()
            val mc = map["runtime.memory_class_mb"]?.canonicalValue?.toIntOrNull()
            if (mx != null && mc != null && mc > 0 && kotlin.math.abs(mx - mc) > 32) {
                violations += CrossFieldViolation(
                    ruleName = "RUNTIME_MAXMEM_VS_MEMCLASS", severity = "high",
                    fields = listOf("runtime.max_memory_mb", "runtime.memory_class_mb"),
                    values = mapOf("runtime.max_memory_mb" to mx.toString(), "runtime.memory_class_mb" to mc.toString()),
                    expected = "Runtime.maxMemory()/MB ≈ ActivityManager.getMemoryClass()(Android 定义等价)",
                    note = "maxMemory=${mx}MB vs memoryClass=${mc}MB 差 ${kotlin.math.abs(mx-mc)}MB = ghost spoof 了 Runtime heap 桶但没 hook getMemoryClass=anchor"
                )
            }
        }
        // (3) 音频:mute=false 却 volume=0 自相矛盾;volume>max 不可能。
        run {
            val vol = map["audio.volume_music"]?.canonicalValue?.toIntOrNull()
            val maxVol = map["audio.max_volume_music"]?.canonicalValue?.toIntOrNull()
            val mute = map["audio.mute_music"]?.canonicalValue
            if (vol != null && mute == "false" && vol == 0) {
                violations += CrossFieldViolation(
                    ruleName = "AUDIO_MUTE_VS_VOLUME", severity = "medium",
                    fields = listOf("audio.mute_music", "audio.volume_music"),
                    values = mapOf("audio.mute_music" to "false", "audio.volume_music" to "0"),
                    expected = "非静音(isStreamMute=false)时 STREAM_MUSIC volume 不应为 0",
                    note = "ghost AudioServiceHook 伪造 volume 却恒 isStreamMute=false → mute=false+volume=0=矛盾锚"
                )
            }
            if (vol != null && maxVol != null && maxVol > 0 && vol > maxVol) {
                violations += CrossFieldViolation(
                    ruleName = "AUDIO_VOLUME_EXCEEDS_MAX", severity = "medium",
                    fields = listOf("audio.volume_music", "audio.max_volume_music"),
                    values = mapOf("audio.volume_music" to vol.toString(), "audio.max_volume_music" to maxVol.toString()),
                    expected = "getStreamVolume ≤ getStreamMaxVolume",
                    note = "volume>max(max 是未 hook 真值)= ghost 伪造 volume 越界=anchor"
                )
            }
        }

        // === Bluetooth 名跨 binder(bt-webview-drm 组)===
        // ghost 经 SettingsProvider spoof device_name;BluetoothAdapter.getName() 走独立 binder 可能泄漏真名。
        run {
            val adapter = map["bt.adapter_name"]?.canonicalValue
            val settingsName = map["bt.settings_device_name"]?.canonicalValue
            if (!adapter.isNullOrBlank() && !adapter.startsWith("<") &&
                !settingsName.isNullOrBlank() && adapter != settingsName) {
                violations += CrossFieldViolation(
                    ruleName = "BLUETOOTH_NAME_VS_SETTINGS", severity = "high",
                    fields = listOf("bt.adapter_name", "bt.settings_device_name"),
                    values = mapOf("bt.adapter_name" to adapter, "bt.settings_device_name" to settingsName),
                    expected = "BluetoothAdapter.getName() 应 == Settings device_name(同一设备名)",
                    note = "BluetoothAdapter.getName()(独立 IBluetooth binder)≠ SettingsProvider spoof 的 device_name = 真蓝牙名泄漏(ghost 没覆盖 binder 路径)"
                )
            }
        }
        // === WebView provider 声称已装(bt-webview-drm 组)===
        map["webview.provider_installed"]?.canonicalValue?.let { inst ->
            if (inst.startsWith("NOT_INSTALLED")) {
                violations += CrossFieldViolation(
                    ruleName = "WEBVIEW_PROVIDER_NOT_INSTALLED", severity = "high",
                    fields = listOf("webview.current_package", "webview.provider_installed"),
                    values = mapOf("webview.current_package" to map["webview.current_package"]?.canonicalValue,
                                   "webview.provider_installed" to inst),
                    expected = "getCurrentWebViewPackage() 声称的 provider 必须真实已安装",
                    note = "ghost 把 WebView provider spoof 成 com.brave.browser 但该包未真装 → getPackageInfo 查不到=硬穿帮(声称的渲染引擎不存在)"
                )
            }
        }
        // === 电池 energy/charge 比(coverage-extra 组)===
        // 真机 energy(nWh)≈charge(µAh)×标称电压(V)×1000 → ratio≈3000-4400;
        // ghost FakeBatteryManager 用 energy=maxCap×(100-cap) 反相关公式 → ratio≪1 = 异常。
        run {
            val charge = map["battery.charge_counter_uah"]?.canonicalValue?.toLongOrNull()
            val energy = map["battery.energy_counter_nwh"]?.canonicalValue?.toLongOrNull()
            if (charge != null && charge > 100_000 && energy != null && energy > 0) {
                val ratio = energy.toDouble() / charge.toDouble()
                if (ratio < 2000 || ratio > 6000) {
                    violations += CrossFieldViolation(
                        ruleName = "BATTERY_ENERGY_CHARGE_RATIO", severity = "medium",
                        fields = listOf("battery.energy_counter_nwh", "battery.charge_counter_uah"),
                        values = mapOf("battery.energy_counter_nwh" to energy.toString(),
                                       "battery.charge_counter_uah" to charge.toString(),
                                       "ratio" to "%.1f".format(ratio)),
                        expected = "energy(nWh)/charge(µAh) ≈ 标称电压×1000(≈3000-4400)",
                        note = "ratio=%.1f 偏离标称电压 → ghost FakeBatteryManager energy 用 (100-cap) 反相关公式(真机 energy 应正比于 charge)=anchor".format(ratio)
                    )
                }
            }
        }

        // === K7:Widevine L1(硬件 DRM)vs Software keystore(无 TEE)矛盾 ===
        run {
            val wvLevel = map["Widevine.securityLevel"]?.canonicalValue
            val attLevel = map["tee.attestation_security_level"]?.canonicalValue
            if (wvLevel != null && wvLevel.contains("L1") &&
                attLevel != null && attLevel.contains("Software", ignoreCase = true)) {
                violations += CrossFieldViolation(
                    ruleName = "WIDEVINE_L1_VS_SOFTWARE_KEYSTORE", severity = "high",
                    fields = listOf("Widevine.securityLevel", "tee.attestation_security_level"),
                    values = mapOf("Widevine.securityLevel" to wvLevel, "tee.attestation_security_level" to attLevel),
                    expected = "Widevine L1(硬件 DRM)⇒ keystore 应硬件支持(TEE/StrongBox)",
                    note = "L1 硬件 DRM 依赖 TEE/TrustZone,但 keystore attestation 报 Software(无硬件)=自相矛盾锚"
                )
            }
        }

        return violations
    }

    /** 型号/厂商字符串 → 规范 OEM 组;未知返 null(不参与,避免误报)。 */
    private fun oemGroup(s: String?): String? {
        val v = s?.trim()?.lowercase() ?: return null
        if (v.isEmpty()) return null
        return when {
            v.contains("motorola") || v == "moto" || v.contains("lenovo") -> "motorola"
            v.contains("google") || v.contains("pixel") -> "google"
            v.contains("samsung") -> "samsung"
            v.contains("xiaomi") || v.contains("redmi") || v.contains("poco") -> "xiaomi"
            v.contains("oppo") || v.contains("realme") || v.contains("oneplus") -> "bbk"
            v.contains("vivo") || v.contains("iqoo") -> "vivo"
            v.contains("huawei") || v.contains("honor") -> "huawei"
            v.contains("sharp") -> "sharp"
            v.contains("sony") -> "sony"
            v.contains("asus") -> "asus"
            v.contains("nubia") || v.contains("zte") -> "zte"
            v.contains("infinix") || v.contains("tecno") || v.contains("itel") -> "transsion"
            v.contains("nothing") -> "nothing"
            else -> null
        }
    }

    /** ro.board.platform 平台代号 → SoC 厂商;未知返 null。 */
    private fun socVendorFromPlatform(s: String?): String? {
        val v = s?.trim()?.lowercase() ?: return null
        if (v.isEmpty()) return null
        return when {
            v.startsWith("gs") || v.startsWith("zuma") -> "google"           // gs101/gs201/zuma = Tensor
            v.startsWith("exynos") || v.startsWith("s5e") || v.startsWith("universal") -> "samsung"
            v.startsWith("mt") -> "mediatek"
            v.startsWith("sm") || v.startsWith("sdm") || v.startsWith("msm") || v.startsWith("qcom") ||
                v in setOf("kalama", "taro", "lahaina", "pineapple", "sun", "bengal", "holi", "parrot",
                    "kona", "lito", "atoll", "trinket", "msmnile", "cape", "waipio", "ukee", "canoe") -> "qualcomm"
            else -> null
        }
    }

    /** SOC_MODEL(如 SM7550 / MT6983 / Tensor)→ SoC 厂商;未知返 null。 */
    private fun socVendorFromModel(s: String?): String? {
        val v = s?.trim()?.uppercase() ?: return null
        if (v.isEmpty()) return null
        return when {
            v.startsWith("SM") || v.startsWith("SDM") || v.startsWith("MSM") || v.startsWith("QCS") ||
                v.startsWith("APQ") -> "qualcomm"
            v.startsWith("MT") -> "mediatek"
            v.startsWith("EXYNOS") || v.startsWith("S5E") -> "samsung"
            v.startsWith("TENSOR") || v.startsWith("GS") || v.contains("GOOGLE") -> "google"
            v.startsWith("KIRIN") -> "huawei"
            else -> null
        }
    }

    /** SOC_MODEL → 档次 flagship/mid;判不了返 null。高通 SM8xxx=旗舰,SM7/6/4xxx=中低。 */
    private fun socTierFromModel(s: String?): String? {
        val v = s?.trim()?.uppercase() ?: return null
        Regex("SM(\\d)").find(v)?.let { return if (it.groupValues[1].toInt() >= 8) "flagship" else "mid" }
        Regex("SDM(\\d)").find(v)?.let { return if (it.groupValues[1].toInt() >= 8) "flagship" else "mid" }
        Regex("MT(\\d{4})").find(v)?.let { return if (it.groupValues[1].toInt() >= 6983) "flagship" else "mid" }
        return null
    }

    private fun checkAllEqualString(
        map: Map<String, FieldResult>,
        groupA: List<String>, groupB: List<String>,
        ruleName: String,
        tolerance: Int = 0,
        caseInsensitive: Boolean = false,
        normalizeLocale: Boolean = false,
        note: String = ""
    ): List<CrossFieldViolation> {
        fun norm(v: String?): String? {
            if (v.isNullOrBlank()) return null
            var s: String = v
            if (caseInsensitive) s = s.lowercase()
            if (normalizeLocale) s = s.replace('_', '-')  // en_HK → en-HK
            return s.trim()
        }
        val all = (groupA + groupB)
        val vals = all.mapNotNull { name -> map[name]?.canonicalValue?.let { name to norm(it) } }
            .filter { it.second != null }
        if (vals.size < 2) return emptyList()
        val distinct = vals.map { it.second }.toSet()
        if (distinct.size <= 1) return emptyList()
        return listOf(CrossFieldViolation(
            ruleName = ruleName,
            severity = "medium",
            fields = all,
            values = all.associateWith { map[it]?.canonicalValue },
            expected = "应等价(发现 $distinct)",
            note = note
        ))
    }

    private fun checkAllEqualWithin(
        map: Map<String, FieldResult>,
        fieldNames: List<String>,
        ruleName: String,
        tolerance: Int = 0,
        allowDifferentValues: Boolean = false,
        note: String = ""
    ): List<CrossFieldViolation> {
        val values = fieldNames.mapNotNull { name ->
            map[name]?.canonicalValue?.let { name to it }
        }
        if (values.size < 2 || allowDifferentValues) return emptyList()
        val ints = values.mapNotNull { (n, v) -> v.toIntOrNull()?.let { n to it } }
        if (ints.size < 2) return emptyList()
        val minV = ints.minOf { it.second }
        val maxV = ints.maxOf { it.second }
        if (maxV - minV <= tolerance) return emptyList()
        return listOf(CrossFieldViolation(
            ruleName = ruleName,
            severity = if (maxV - minV > 50) "high" else "medium",
            fields = fieldNames,
            values = fieldNames.associateWith { map[it]?.canonicalValue },
            expected = "所有值应在 ±${tolerance} 内(发现差异 ${maxV - minV})",
            note = note
        ))
    }

    private fun checkAllEqualNormalized(
        map: Map<String, FieldResult>,
        fieldNames: List<String>,
        ruleName: String,
        note: String = ""
    ): List<CrossFieldViolation> {
        // resolution 字段统一 normalize 为 "long×short" 形式
        fun normalize(v: String?): String? {
            if (v.isNullOrBlank()) return null
            // 跳过 shell 错误字符串(权限不足/服务不存在等),不算 inconsistent
            // 例 "cmd: Can't find service: window" / "Error: ..." / "Permission denied"
            val lower = v.lowercase()
            if (lower.startsWith("cmd:") || lower.startsWith("error") ||
                lower.contains("can't find") || lower.contains("permission denied") ||
                lower.contains("not found") || lower.contains("inaccessible")) {
                return null  // 视为"未采集到",不参与比对
            }
            val nums = Regex("\\d+").findAll(v).map { it.value.toInt() }.toList()
            if (nums.size < 2) return null
            val long = nums.max()
            val short = nums.min()
            // 必须像 resolution(短边 ≥ 300,长边 ≥ 500)— 否则可能是误识别数字
            if (short < 300 || long < 500) return null
            return "${long}x${short}"
        }
        val values = fieldNames.mapNotNull { name ->
            map[name]?.canonicalValue?.let { name to normalize(it) }
        }.filter { it.second != null }
        if (values.size < 2) return emptyList()
        val distinct = values.map { it.second }.toSet()
        if (distinct.size <= 1) return emptyList()
        return listOf(CrossFieldViolation(
            ruleName = ruleName,
            severity = "high",
            fields = fieldNames,
            values = fieldNames.associateWith { map[it]?.canonicalValue },
            expected = "所有 resolution 字段 normalize 后应一致(发现 $distinct)",
            note = note
        ))
    }
}
