# ghost_verify 覆盖缺口报告

> 说明:下列按 group 分节列出所有 `no`/`partial` 缺口,以及少数标 `yes` 但仍带实质待办(cross-rule 缺失/死规则)的"补强项"。source 标注:`(java)` API、`(native)` __system_property_get/syscall、`(shell)`、`(reflect)`、`(proc)`、`(file)`。build_props 里两条 TEE 交叉项与 MediaDrm(DRM 硬件根)已归并进第 2 节 Keystore/attestation。

---

## ✅ 已实现批次(2026-07-19,装机验证,未提交)

**Keystore/attestation(K1-K5 + crypto)**:tee.chain_verified / leaf_validity_hours / root_pubkey_sha256 / osVersion[705] / osPatchLevel[706] / RootOfTrust[704](verifiedBootState/deviceLocked/verifiedBootKey/Hash)/ keyinfo.security_level / inside_secure_hardware / has_feature.strongbox|app_attest|device_id;规则 ATTEST_CHAIN_NOT_VERIFIED / LEAF_VALIDITY_TOO_SHORT / STRONGBOX_LEVEL_VS_FEATURE。**keystore-crypto**:aes_encrypt/self_decrypt/delete_alias_regen_decrypt/encryption_is_noop + restore-diff crossDeviceDecrypt;规则 KEYSTORE_ENCRYPTION_NOOP。★结论:ghost 常量 seed"fuck"+NoEncryptionCipher 空加密→加密 token 跨设备/备份还原/新机可解,但密文==明文是检测面。

**6 组 HIGH 缺口(workflow 生成+集成)**:
- **network-ifaces**(真洞):NetworkInterface 全枚举 + tun/ppp VPN 泄漏 + 真 MAC 泄漏 + 多网卡 + WifiInfo/DHCP IP 链 + hasTransport;规则 NETWORK_IP_CHAIN_MISMATCH/VPN_INTERFACE_LEAK/REAL_MAC_LEAK/MULTI_NIC/TRANSPORT_VPN_ACTIVE/TRANSPORT_STORY + **NO_LOOPBACK**(新增,抓 getNetworkInterfaces 返空)。
- **installsource**:getInstallSourceInfo/getInstallerPackageName 三读路径一致 + initiating 签名==真 vending;规则 INSTALLER_NOT_VENDING/VENDING_ABSENT/SIGNING_MISSING/UPDATE_OWNER_NOT_VENDING。
- **display_gpu**:mode/supportedModes/stable/realSize 干净 WxH 并入 RESOLUTION_ALL_EQUAL + DisplayManagerGlobal.getDisplayInfo logical/physical + EGL14 pbuffer ctx GLSL;规则 DISPLAY_INFO_GLOBAL_VS_RESOLUTION/GPU_FAMILY_CONSISTENCY/GPU_RENDERER_VS_EGL_DRIVER/GLSL_VS_GL_VERSION。
- **telephony**:simState/hasIccCard/networkCountryIso/simCarrierId/line1Number;规则 SIM_READY_IMPLIES_OPERATOR/SIM_ABSENT_BUT_OPERATOR/ICC_*_SIM_* + **修死规则 SIM_COUNTRY_ISO_CROSS**(原引用源标签非 field 名)。
- **sensor-metadata**:每传感器 maxRange/resolution/version/power/minDelay + name 乱码扫描 + 量程/分辨率倒挂扫描;规则 SENSOR_NAME_GARBAGE/RESOLUTION_EXCEEDS_RANGE/TOO_COARSE/ACCEL_RANGE_NONSTANDARD/RANGE_RESOLUTION_INVERTED_ANY(倒挂扫描已用严格 `>` 排除触发型 1.0/1.0 传感器误报)。
- **misc-coverage**:android_id.file_vs_api(API vs settings_ssaid.xml 直读/su)+ relocator.self_native_lib_dir/split_dirs/path_tokens;规则 ACCESSIBILITY_COUNT_VS_SETTINGS_LEAK。

**★装机当场揪出的真实 ghost 检测信号**:
1. `SENSOR_ACCEL_RANGE_NONSTANDARD` — 加速度计 maxRange=68.09(≈6.94g),非标准 g 倍数(BMI260 真值应 ±16g)→ ghost 随机量程露馅。

**★订正(2026-07-19,诊断 + Codex review 后)**:先前把 `NETWORK_NO_LOOPBACK`(getNetworkInterfaces() 返空)当作 ghost bug 是**错的**。加诊断字段 `network.iface_error` + 健康机复测后钉死真因:
`java.net.SocketException: getifaddrs failed: EACCES` —— **Android 11+ 对 untrusted_app 的 getifaddrs/NETLINK_ROUTE 硬限制**(Google 防 MAC/网卡指纹),真机任何 app(持全套网络权限也一样)都拿这个 EACCES,**不是 ghost 穿帮**。verify 跑在正常 `u:r:untrusted_app:s0`、无 AVC 拒绝为证。
- NetworkInterfaceHook 在 Android 11+ 是**无效遗留**(getAll 在 hook 前就 EACCES),但无害(真机 app 同样枚举不到 → farm app 拿同样 EACCES = 一致不穿帮);VPN/MAC 检测应走已有的 network-quirks(NET_CAPABILITY_NOT_VPN / DNS 差分 / WifiInfo)。
- 已修 `NETWORK_NO_LOOPBACK` 误报:仅当 `iface_error=="ok"`(枚举真成功)却缺 lo 才报。
- 已按 Codex 给 NetworkInterfaceHook 加 fail-safe(绝不提交空数组 + 精确匹配 wlan0/rmnet + cellIp 校验 + 反射失败放行原结果),防御性改进(older Android 仍有意义),已构建 + reboot 部署。

---

## 1. 按 group 的缺口

### build_props
- **BuildHook · Verified Boot sysprops**(partial,high)— 伪造 ro.boot.verifiedbootstate=green/flash.locked=1/veritymode/warranty_bit/qemu(native 单源)。读:__system_property_get。**补→见第2节 K2**:解析 TEE RootOfTrust[704] verifiedBootState/deviceLocked 与这些 sysprop 交叉(root unlock→TEE orange/deviceLocked=false 硬拆 green/1,当前完全测不到)。
- **BuildHook · SECURITY_PATCH**(partial,high)— 仅 java-vs-native 同源,无硬件交叉。**补→见第2节 K3**:解析 osPatchLevel[706]/osVersion[705] 与 Build.VERSION.SECURITY_PATCH/RELEASE 交叉。
- **SystemClockHook**(partial,medium)— 伪造 elapsedRealtime+=base 拉长开机时长。读 `SystemClock.elapsedRealtime()`(java 单源,无交叉)。补 field `uptime_cross_source` = elapsedRealtime(java) vs /proc/uptime(proc) vs `clock_gettime(CLOCK_BOOTTIME)`(native) vs `currentTimeMillis-/proc/stat btime`;并采 elapsedRealtimeNanos。规则:四源一致(java 长 uptime vs proc 短 uptime=anchor)。
- **LinuxHook · 磁盘容量**(no,medium)— 伪造 statvfs/getTotalSpace/UnixFileStore→diskSize。读 StatFs.totalBytes/File.getTotalSpace(java)。**采集器完全没有磁盘字段**。补 field `disk_total_size` 多源 = StatFs.totalBytes(java) vs statvfs(/data)(native) vs /proc/partitions(proc) vs /sys/block/mmcblk0/size×512(file) vs `df /data`(shell) + 一致性(ghost 只 hook Java 层,native/proc/sysfs 暴露真容量)。
- **LocaleHook / TimeZoneHook**(yes,补强,low)— 清理死规则 `LOCALE_JAVA_VS_NATIVE`/`TIMEZONE_JAVA_VS_NATIVE`(引用不存在的 field 名 "Locale.getDefault"/"persist.sys.locale_native",永不触发);可加 region↔simCountryIso↔tz 地理三角规则 + `rawOffset==getTimeZone(id).rawOffset` 自洽。

### screen_display
- **DisplayHook · getMode/getSupportedModes/getStableDisplaySize**(partial,high)— 伪造 Mode.physicalWidth/Height + getStableDisplaySize(GMS 主路径)。字段已采(display_get_mode_physical/supported_modes/stable_display_size)但**不在 RESOLUTION_ALL_EQUAL cross-rule**(resFields 只有 resolution/wm_size_cmd/iwm_initial/iwm_base),每个 hook body 被 runCatching 包住→静默失败会漏真屏却无 violation。补:把这三项 + display_get_real_size 加进 RESOLUTION_ALL_EQUAL。
- **DisplayHook · DisplayManagerGlobal.getDisplayInfo**(partial,high)— **未 spoof**:hook 只改 android.view.Display.getMode(),DisplayInfo.physicalWidth/Height(GMS 走 hidden API 直读)绕过。字段已采但不在任何 cross-rule。补:cross rule 断言 display_manager_global_display_info physical/logical == resolution;并**实机确认 setForcedDisplaySize 是否重写 DisplayInfo.physicalWidth**,若否 ghost 需补 DisplayManagerGlobal.getDisplayInfo hook。
- **GLESHook · glGetString 四串**(yes,补强,high)— native getGlesStrings + Java GLES10(无 GL context 返 null→实为 native 单源)。**无任何 GPU cross-field 规则**。补规则 `GPU_FAMILY_CONSISTENCY`:GL_VENDOR 家族(Qualcomm/ARM/Imagination) ↔ GL_RENDERER token(Adreno/Mali/PowerVR) ↔ GL_VERSION vendor 前缀(V@ / v1.rNpM)一致。
- **GLESHook · GL_SHADING_LANGUAGE_VERSION**(partial,medium)— **未 spoof**(0x8B8C 落真驱动)。读 GLES10.glGetString(0x8B8C)(java,单源)。补 native 源 + `GLSL_VS_GL_VERSION` 规则(GLSL 纪元 ↔ GL_VERSION);ghost 侧需扩 hook+setGlSpoof 覆盖 0x8B8C。
- **GLESHook · egl 驱动文件(硬件真值,不可 spoof)**(partial,high)— 读 /vendor/lib*/egl 列表(file)、ro.hardware.egl/vulkan(native)、dl_iterate_phdr+/proc/self/maps vendor SO。字段已采但**无 cross-rule 绑定 spoof 的 renderer**。补规则 `GPU_RENDERER_VS_EGL_DRIVER`:renderer 家族→期望 egl .so 模式 / ro.hardware.egl 值 / 已加载 vendor SO(伪 Adreno 却 libGLES_mali.so 或 ro.hardware.egl=mali=硬锚)。

### telephony_net
- **TelephonyManagerHook · SIM operator**(yes,修死规则,high)— `SIM_COUNTRY_ISO_CROSS` 查的是 'TelephonyManager.getSimCountryIso'/'gsm.operator.iso-country',但注册 field 名是 `simCountryIso`→无 map 命中,规则永不触发。改用真 field 名或删(within-field 已覆盖)。
- **TelephonyManagerHook · SIM present/ready**(no,high)— 伪造 getSimStateForSlotIndex→READY(5)、hasIccCardUsingSlotIndex→true。补 field `telephony.simState`(getSimState,java)+`telephony.hasIccCard`(java)。规则:simState==READY ⇒ simOperator 非空;ABSENT 但 operator 有值=矛盾。
- **TelephonyManagerHook · getNetworkCountryIso**(no,medium)— 补 `telephony.networkCountryIso`(getNetworkCountryIso,java + gsm.operator.iso-country,native)+ 规则 ==simCountryIso。
- **TelephonyManagerHook · Carrier id**(no,medium)— 补 `telephony.simCarrierId`/`simCarrierIdName`(java)+ 规则 carrierId↔simOperator(MCCMNC)属同一 carrier_list 条目。
- **TelephonyManagerHook · ActiveSubscription**(no,medium)— 补 subscription 采集器遍历 SubscriptionInfo(java,需 READ_PHONE_STATE):mcc/mnc/carrierName/countryIso/carrierId/number。规则:mccString+mncString==simOperator、countryIso==simCountryIso、carrierId==getSimCarrierId。
- **TelephonyManagerHook · line1Number**(no,medium)— 补 `telephony.line1Number`(java)+ 规则:号码国家前缀 ↔ simCountryIso/simOperator。
- **SubscriptionManagerHook · activeCount**(no,medium)— 补 `subscription.activeCount`(getActiveSubscriptionInfoCount,java)与 list.size、activeModemCount 对齐(=1↔单 SIM)。
- **TelephonyManagerHook · phoneType**(partial,low)— java 单源。补规则 phoneType==GSM ↔ simState READY + operator 非空。
- **WifiServiceHook · getConnectionInfo**(yes,补强,high)— 已采 ssid/bssid/mac(perm-gated)。补 cross-check:ssid 有网时非空稳定;WifiInfo.ipAddress == NetworkInterface wlan addr(见下)。
- **WifiServiceHook · getDhcpInfo**(partial,medium)— 只采 dhcp dns1。补 `wifi.dhcp_gateway`/`dhcp_ipaddress`/`server`/`netmask`(java)+ 规则 dhcp.ipAddress==WifiInfo.ipAddress==NetworkInterface wlan==cellIp。
- **WifiServiceHook · getScanResults**(yes,补强,medium)— 只采 count。补 BSSID OUI 真实性/无重复/频段分布 hash + connected_bssid 必在扫描列表内。
- **ConnectivityManagerHook · getNetworkCapabilities**(yes,补强,high)— 已覆盖 vpn_active(NOT_VPN)。补:hasTransport(WIFI/CELLULAR) 与 WiFi/cell 故事一致 + 直接读 hasTransport(TRANSPORT_VPN) 作第二 VPN 信号。
- **★ NetworkInterfaceHook**(no,high,真洞)— 伪造 getAll() 只留 wlan/rmnet+lo、addrs 全改 cellIp、隐藏 tun0/ppp。读 `NetworkInterface.getNetworkInterfaces()` name+InetAddresses+getHardwareAddress(java,无权限,**绕过 Wifi/Connectivity hook**)。**GhostCollector 完全未采**。补 field `network.interfaces`(java)。规则:wlan/rmnet IP==WifiInfo.ipAddress==DhcpInfo.ipAddress(=cellIp);出现 tun0/ppp=VPN 泄漏(绕过 NOT_VPN spoof);getHardwareAddress 暴露真 MAC=泄漏;意外多网卡=泄漏。
- **低价值/不可读(合并)**(low)— 特权/常量返回:IMEI/MEID/IMSI/ICCID(READ_PRIVILEGED_PHONE_STATE)、BluetoothAdapter.getAddress(恒 02:00:…)、getConfiguredNetworks/getCurrentNetwork(特权)、SIM 能力布尔(isDataEnabled/isSmsCapable,行为噪声)、TrafficStats(易变计数器,仅可采 >0 反新机)。仅在 verify 以系统/特权身份运行时才补。

### sensors_hw
- **SensorManagerHook**(partial,high)— 伪造 getFullSensorList 覆盖每 Sensor 的 name/vendor/**maxRange/resolution**(不改 count/version/power/minDelay)。读 getSensorList/getDefaultSensor→getName/getVendor/getMaximumRange/getResolution(java 单源,client/server 同路径无第二源)。已采 name/vendor,**maxRange/resolution 完全没采**。补 field `sensor.{accelerometer,gyroscope,magnetic}.maxRange`/`.resolution`(java)。规则:name↔(maxRange,resolution,version,power,minDelay)参考库固定元组自洽(hook 只改 4 字段留真 version/power);name 乱码(stringUpper(5) 生成 QFRJU 类)因单 Java 源无法靠一致性抓→对 name 值做字典/正则乱码判定。
- **AudioServiceHook**(no,medium)— 伪造 getStreamVolume/getLastAudibleStreamVolume 返伪值、isStreamMute 恒 false、刻意不 hook max/min。读 AudioManager.getStreamVolume/isStreamMute/getStreamMaxVolume(java)。补 field `audio.volume_{music,ring,alarm,notification,voice_call}`、`audio.mute_music`、`audio.volume_max_music`(java,max 是未 hook 真值)。规则:(1)mute=false 但 volume=0=矛盾;(2)volume≤max 且比例合理;(3)非静音时 lastAudible==volume。
- **BatteryServiceHook · getProperty**(partial,medium)— 已采 level/is_charging。补 `battery.charge_counter`/`energy_counter`(getIntProperty,java)。规则:energy≈charge×标称电压(µAh↔nWh 量级),charge 与 capacity% 折算 mAh 量级自洽(FakeBatteryManager 用 diskSize seed 派生,校验跨 profile 随机/自洽)。
- **BatteryServiceHook · ACTION_BATTERY_CHANGED 广播路径**(no,medium)— 伪造 sticky Intent 的 EXTRA_LEVEL/STATUS/PLUGGED,不改 SCALE/TEMP/VOLTAGE/HEALTH/TECHNOLOGY(真机原值)。读 registerReceiver(null, ACTION_BATTERY_CHANGED)(java)。verify 从不注册此广播,零覆盖。补 field `battery.bcast_{level,scale,status,plugged,temperature,voltage,health,technology}`。★规则(两 hooked 路径必须自洽):(a)bcast_level×100/scale≈getIntProperty(CAPACITY);(b)bcast_status==getIntProperty(STATUS)==is_charging;(c)status∈{CHARGING,FULL}⇔plugged>0;(d)★伪造 plugged=AC 但真 temperature/voltage 无充电特征=anchor。

### ids_attribution
- **★ PackageRelocator**(partial,high)— 伪造:批量 mv 已装 app /data/app/~~token 路径 per-device 派生 + 反射改 PMS(setPath/nativeLibraryDir/splitCodePaths)。读 getInstalledApplications().sourceDir/nativeLibraryDir/splitSourceDirs、/proc/self/maps base.apk。已采 path_fingerprint(仅抽 sorted 前 12)+path_sample,**无 in-session 规则**。补:(1)跨会话自动 diff fingerprint 恒定=牧场告警;(2)枚举**全部**可见 app sourceDir 校验都在 /data/app/~~ 且符合 per-device 派生(任一跨设备恒定=泄漏);(3)加采 nativeLibraryDir/splitSourceDirs 同源。
- **InstallCodePathHook**(partial,medium)— 伪造新装 app 出生在 (deviceId,pkg) 派生 token 路径。读 ApplicationInfo.sourceDir / /proc/self/maps。补:跨会话 diff path_fingerprint;规则校验 token 形态=16B Base64 URL_SAFE|NO_WRAP(与 AOSP 不可区分)且新装/已装方案一致。
- **OaidHook**(no,medium)— 伪造 SharedPreferencesImpl.getString key=="adid_key"→settingData.oaid。读:MSA MdidSdkHelper→getOAID / 华为 AdvertisingIdClient / 小米 IdentifierManager.getOAID / 直读 SP "adid_key"。detectOaidProviders 只 Class.forName 探测类存在不取值。补 field:经 MSA/各 OEM API 实际取 OAID 值 + 直读 SP "adid_key"(reflect+java)。规则:SP 值==SDK API 值,且 OAID per-device 稳定 + 跨一键新机必变。
- **AccountManagerServiceHook**(no,medium)— 当前未主动 spoof(block 分支注释掉);reloadAccounts 清 mUsers 缓存(newphone 身份重置)。读 AccountManager.getAccounts()/getAccountsByType("com.google")。**collector 完全不采账号**。补 field:com.google 账号 count + 类型集合 hash(不读明文邮箱)(java)。跨会话规则:newPhone 后 google-account count 应=0/全新(验证 reloadAccounts 生效,无残留旧身份)。
- MediaDrm 相关缺口→**见第 2 节 K7**(硬件根)。

### antidetect
- **AccessibilityManagerHook**(yes,补强,high)— 补 CrossFieldChecker 规则:accessibility_enabled_services_count(java hooked→0)==0 但 accessibility.enabled_services(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,SettingsProvider 未 hook 路径)非空→inconsistent(hook 只 spoof client AM 不动 SettingsProvider)。注:accessibility_is_enabled 已自动交叉 4 源会抓 isEnabled=false-but-Settings=1 那半。
- **RuntimeHook**(no,medium)— 伪造 maxMemory/totalMemory→固定 JVM heap 桶(256/384/512M)。读 Runtime.maxMemory/totalMemory/freeMemory;cross vs ActivityManager.getMemoryClass()*1MB / getLargeMemoryClass / MemoryInfo.totalMem / proc meminfo。只采 /proc/meminfo.MemTotal。补 field `runtime_max_memory`/`runtime_total_memory`(java)、`activitymanager_memory_class`/`large_memory_class`/`memoryinfo_total_mem`(java)。规则:maxMemory≈getMemoryClass()*MB(ghost hook Runtime 但几乎未 hook getMemoryClass→不匹配=anchor);totalMemory≤maxMemory;maxMemory 相对 MemTotal 合理。
- **VMDebugHook**(no,medium)— 伪造 getInstancesOfClasses→null、method tracing no-op。读 reflect VMDebug.getInstancesOfClasses(Class[],boolean)(真机非 null / ghost null=异常);Debug.startMethodTracing 检 trace 文件是否写入。补 field `vmdebug_getInstancesOfClasses_null`(reflect,null 本身=信号)、`vmdebug_method_tracing_writes`(java,no-op 留空文件)。
- **WebviewHook · provider spoof**(no,medium)— 伪造 system_server 改 WebView provider com.google.android.webview→com.brave.browser + validityResult=0。读 WebView.getCurrentWebViewPackage().packageName+versionName、WebSettings.getDefaultUserAgent。补 field `webview_current_package`、`webview_default_ua`(java)。规则:current package 必须真实已装(getPackageInfo);UA Chrome 主版本==provider versionName(声称 brave 却 UA=stock Chrome / versionName 无对应已装包=锚)。
- **StrictModeHook**(low,可跳)— 反篡改中和,非设备身份。可选 `strictmode_policy_roundtrip`(set detectAll 后 getThreadPolicy mask 比对)。

### applist_pms
- **★ SettingsProviderHook · android_id**(partial,high)— 伪造 android_id 键→settingData.android_id(hooked uid)。读 Settings.Secure.getString(ANDROID_ID) / shell / **直读 /data/system/users/<u>/settings_ssaid.xml**。只采 provider API 一路(必被 spoof)。补:native 读 settings_ssaid.xml 里该包 ssaid 与 API 值对比(hook 只改 provider 返回不改 xml→直读文件拿真 android_id=穿帮)(file/native)。
- **★ ComputerEngineHook · getInstallSourceInfo**(no,high,attestation-adjacent)— 伪造 initiating/installingPackageName→com.android.vending + initiatingPackageSigningInfo 塞真 vending SigningInfo。读 getInstallSourceInfo(pkg).getInitiatingPackageName/getInstallingPackageName/getInitiatingPackageSigningInfo(java,PI 安装来源核验核心)。补 field:对 farmed app 逐个读 initiating/installing(应==vending)+ signingInfo 证书 SHA256(应==真 vending 签名)。规则:所有第三方 app 安装源==Play 且签名==真 vending。
- **★ ComputerEngineHook · getInstallerPackageName**(no,high)— 伪造 legacy API 对第三方非系统包返 com.android.vending。读 getInstallerPackageName(pkg)(java,deprecated 但风控常用)。补 field:抽样 farmed app+verify 自身读 getInstallerPackageName(应==vending)并与 getInstallSourceInfo.initiatingPackageName 交叉一致。
- **ComputerEngineHook · getSystemSharedLibraryNames**(no,medium)— 伪造 extraData[SHARE_LIBS] 整表替换。读 getSystemSharedLibraryNames()(java)。补 field:共享库名 sorted sha1+count,与目标机型 profile / features / build 品牌交叉(OEM/机型共享库差异明显=指纹)。
- **ComputerEngineHook · install-time spoof**(partial,medium)— 伪造第三方包 firstInstallTime==lastUpdateTime。读 getPackageInfo.firstInstallTime/lastUpdateTime(单查+列表+**getPackagesHoldingPermissions** 三路径)。补:(1)app.installtime_spread 并抽 lastUpdateTime 断言==firstInstall(方案 A 不变量,lastUpdate>first=穿帮);(2)触发 getPackagesHoldingPermissions 枚举路径校验 install-time 同源(当前只用 getInstalledPackages/getPackageInfo)。
- **PackageManagerServiceHook · features**(partial,medium)— hasSystemFeature+getSystemAvailableFeatures 共用 spoof set。补规则 `FEATURE_API_CROSS`:hasSystemFeature(x) ⇔ x∈getSystemAvailableFeatures(对 7 个 Pixel 采样 feature)。
- **SettingsProviderHook · bluetooth_name/device_name**(no,medium)— 伪造 device_name/bluetooth_name→props.name。读 Settings.Global device_name / Settings.Secure bluetooth_name / BluetoothAdapter.getName()。补 field:Settings.Global device_name(java)+BluetoothAdapter.getName()(java,独立 binder 不经 SettingsProvider,可能泄漏真名)。规则:与 Build.MODEL/props.name 交叉。
- **SettingsProviderHook · boot_count**(yes,补强,medium/low)— 单源已覆盖。可选 cross-field:boot_count vs uptime_minutes vs self.firstInstallTime 联合(三者都新=机器人)。
- **SettingsProviderHook · database_creation_buildid/coversheet_id**(no,low)— 补读两键(java)与 Build.ID 交叉一致(低区分度)。
- **SettingsProviderHook · bluetooth_address / volume_***(no,low)— Android 8+ bt_address 恒 02:00:… 系统保护、volume 弱信号,检测价值有限。

---

## 2. Keystore / Attestation 缺口(硬件认证面,用户最重视)

> 核心问题:parseAttestationExtension 只扫 attestationId 标签 [710-717],**完全跳过 RootOfTrust[704]、osVersion[705]、osPatchLevel[706]**;且 cert chain 只记录长度,零验签。ghost 的伪造 leaf 用自己私钥重签、KeyInfo 报 StrongBox 而 attestation 报 TEE、osPatch 硬编码 2024-01——这些**内部自相矛盾 + 与 spoof Build 矛盾**目前 verify 全测不到。

- **K1 · TEEHook cert chain 伪造**(no,high,★最强穿帮)— leaf 用 ghost keyPair_EC/RSA 重签(与父 certs_EC[0] Google 公钥不匹配),leaf 有效期仅 notBefore+1h(真机数年)。读 getCertificateChain→逐级 cert.verify(parent.publicKey) + leaf.checkValidity/notAfter-notBefore + root 公钥 ∈ Google hw-attestation root allowlist。当前只存 tee.cert_chain.length。补:①链式验签(ghost leaf 对不上 Google 中间证书=必失败)②leaf 有效期跨度 ≫1h ③root 公钥比对 Google 硬件 attestation root 白名单。
- **K2 · TEEHook RootOfTrust[704]**(no,high)— 伪造 verifiedBootState=0(Verified)/deviceLocked=TRUE,但 verifiedBootKey/Hash=每次 32B SecureRandom 随机。补 field `att.verified_boot_state`/`device_locked`/`verified_boot_key`(hex)/`verified_boot_hash`(hex)(reflect ASN.1)。规则:①verifiedBootKey 命中已知 Google/OEM 摘要白名单(随机=锚)②verifiedBootHash 跨两次 attestation 必须稳定(每次变=锚)③device_locked/verified_boot_state == ro.boot.verifiedbootstate + ro.boot.flash.locked(=build_props Verified Boot 项;root unlock 硬拆 sysprop 的 green/1)。
- **K3 · TEEHook osVersion[705]/osPatchLevel[706]**(no,high)— 硬编码 osVersion=130000(A13)/osPatchLevel=202401。补 field `att.os_version`/`att.os_patch_level`(reflect)。规则:os_version(130000→13)==Build.VERSION.RELEASE 映射;os_patch_level(202401→2024-01)==Build.VERSION.SECURITY_PATCH / ro.build.version.security_patch(硬编码 A13/2024-01 与 spoof 到 A14/15/16 直接矛盾)(=build_props SECURITY_PATCH 项)。
- **K4 · TEEHook KeyInfo StrongBox**(no,high)— getSecurityLevel→2(StrongBox)/isInsideSecureHardware→true。读 KeyFactory.getInstance(alg,"AndroidKeyStore").getKeySpec(priv, KeyInfo).getSecurityLevel()/isInsideSecureHardware()(java)。补 field `keyinfo.security_level`/`keyinfo.inside_secure_hardware`。规则:keyinfo.security_level == tee.attestation_security_level(★ghost 内部矛盾:KeyInfo 报 StrongBox(2) 但 attestation 报 TEE(1),对拉即穿帮)。
- **K5 · TEEHook strongbox/app_attest/device_id_attestation feature**(no,high)— hasSystemFeature 这三个→false。读 PackageManager.hasSystemFeature("android.hardware.strongbox_keystore" / "android.hardware.keystore.app_attest_key" / "android.software.device_id_attestation")(java)。补 field `has_feature.<...>`。规则:①security_level==StrongBox 却 strongbox feature=false 自相矛盾 ②Build 冒充 Pixel/三星旗舰(本应有 strongbox)却全 false=锚。
- **K6 · PlayIntegrityHook**(no,high,由 K1–K5 覆盖)— verdict 本体属服务端(需 server nonce 回验,本地 collector 够不到)。其本地锚定信号=同一套 keystore attestation + verified boot→补齐 K1–K5 即等于覆盖 PI 的本地攻击面。
- **K7 · MediaDrmHook(DRM 硬件根,keystore_attest + ids_attribution 两组)**(partial,high)— native_setup 只改 args[2] origin=mediaDrmUUID(影响 Widevine L3 deviceUniqueId 派生),不改 systemId/securityLevel。读 MediaDrm(EDEF8BA9-…).getPropertyByteArray("deviceUniqueId")/getPropertyString("systemId"/"securityLevel")。三值已采但单源无规则,且 collector 用**默认 origin** 构造→可能根本观察不到 spoof。补规则:①deviceUniqueId per-device 稳定 + 跨一键新机必变(否则硬件 DRM ID 泄漏物理机)②securityLevel(L1/L3)与所冒充机型 + TEE keymaster_security_level 协调(冒充旗舰却 L3=锚)③systemId 与 OEM 一致。
- **K8 · KeyStoreHook**(partial,medium)— getEntry/getKey/getCertificate 换固定内嵌密钥、containsAlias→true 注入虚拟 alias、Cipher 路由 NoEncryptionCipher。补:①KAT(见 K10)②枚举 aliases() 检虚拟 alias 泄漏。attestation 部分已由 TEEHook 覆盖。
- **K9 · MyKeyPairGenerator 固定密钥**(no,medium)— 未设 challenge 的 AndroidKeyStore keygen 返固定内嵌 keyPair(全设备同一把公钥)。读 KeyPairGenerator EC/RSA "AndroidKeyStore" **不调 setAttestationChallenge**→public.getEncoded() SHA-256 跨设备/安装比对。collectKeystoreAttestation 恒带 challenge→从不触发此分支。补 field `keystore.nonattest_ec_pubkey_sha256`(+RSA)(java,显式不带 challenge)。规则:固定内嵌公钥→所有 ghost 用户同一把=跨用户唯一锚点(应 per-device 唯一)。
- **K10 · NoEncryptionCipher 空操作**(no,medium)— ghost 密钥 Cipher 变空操作(doFinal 原样返明文 / wrap 返 getEncoded / GCM 剥 16B tag)。读 Cipher AES/GCM/NoPadding + AndroidKeyStore 密钥 ENCRYPT(已知明文)。补 KAT field:①密文!=明文 ②同明文两次密文不同(随机 IV)③GCM 密文长度=明文+16(含 tag)。命中即抓空操作密码。

**Keystore 已覆盖:** TEEHook attestationId[710-717] vs Build.*(每个 tee.id.X 含 Build.X + tee.idX 双源,FieldResult 自动判不一致=核心锚点,真机走 hackLeafExistingCert 保留真值正是这条抓);TrustManagerServiceHook isDeviceSecure(与 keyguard.is_secure 双源交叉)。

---

## 3. 已覆盖良好(一句话带过)

- **build_props(身份面):** Build.* 全套 java/native/shell 三源 + fingerprint 拆解 + SDK↔release 映射 + SOC/HARDWARE java-vs-native,身份面到位;os.version(kernel)四源一致。
- **screen_display(分辨率主链):** IWindowManager initial/base size+density、Resources/Display real-metrics、WindowMetrics、DENSITY_DEVICE_STABLE 全采且进 RESOLUTION_ALL_EQUAL/DPI_ALL_EQUAL;GL 四串已采;keyguard 双 binder 双源。
- **telephony_net(DNS/VPN):** network.dns.via_vpn_or_proxy 做 active⊄dhcp 集差 = 强隧道检测;vpn_active(NOT_VPN);simOperator/Name/CountryIso within-field java-vs-native。
- **applist_pms(可见性主面):** PmsHookTarget30/33 的 app-presence(peer_visible/sensitive_visible/visible_list_hash)+installed-apps(vector_delta 交叉三 API);accessibility 多路径含 isEnabled 盲区检测;adb_enabled/development_settings、display_size/density_forced 抹痕。
- **ids_attribution:** GAID/InstallReferrer 属纯 log 或广告归因业务(归 AF 审计),非设备身份面。

---

## 4. 建议补齐清单(按 priority 排序,可据此写代码)

### HIGH(先做:硬件认证 → 绕 hook 真洞 → 屏幕/GPU/网络 → 其余)
1. **K1** TEE cert chain 验签 + leaf 有效期跨度 + Google root allowlist(★最强穿帮)
2. **K2** 解析 RootOfTrust[704] verifiedBootState/deviceLocked/verifiedBootKey/Hash + 白名单/稳定性/vs ro.boot.*
3. **K3** 解析 osVersion[705]/osPatchLevel[706] + vs Build.RELEASE/SECURITY_PATCH
4. **K4** KeyInfo security_level/inside_secure_hardware + == attestation_security_level
5. **K5** strongbox/app_attest/device_id_attestation hasSystemFeature + 与旗舰画像一致性
6. **K6** PlayIntegrity(实现 K1–K5 即覆盖本地面)
7. **K7** MediaDrm deviceUniqueId 稳定性/跨新机变 + securityLevel vs 画像/TEE + systemId vs OEM
8. **NetworkInterface** 全网卡 name/addr/hwaddr 采集 + tun0/ppp VPN 泄漏 + IP/MAC 交叉(★真洞)
9. **ComputerEngine getInstallSourceInfo** initiating/installing==vending + signingInfo SHA256==真 vending
10. **ComputerEngine getInstallerPackageName** ==vending + 与 InstallSourceInfo 交叉
11. **SettingsProvider android_id** native 读 settings_ssaid.xml vs Settings.Secure API
12. **DisplayHook** 把 getMode/supportedModes/stableDisplaySize/getRealSize 并入 RESOLUTION_ALL_EQUAL
13. **DisplayHook** DisplayManagerGlobal.getDisplayInfo cross rule + 实机确认是否需补 hook
14. **GLES** GPU_FAMILY_CONSISTENCY(vendor↔renderer↔version)
15. **GLES** GPU_RENDERER_VS_EGL_DRIVER(renderer vs egl .so / ro.hardware.egl / loaded SO)
16. **Telephony** simState/hasIccCard + operator 一致性
17. **Telephony** 修死规则 SIM_COUNTRY_ISO_CROSS(改用真 field 名 simCountryIso)
18. **Wifi** getConnectionInfo cross-check(ip==NetworkInterface wlan)
19. **Connectivity** hasTransport(WIFI/CELLULAR/VPN) 一致性
20. **SensorManager** maxRange/resolution + name 元组自洽 + 乱码检测
21. **PackageRelocator** 全量可见 app sourceDir per-device 派生校验 + 跨会话 fingerprint diff + nativeLibraryDir/splitSourceDirs
22. **AccessibilityManager** cross-field(Java count==0 vs Settings ENABLED_ACCESSIBILITY_SERVICES 非空)

### MEDIUM
- **K8** KeyStore alias 枚举 + KAT;**K9** 非-attest 固定公钥 SHA256(跨用户唯一);**K10** NoEncryptionCipher KAT(密文!=明文/随机 IV/GCM tag)
- SystemClock uptime_cross_source(java/proc/native/btime)
- LinuxHook disk_total_size 多源
- GLES GL_SHADING_LANGUAGE_VERSION native 源 + GLSL_VS_GL_VERSION
- Wifi dhcp gateway/ip/server/netmask + IP 链交叉;Wifi scan BSSID 真实性 + connected 在列表
- Telephony networkCountryIso / simCarrierId / ActiveSubscription 采集器 / line1Number;SubscriptionManager activeCount
- Audio 各 stream volume/mute/max + 一致性(mute=false 但 vol=0 矛盾)
- Battery charge/energy counter;Battery 广播路径全字段 + 两路径自洽(★真温压 vs 伪 plugged)
- OAID 实际取值 + SP vs SDK + per-device 稳定跨新机变
- InstallCodePath token 形态校验 + 跨会话 diff
- AccountManager google 账号 count/hash + newPhone 清零验证
- Runtime heap vs getMemoryClass;VMDebug getInstancesOfClasses null + tracing;Webview provider package/UA 一致性
- PMS FEATURE_API_CROSS;ComputerEngine 共享库 hash;ComputerEngine install-time first==last + getPackagesHoldingPermissions 路径
- SettingsProvider device_name/bluetooth_name vs Build.MODEL;boot_count 三新联合

### LOW
- Locale/TimeZone 死规则清理 + 地理三角/rawOffset 自洽
- phoneType↔SIM 一致性;SIM 能力布尔
- 特权/不可读(IMEI/MEID/IMSI/ICCID、BT MAC、getConfiguredNetworks)仅特权模型;TrafficStats 计数器
- StrictMode roundtrip(可跳);SettingsProvider database_creation_buildid / bluetooth_address / volume_*;GAID 稳定性(可重置,意义有限)