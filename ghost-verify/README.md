# ghost-verify

独立 Android module,用于验证 [fakeFramework](../../fakeFramework-hotfix) 的"一键新机"
是否真把每个字段都改完整,有没有遗漏 / 多路径不一致。

## 设计原理

对每个 ghost 改过的字段,提供 **2~5 个独立采集路径**:

| 层 | 例子 | 用于发现 |
|---|---|---|
| `java` | `Build.MANUFACTURER` / `Settings.Secure.ANDROID_ID` | Java 反射、framework API |
| `native` | `__system_property_get("ro.product.manufacturer")` | libc 原生路径,绕过 Java 抽象 |
| `shell` | `Runtime.exec("getprop ro.product.manufacturer")` | shell 子进程路径 |
| `proc` | `/proc/cpuinfo` / `/proc/sys/kernel/random/boot_id` | 内核接口 |
| `egl` | native `eglMakeCurrent + glGetString(GL_RENDERER)` | GPU 真实驱动查询 |

同字段不同路径采集到的值如果**集合去重后 ≤ 1 个**就是 `consistent: true`;否则就是 ghost 漏 hook 某条路径(自动标 ❌)。

## 覆盖字段

- **Build.\*** — MANUFACTURER/BRAND/BOARD/DEVICE/MODEL/PRODUCT/HARDWARE/**SOC_MODEL**/**SOC_MANUFACTURER**/FINGERPRINT/HOST/ID/DISPLAY/TIME/TYPE/TAGS/BOOTLOADER/**RADIO**/SERIAL/SKU/ODM_SKU/SUPPORTED_ABIS
- **Build.VERSION.\*** — SDK_INT/RELEASE/INCREMENTAL/**SECURITY_PATCH**/CODENAME/BASE_OS
- **Settings** — ANDROID_ID/ADB_ENABLED/DEVELOPMENT_SETTINGS_ENABLED/SCREEN_BRIGHTNESS
- **Display** — resolution/dpi/`cache_key.display_info`
- **kernel** — uname(sysname/nodename/release/version/machine)/boot_id/`/proc/version`
- **hw** — `/proc/cpuinfo.Hardware`/`/proc/meminfo.MemTotal`/cpu_freq_max
- **gpu** — **GL_VENDOR/GL_RENDERER/GL_VERSION/GL_EXTENSIONS**(Java GLES10 vs native EGL pbuffer)
- **telephony** — simOperator/simOperatorName/simCountryIso/networkOperator/phoneType
- **features** — features count/SHA1,以及 7 个 Pixel-only feature 单独检测
- **misc** — timezone/locale/`ro.build.description`/`ro.boot.boot_devices`/`ro.boot.vbmeta.digest`/`ro.config.ringtone`
- **system-files** — stat 7 个关键 SO/jar 的 size/mtime/mode(检测 ghost modifySystemFile 重定向)
- **uptime** — `SystemClock` / libc `clock_gettime` / raw `svc` / `sysinfo` / `/proc/uptime` / `/proc/stat btime`
- **camera** — 仅只读 `CameraCharacteristics`,采 ID、能力、焦距、sensor size、stream map、可见校准参数和 HAL version；不打开相机
- **sensors** — 完整 public metadata、OEM private type、`Sensor.getId()`、650ms accel/gyro/magnetic 事件统计与时间戳同源
- **cpu/memory** — libc 与 raw `svc` 读取 cpufreq policy；三次 `/proc/meminfo` 与 `ActivityManager.MemoryInfo` 动态交叉验证
- **features/NFC** — 完整 `FeatureInfo(name/version/GLES/flags)` 契约以及 camera/NFC/sensor service 实际能力

报告中的 `clusteringSignals` 只声明每个值属于 `identity`、`family`、
`physical_candidate` 还是 `dynamic`。单份报告不会把“值稳定”误当成聚集证据；跨身份、跨物理机结论必须由显式分组比较器给出。

## Build

```bash
cd RiskEngine
./gradlew :ghost-verify:assembleDebug
adb install -r ghost-verify/build/outputs/apk/debug/ghost-verify-debug.apk
adb shell pm grant com.ghost.verify android.permission.CAMERA
```

## Run

1. 在测试设备上打开 "Ghost Verify" app
2. 点 **采集设备信息**
3. 报告保存到 `/sdcard/Download/ghost_verify/ghost_verify_<timestamp>.json`
4. 拉取对比:
   ```bash
   adb pull /sdcard/Download/ghost_verify/ ./
   ```
5. 跑两次(一次原始设备,一次一键新机后)对比 JSON 差异:
   ```bash
   jq '.fields[] | select(.consistent==false) | .name' ghost_verify_*.json
   ```

## schema3 恢复字段本地审计

独立 APK 采集 → clone restore 后，用专用 `auto=restore-audit` 采集本轮实际 API 读值，再在电脑本地与恢复输入的 canonical device 比较。此入口复用 `GhostCollector` / `SourceValue` / `CollectReport`；在 SDK 初始化前分流，不调用 GmsClone 账号采集、不执行联网探针、不读写 `SnapshotStore`，也不上传审计数据。普通 `auto=collect` 和合成自检报告缺少本轮证据，不能代替此入口。

设备切换后，先由主仓 harness 重新安装并确认 `getHookPkgs` 包含 `com.ghost.verify`；只 enable 不足以收养。安装行为和副作用由主仓回归流程管理。每轮使用全新 nonce；以下命令只给调用方式，真实设备的安装/还原/备份与账号断言统一由主仓 `ghost-test/run.sh` 执行：

```bash
# CURRENT_DEVICE_ID 取本轮 getRunningDevice；不是源快照的 GSF device_id。
SER=$(adb devices -l | awk '/usb:20-4/{print $1}')
RUN_ID=$(python3 -I -c 'import uuid; print(uuid.uuid4().hex)')
START_S=$(adb -s "$SER" shell date +%s)
NOT_BEFORE_MS=$((START_S * 1000))
adb -s "$SER" shell am force-stop com.ghost.verify
adb -s "$SER" shell am start -n com.ghost.verify/.MainActivity \
  --es auto restore-audit --es audit_run_id "$RUN_ID"
# 等待 GhostVerifyRestore 的 COLLECT_DONE；COLLECT_FAILED 不能用于验收。
adb -s "$SER" logcat -d -s GhostVerifyRestore:I '*:S'
```

报告固定写到 `/sdcard/Android/data/com.ghost.verify/files/restore_audit/restore_audit_<RUN_ID>.json`；外部私有存储不可用时退回内部 `files/restore_audit/`。同 run ID 的文件已存在时拒绝复用。采集前后均保存 roster 收养状态与 `expectedEnv.deviceId` 当前身份；`expectedEnv.expected` 值被丢弃，不进入实际观测。harness 还应独立确认采集前后 `getRunningDevice` 相等。

```bash
# PRIVATE_DIR 是本轮新建、权限 0700 的本机目录；只读取本轮精确文件名。
DEVICE_REPORT="/sdcard/Android/data/com.ghost.verify/files/restore_audit/restore_audit_${RUN_ID}.json"
adb -s "$SER" exec-out su -c "cat $DEVICE_REPORT" > "$PRIVATE_DIR/independent-ghost-verify.json"
chmod 600 "$PRIVATE_DIR/independent-ghost-verify.json"
python3 -I ghost-verify/tools/compare_restore_snapshot.py \
  --snapshot "$PRIVATE_DIR/schema3-snapshot.json" \
  --report "$PRIVATE_DIR/independent-ghost-verify.json" \
  --expected-device-id "$CURRENT_DEVICE_ID" \
  --run-id "$RUN_ID" --not-before-ms "$NOT_BEFORE_MS" \
  --output "$PRIVATE_DIR/sanitized-result.json"
```

`--snapshot` 接受解密后的裸 `schema_version=3` 快照，以及私有中央 one 响应 `{data:{id,clone_data:object|string}}`。输入只在本地解析；账号集合、PB、token 保真由主仓 harness 另行检查。`--expected-device-id` 也可写作 `--restored-device-id`。`--output` 创建权限 0600 的新文件，拒绝覆盖；即使输入被拒，仍输出脱敏的拒收理由。stdout 和结果文件只包含固定字段名、观测来源、状态、覆盖率及静态原因，不包含预期值、观测值、账号名、PB、token、未知输入键或原始解析异常。

比较只读取 `ghost.fields[].sources` 中明确命名 API 和 layer 的结果；不会用 `canonicalValue`、SDK 字段、期望配置、GMS 基准或 `restore_diff` 缓存补值。它拒收没有实际观测、无收养证据、前后身份不符、非本轮 nonce、早于 `--not-before-ms`、采集时段不符或采集进程来源不符的报告。它是回归审计证据检查，不是防篡改签名协议。

| 逐字段状态 / 总结退出码 | 含义 |
|---|---|
| `PASS` / 全部通过为 0 | 对应实际 API 值与 canonical 预期相等 |
| `MISMATCH` / 1 | 实际值与预期不相等 |
| `MISSING` / 1 | 预期有字段，但报告缺该字段或指定直接来源 |
| `UNOBSERVABLE` / 无失败但有跳过为 `PARTIAL`、3 | API 权限失败/占位值，或采集范围不支持该语义；不算 PASS |
| `REJECTED` / 2 | 输入格式、收养、身份或新鲜性不能建立有效比较 |

覆盖分母仅包含 canonical device 实际携带的恢复字段，不补造未采字段。display 的 resolution 宽高和 dpi 分开计数；locale 与 sensorMap 等复合恢复值整体比较。`observedPercent=(PASS+MISMATCH)/total`，`passPercent=PASS/total`，`MISSING` 和 `UNOBSERVABLE` 分别计数。

映射边界：Build / VERSION 对应 Java API，`props.name` 对应 PRODUCT，`build_date_utc` 秒对比 Build.TIME 毫秒；内存按实际字节而非取整 MiB；diskSize 走外部存储 StatFs；display 宽高按大小排序以消除旋转，dpi 对应 app resources 的逻辑 densityDpi；locale 取 Resources.Configuration 的 language/country/variant（保留空国家/variant），时区取 TimeZone ID。GAID 通过设备/用户范围的 AdvertisingIdClient 直接观测；`settingData.oaid` 在此合同中是 GMS GAID。共享库预期值按 producer `TextUtils.join(" ", libraries)` 的空格格式拆分，实际观测按 `joinToString(",")` 的逗号格式拆分，再按集合比较；顺序不影响结果，缺库产生 `MISMATCH`。默认传感器按完整 name/vendor/maxRange/resolution 映射比较，音量按 Android stream 0..5 直接读。

`props.baseband_version` 成功观测到的空串表示 Wi-Fi 设备的合法恢复值，专用采集入口在 RADIO Java 来源保留该空串，比较器允许空串对空串为 `PASS`、空串对非空串为 `MISMATCH`。错误、权限拒绝、null 仍为 `UNOBSERVABLE`；旧报告中丢成 null 的值不能从预期空串推断成功，其他字段的空串也不放行。

`props.sdk` 遵循服务的 ASCII 正整数字符串要求和消费者 `toIntOrNull()` 的正 Int 范围；不额外限定为 SDK 29..37，也不要求落入固定 SDK/release 对照表。独立采集 APK 的 API 21 来源可进入审计，SDK/release 分别与实际 API 读值比较。Ghost / ghost-verify 自身 APK 的 minSdk 不构成源快照 SDK 下限。

`extraData.ssaid_vending` 属于 Play UID/签名/用户范围，verify 的 ANDROID_ID 无法证明其恢复，明确 `UNOBSERVABLE`。IMEI/MEID/IMSI/ICCID 等未在本入口取对应特权 API，也明确跳过；不会把 GmsClone 的 presence 标志当其真值。`props.hardware` 仅是 legacy mapper 输入，不承诺写回 live props；opaque display_info、SMSC、carrier ID、不同 GL API 契约下的 extension 集合等仍列为不可直接验证。若实际 API 字段不一致，只报告给主仓，比较器不修改任何拦截或仿真逻辑。

本地验证（纯合成数据，不读取真实账号报告）：

```bash
python3 -I -m unittest discover -s ghost-verify/tools -p 'test_compare_*.py'
JAVA_HOME=/path/to/jdk17 ./gradlew :ghost-verify:testDebugUnitTest :ghost-verify:assembleDebug --offline
```

## 物理机聚集性 A/B

脚本化采集必须带 `auto=collect`。每台物理机至少采两个不同虚拟身份；要确认具体物理机锚，至少需要两台 Pixel 6：

```bash
adb -s SERIAL shell am force-stop com.ghost.verify
adb -s SERIAL shell am start -n com.ghost.verify/.MainActivity --es auto collect
adb -s SERIAL pull /sdcard/Download/ghost_verify/ ./reports/

python3 ghost-verify/tools/compare_clustering_reports.py \
  --sample pixel6-a:identity-a1=reports/a1.json \
  --sample pixel6-a:identity-a2=reports/a2.json \
  --sample pixel6-b:identity-b1=reports/b1.json \
  --sample pixel6-b:identity-b2=reports/b2.json \
  --json-output reports/clustering_result.json
```

比较器的判据：

- `IDENTITY_COLLISION`：同一物理机的不同虚拟身份复用了本应轮换的高熵值。
- `CONFIRMED_PHYSICAL_UNIT_ANCHOR`：某值在每台物理机内跨身份稳定，同时能区分两台物理机。
- `SUSPECTED_PHYSICAL_ANCHOR`：仅证实单机跨身份稳定，仍需第二台同型号机器排除公共常量。
- `CROSS_TARGET_FAMILY_COLLISION`：不同声明机型仍暴露相同硬件家族画像；需结合真实同型号基线判断。
- `DYNAMIC_SIGNAL_FROZEN`：同一身份的多份报告里动态信号逐字相同；扩大间隔复现后可确认固定快照伪造。
- `CROSS_IDENTITY_DYNAMIC_FROZEN`：至少两个身份各有两份稳定样本，且复用了完全相同的动态快照。

## 报告格式

```json
{
  "timestamp": 1733484000000,
  "sessionId": "ABC123_2026-06-06_14-30-00",
  "deviceLabel": "POCO/24069PC21G (peridot)",
  "fieldCount": 80,
  "inconsistentCount": 3,
  "fields": [
    {
      "name": "MANUFACTURER",
      "category": "build",
      "consistent": true,
      "canonicalValue": "POCO",
      "sources": [
        { "source": "Build.MANUFACTURER", "layer": "java", "value": "POCO" },
        { "source": "ro.product.manufacturer", "layer": "native", "value": "POCO" },
        { "source": "ro.product.vendor.manufacturer", "layer": "native", "value": "POCO" },
        { "source": "getprop ro.product.manufacturer", "layer": "shell", "value": "POCO" }
      ]
    },
    {
      "name": "SOC_MODEL",
      "category": "build",
      "consistent": false,
      "canonicalValue": null,
      "sources": [
        { "source": "Build.SOC_MODEL", "layer": "java", "value": "24069PC21G" },
        { "source": "ro.soc.model", "layer": "native", "value": "SM8635" }
      ]
    }
  ]
}
```

`SOC_MODEL` 不一致 = ghost BuildHook 把 model 错赋给了 SOC_MODEL(已修复)。

## 采集进程来源与合成自检

新报告的 `ghost.observationContext` 记录采集器的包名、进程名、UID、PID 和
`scope=collector_process_and_children`，界面同时显示来源。它标记报告的采集环境，
不证明 GMS 或 DroidGuard 在其它路径中实际采集或上传了这些字段。旧报告缺少该项时
来源仍为未知，不用当前进程信息补猜。

Ghost 另有在 GMS 主进程或 persistent 进程执行的 clone 采集接口；它与本模块的
本进程采集不是同一种来源，完整产物还含账号材料。`GmsClone` 只把其中的身份/运行时
字段映射成 `gms.*` 基准(见下节),不提取凭证;权限门控标识(imei/meid/serialno)
只记"有值/无值"。

仅检查报告格式、来源序列化和缺失/单来源/冲突判定时，可运行合成自检：

```bash
SER=$(adb devices -l | awk '/usb:20-2 /{print $1}')
adb -s "$SER" shell am start -n com.ghost.verify/.MainActivity --es auto selftest
```

自检在 SDK 初始化及权限请求前返回，只使用合成字段；不会执行 `GhostCollector`、
账号采集、网络探针或 `SnapshotStore` 读写。它在应用外部私有目录写入
`report_selftest.json`（通常为 `/sdcard/Android/data/com.ghost.verify/files/`），
包含 `dataKind=synthetic`、逐项结果和 `passed`。自检通过只证明报告逻辑，
不能作为环境真实性、GMS 读值或 Play Integrity 的验收结果。

## 两侧比对:PairStatus 与 baseline.pairs

app↔GMS(`gms.*`)、app↔Ghost 期望值(`expectedEnv`)、进程↔期望值三类比对统一先归一
(`normalizeObserved`):空串→`empty`;`unknown`、身份字段的 `-1`→`placeholder`;
`<denied…>`、错误以 `SecurityException` 开头→`permission`。再判定 `PairStatus`:

| 状态 | 含义 | 是否出告警 |
|---|---|---|
| `MATCH` / `MISMATCH` | 两侧都可采,值相等/不等(大小写不敏感;宽高按无序对,横竖屏互换算 MATCH) | MISMATCH 按原规则出 high |
| `NOT_COLLECTABLE` | 权限门控字段(`PERMISSION_GATED`:`Build.getSerial()`、`line1Number`、`gms.telephony.*`)任一侧不可采,或一侧为权限拒绝,或两侧都没值 | 永不出 |
| `ONE_SIDED` | 非权限字段一侧有值一侧不可采(hook 只覆盖一边或旧 Ghost 缺键) | GMS 比对出 `GMS_ONE_SIDED_VALUE`(low) |
| `NOT_RUN` | 比对对象没运行(gms.unstable 未启动、观测目标无结果) | 仅 info |

报告 `ghost.baseline.pairs[]` 逐条列出所有参与比对的对:`{field, leftField, rightField, left, right, status, reason}`;
`coverage.permissionGated` 单列权限门控且不可采的字段,不再混入未采集/单来源。

新增/改写的规则:

- `GMS_RUNTIME_VIEW_MISMATCH` / `GMS_IDENTITY_VS_APP`(high):改为基于 PairResult,只在 MISMATCH 时出。
  身份对新增 `RELEASE`、`runtime.total_mem_mb`、`uname.release`、`uname.machine`、`timezone`、
  `dpi_app_resources_java↔display.density_dpi`、`resolution↔gms.display.real_width/real_height`(无序)、
  `locale` 国家↔`gms.locale.country`、`Build.getSerial()` 有无↔`gms.telephony.serialno`(权限门控)。
  `SECURITY_PATCH` 不在身份对里:所有 Google UID 共享档案补丁(L1),本来就可以 ≠ 虚拟设备
  (wa_26:档案 `2026-10-05` / 虚拟设备 `2026-10-01`),改由下一条规则比。
- `GMS_SECURITY_PATCH_VS_EXPECTED`(high):`gms.SECURITY_PATCH` 必须等于 `expectedEnv(gms 主进程)`
  的 `build.securityPatch`(档案 L1 值),不是 app 值。旧 Ghost 无该期望 → 记 ONE_SIDED(low)。
- `GMS_ONE_SIDED_VALUE`(low):上述对 ONE_SIDED。
- `GMS_PROFILE_PROBE_NOT_RUN`(info,不计风险分):clone 顶层 `profileProbeState=unstable_not_running`;
  状态缺失或 `absent` 仍按 `GMS_PROFILE_PROBE_MISSING`(high)。
- `APP_VS_EXPECTED`(high):采集时调用 `content://com.ghost.call/expectedEnv?pkg=com.ghost.verify&process=<本进程>`,
  `expected` 每个键与本进程读值比较(`leftField`=app 字段,`rightField`=`expected.<key>`);缺键不比较。
  旧 Ghost 返回 `Method not found: expectedEnv` → `_meta.expected_env_status=unsupported`,不比较、不计风险。

只映射不比较(app 侧没有同义字段):`gms.telephony.imei`、`gms.telephony.meid`、`gms.req_gl_es_version`、
`gms.gpu_family`;窗口级 `gms.display.width/height` 受 Activity 窗口影响,也不与 app 比较。

## 进程环境观测(ProcessEnvActivity)

主界面"进程环境观测"进入。Ghost 在目标进程里注入采集 env(`content://com.ghost.call/observe`),
页面把每个进程的读值与 Ghost 给该进程的期望值(`expectedEnv?pkg=&process=`)、verify 自身读值逐字段对照。
`com.google.android.gms.unstable` 期望 Pixel 档案(L2),其余进程期望虚拟设备(L3)。

- 控件:开始/停止注入采集、TTL(默认 600 秒,Ghost 钳到 10..1800)、重启目标(`restart=1/0`)、
  目标多选(默认 gms + vending,其余来自 `getHookPkgs`)、刷新、导出、只看差异。
- 表格:行按 build/display/gl/mem/kernel/runtime/permissions 分组;列 = Ghost 期望(verify 自身的期望值)|
  verify(self)| 每个 `pkg:process`。GMS 点名时 `.unstable` 即使没有采样也显示 L2 期望与“– 未运行”。格子 ✓ 一致 / ✗ 不一致(高亮;该进程期望与第一列不同时附"期望:")/
  🔒 权限不可采 / – 未运行或缺值。宽高合成 `display.size` / `display.realSize` 无序比较。
- 无期望值的键只在同 layer 的进程间取多数值比较;`androidId`、电量/温度/电压、进程堆内存等天然不同的值不比较。
  `gl.extensions.{count,sha256}` 在表中保留观测值，但不参与 ✗ 判定：verify 的 NativeBridge 走 GLES2 `glGetString`,注入端 GlProbe 走 GLES3 `glGetStringi`，wa_26 同一驱动分别得到 105/104 项，无法直接互比。
- 归因提示:同 layer 全部进程一致但≠期望 →"优先怀疑期望值/配置投影";只有部分进程≠期望 →"该进程 hook 漏装或串档"。
- 旧 Ghost 返回 `Method not found: observe` → 显示"Ghost 版本不支持观测"。

provider 响应解析:cursor 第 0 列第一行;是原始 JSON 对象串,若首字符为 `"` 先按 JSON 字符串解一层;
`Method not found…` → 不支持;`ok!=true` → 失败(`error`)。`results` 分页:`next>=0` 时用 `from=next` 续拉,`-1` 结束;
同一进程多条只取 `at` 最新的一条。

headless(按 USB 口取序列号):

```bash
SER=$(adb devices -l | awk '/usb:20-4/{print $1}')
adb -s "$SER" shell am start -n com.ghost.verify/.ProcessEnvActivity --es auto observe \
  --es targets com.google.android.gms,com.android.vending --ei ttl 600 --ei wait 60 [--ez keep true] [--ez restart false]
adb -s "$SER" logcat -d -s GhostVerifyObserve | grep OBSERVE_DONE
```

流程:`op=start` → 每 3 秒拉一次 results,直到每个目标至少一个进程有结果（目标含 GMS 时还须等到 `.unstable`）或 `wait` 秒超时 → 写
`Download/ghost_verify/observe_<ts>.json`(失败退回 app 外部私有目录)→ 未带 `keep` 时 `op=stop` →
logcat `OBSERVE_DONE path=<路径> processes=<N> mismatches=<M>`(N=有结果的目标进程数,M=全部 ✗ 格子数)。
导出含 `spec`、每列的期望值与 layer、原始 env(telephony 值已换成 `present`)和比较结果。

## 覆盖率与判定边界

每个字段新增 `validSourceCount` 和 `comparisonStatus`：UNAVAILABLE=无有效来源，SINGLE_SOURCE=仅一个来源，CONSISTENT=至少两个有效来源相同，INCONSISTENT=来源冲突。部分来源失败时，仍需结合 `validSourceCount / sources.size` 判断覆盖缺项。报告 `coverage` 分别统计四类；旧 `consistent` 布尔值仅保留兼容，不能单独作为验收门槛。界面把字段冲突与跨字段告警分开显示，未采集和单来源不再显示为绿色通过。

逻辑 densityDpi 不能用于计算物理英寸；缺少可信面板尺寸及形态时不产生物理对角线结论。SDK native 调试检查只读 TracerPid，不执行改变跟踪状态的 PTRACE_TRACEME；读取失败不构成阳性证据，也不证明没有调试器。

回归命令：

```bash
./gradlew :ghost-verify:testDebugUnitTest :ghost-verify:assembleDebug --offline
clang++ -std=c++17 riskengine-sdk/src/test/cpp/native_debug_detector_test.cpp riskengine-sdk/src/main/cpp/detector/native_debug_detector.cpp -o /tmp/ghost-native-debug-test
/tmp/ghost-native-debug-test
```

ReportCoverageTest 覆盖零来源、单来源、部分采集、多源冲突、JSON 导出、进程来源往返序列化、旧报告来源保持未知与合成自检，以及平板逻辑分辨率不触发旧手机对角线规则。native 用例覆盖无 tracer、重复检查、正 TracerPid 和读取失败。

2026-11-02：`:ghost-verify:testDebugUnitTest :ghost-verify:assembleDebug --offline` 通过（10 项 JVM 测试），USB `20-2` 实际启动 `auto=selftest` 后 7/7 通过，界面与 JSON 均确认 PASS。测试包最后恢复禁用、停止状态。本次对禁用 residual 验证器的 `install -r` 被 Ghost 安装协调器转换为 route2 真卸载后重装，旧私有数据未保留；后续部署必须先核对该副作用，不能将 `-r` 视作保留数据的充分条件。

2026-10-18 USB 20-4 实测：552 字段中 38 项未采集、425 项单来源、87 项多源一致、2 项冲突；移除错误屏幕规则后保留 7 项跨字段告警，SDK 分数从原 ptrace 误判的 8 降为 0。该结果不代表既有 SDK/认证版本、空加密、硬件家族或 meminfo 冻结问题已解决。
