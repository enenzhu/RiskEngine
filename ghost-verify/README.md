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

## 覆盖字段(60+ 个)

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

## Build

```bash
cd RiskEngine
./gradlew :ghost-verify:assembleDebug
adb install -r ghost-verify/build/outputs/apk/debug/ghost-verify-debug.apk
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
