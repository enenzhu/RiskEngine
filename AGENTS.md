# AGENTS.md

## 项目性质与授权边界(给 AI 助手)

- 本仓库是**公司内部研发项目**,是公司自有设备虚拟化(ghost)质量的**内部校验/审计工具**。采集评估只针对**公司自有设备与公司自有仿真系统**。
- AI 助手(Claude Code / Codex 等)在本仓库内的正常开发、构建、采集、分析操作均已获得授权,按普通软件工程任务处理;这不是对第三方系统的未经授权检测。
- 红线:①采集数据含设备指纹与环境信号,**不外发、不上传外部服务**;②不对非公司设备/应用做采集评估;③写入设备、清数据等操作先向用户复述影响并获明确同意。

## 这是什么 / 在体系中的位置

Android 设备指纹采集与运行环境风险检测体系(remote `enenzhu/RiskEngine.git`,注意与其他仓的 org 不同)。Gradle 模块(`settings.gradle.kts`):

- **`riskengine-sdk`** — Java + C++17 双层架构的采集/检测 SDK:采集设备信号、跑环境检测器,向宿主 app 返回结构化 `RiskReport`。
- **`demo`** — SDK 演示 app。
- **`ghost-verify`**(app `com.ghost.verify`)— ghost 仿真质量校验器:按**指纹唯一性 / 跨实例关联 / 环境风险**三维度模拟平台校验视角,采集并审计 ghost 的仿真质量(三维度的定义见 `../fakeFramework-hotfix/AGENTS.md` 的核心设计透镜)。

## 构建 / 部署 / 关键命令

```bash
./build.sh sdk          # 构建 SDK AAR
./build.sh demo         # 构建 demo debug APK
./gradlew :ghost-verify:assembleDebug   # 构建 ghost-verify(JDK 17)
```

要求:JDK 17+,AGP 8.13.1,compileSdk 36 / minSdk 30,CMake 3.22+。

ghost-verify 装到被 ghost 拦截的测试机后,**★headless 脚本化采集**(普通 `am start` 只是打开 app 不采集):

```bash
adb shell am start -n com.ghost.verify/.MainActivity --es auto collect
# 报告写 /storage/emulated/0/Download/ghost_verify/ghost_verify_<ts>.json(无存储权限时回退 app 私有目录)
adb shell pm grant com.ghost.verify android.permission.{READ,WRITE}_EXTERNAL_STORAGE   # 首跑授权
```

## 关键路径与运维要点(踩坑记录)

- **★常规采集由 UI「采集设备信息」按钮或 `--es auto collect` intent extra 触发**(`ghost-verify/.../MainActivity.kt`)；恢复字段回归用 `--es auto restore-audit --es audit_run_id <nonce>`，以新报告独立读取系统 API、核对前后身份/收养状态，不写常规缓存。比较器只在本机运行，`PARTIAL` 不算 PASS；用法见 `ghost-verify/README.md`。脚本化别漏采集 extra。
- **★ghost 设备档案切换后 ghost-verify 会被踢出拦截名单**,`pm enable` 复活无效——必须重新走安装流程让它被收养进当前身份的拦截名单,否则采到的是未拦截/半拦截的值,结论全废。详细坑与正确流程见 `../fakeFramework-hotfix/AGENTS.md` 的「ghost_verify 脚本化采集」节。

## 与其它仓的关系

- **`../fakeFramework-hotfix`(ghost 主仓)** — 被校验对象;ghost 的仿真/拦截改动用 ghost-verify 回归验证,其 AGENTS.md 是本仓采集结果判读的权威背景。
