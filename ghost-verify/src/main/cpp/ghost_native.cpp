// Native 采集层 — 故意不依赖 RiskEngine SDK,自给自足。
// 目的:跟 Java 层采集的同一字段做交叉验证,任何不一致说明 ghost spoof 漏了某条路径。
//
// 提供:
//   - getSystemProperty(key)      → __system_property_get(libc, 跳过 Java getprop CLI)
//   - readFile(path, maxBytes)    → 直接 fopen,读 /proc/cpuinfo, /proc/meminfo,
//                                    /proc/sys/kernel/random/boot_id, /system/build.prop 等
//   - getUname()                  → uname() syscall(返回 sysname/nodename/release/version/machine)
//   - getGlesStrings()            → 真 native 创建 EGL pbuffer context + glGetString(GL_RENDERER/...)
//                                    比 Java 层 GLES10.glGetString 走更底层路径
//   - statFile(path)              → stat(),返回 size/mtime/mode(用于 modifySystemFile 检测)

#include <jni.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <android/log.h>

#define LOG_TAG "ghost_native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static jstring toJstring(JNIEnv* env, const std::string& s) {
    return env->NewStringUTF(s.c_str());
}

// ============================================================
// getSystemProperty: __system_property_get
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_getSystemProperty(JNIEnv* env, jclass, jstring jkey) {
    if (!jkey) return env->NewStringUTF("");
    const char* key = env->GetStringUTFChars(jkey, nullptr);
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(key, value);
    env->ReleaseStringUTFChars(jkey, key);
    if (len <= 0) return env->NewStringUTF("");
    return env->NewStringUTF(value);
}

// ============================================================
// getSystemPropertyViaFind: 走 __system_property_find + __system_property_read
// 第二条 native sysprop 读取路径 — 攻击者(大厂风控)用这个绕过仅 hook 了
// __system_property_get 的 spoof。文章原话:"大厂在 android 9 以上会直接调用
// system_properties.Get... 如果只 Hook __system_property_get 的话可能就会导致指纹泄漏"
// ghost 应该两条路径都 hook,否则这里跟 getSystemProperty 不一致 = ghost 漏 hook
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_getSystemPropertyViaFind(JNIEnv* env, jclass, jstring jkey) {
    if (!jkey) return env->NewStringUTF("");
    const char* key = env->GetStringUTFChars(jkey, nullptr);
    const prop_info* pi = __system_property_find(key);
    env->ReleaseStringUTFChars(jkey, key);
    if (!pi) return env->NewStringUTF("");
    char name[PROP_NAME_MAX] = {0};
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_read(pi, name, value);
    if (len <= 0) return env->NewStringUTF("");
    return env->NewStringUTF(value);
}

// ============================================================
// execShell: popen() 执行 shell 命令,fgets 读取 stdout
// 模拟商业风控 SDK 走 popen 路径绕过 Java/getSystemProperty hook —
// 文章列的 getprop / uname -a / cat /sys/devices/soc0/serial_number / ip a /
// ps -ef / df grep magisk 等都走这条。execve(底层是 svc_openat),所以 ghost
// SVC IO 重定向有没有覆盖通过这个能立刻看出来。
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_execShell(JNIEnv* env, jclass, jstring jcmd, jint maxBytes) {
    if (!jcmd) return env->NewStringUTF("");
    const char* cmd = env->GetStringUTFChars(jcmd, nullptr);
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        env->ReleaseStringUTFChars(jcmd, cmd);
        return env->NewStringUTF("");
    }
    const int cap = maxBytes > 0 && maxBytes < 65536 ? maxBytes : 32768;
    std::vector<char> buf(cap + 1, 0);
    size_t total = 0;
    while (total < (size_t) cap) {
        size_t n = fread(buf.data() + total, 1, cap - total, fp);
        if (n == 0) break;
        total += n;
    }
    pclose(fp);
    env->ReleaseStringUTFChars(jcmd, cmd);
    buf[total] = 0;
    return env->NewStringUTF(buf.data());
}

// ============================================================
// readFile: 直接 fopen,绕过 Java IO 抽象
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_readFile(JNIEnv* env, jclass, jstring jpath, jint maxBytes) {
    if (!jpath) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    FILE* fp = fopen(path, "r");
    if (!fp) {
        env->ReleaseStringUTFChars(jpath, path);
        return env->NewStringUTF("");
    }
    const int cap = maxBytes > 0 && maxBytes < 65536 ? maxBytes : 65536;
    std::vector<char> buf(cap + 1, 0);
    size_t n = fread(buf.data(), 1, cap, fp);
    fclose(fp);
    env->ReleaseStringUTFChars(jpath, path);
    buf[n] = 0;
    return env->NewStringUTF(buf.data());
}

// ============================================================
// uname() syscall
// ============================================================
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ghost_verify_NativeBridge_getUname(JNIEnv* env, jclass) {
    struct utsname u {};
    int rc = uname(&u);
    jobjectArray arr = env->NewObjectArray(5, env->FindClass("java/lang/String"), nullptr);
    if (rc != 0) return arr;
    env->SetObjectArrayElement(arr, 0, toJstring(env, u.sysname));
    env->SetObjectArrayElement(arr, 1, toJstring(env, u.nodename));
    env->SetObjectArrayElement(arr, 2, toJstring(env, u.release));
    env->SetObjectArrayElement(arr, 3, toJstring(env, u.version));
    env->SetObjectArrayElement(arr, 4, toJstring(env, u.machine));
    return arr;
}

// ============================================================
// EGL/GLES native 路径采集 GL_VENDOR/RENDERER/VERSION/EXTENSIONS
// 走真实 EGL pbuffer + eglMakeCurrent,跟 Java 层 GLES10.glGetString 比对
// ============================================================
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ghost_verify_NativeBridge_getGlesStrings(JNIEnv* env, jclass) {
    jobjectArray result = env->NewObjectArray(4, env->FindClass("java/lang/String"), nullptr);

    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) {
        LOGE("eglGetDisplay failed");
        return result;
    }
    EGLint major, minor;
    if (!eglInitialize(display, &major, &minor)) {
        LOGE("eglInitialize failed");
        return result;
    }
    const EGLint configAttribs[] = {
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8,
            EGL_NONE
    };
    EGLConfig config;
    EGLint numConfigs;
    if (!eglChooseConfig(display, configAttribs, &config, 1, &numConfigs) || numConfigs == 0) {
        LOGE("eglChooseConfig failed");
        eglTerminate(display);
        return result;
    }
    const EGLint pbufAttribs[] = {EGL_WIDTH, 8, EGL_HEIGHT, 8, EGL_NONE};
    EGLSurface surface = eglCreatePbufferSurface(display, config, pbufAttribs);
    if (surface == EGL_NO_SURFACE) {
        LOGE("eglCreatePbufferSurface failed");
        eglTerminate(display);
        return result;
    }
    const EGLint ctxAttribs[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, ctxAttribs);
    if (context == EGL_NO_CONTEXT) {
        LOGE("eglCreateContext failed");
        eglDestroySurface(display, surface);
        eglTerminate(display);
        return result;
    }
    if (!eglMakeCurrent(display, surface, surface, context)) {
        LOGE("eglMakeCurrent failed");
        eglDestroyContext(display, context);
        eglDestroySurface(display, surface);
        eglTerminate(display);
        return result;
    }

    auto safeStr = [](const GLubyte* p) -> std::string {
        return p ? std::string(reinterpret_cast<const char*>(p)) : std::string();
    };
    std::string vendor = safeStr(glGetString(GL_VENDOR));
    std::string renderer = safeStr(glGetString(GL_RENDERER));
    std::string version = safeStr(glGetString(GL_VERSION));
    std::string extensions = safeStr(glGetString(GL_EXTENSIONS));

    env->SetObjectArrayElement(result, 0, toJstring(env, vendor));
    env->SetObjectArrayElement(result, 1, toJstring(env, renderer));
    env->SetObjectArrayElement(result, 2, toJstring(env, version));
    env->SetObjectArrayElement(result, 3, toJstring(env, extensions));

    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroyContext(display, context);
    eglDestroySurface(display, surface);
    eglTerminate(display);
    return result;
}

// ============================================================
// statFile: stat(),返回 [size, mtime, mode] 字符串
// 用于检测 ghost modifySystemFile 重定向(eg /system/lib/libc.so 是否被改)
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_statFile(JNIEnv* env, jclass, jstring jpath) {
    if (!jpath) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    struct stat st {};
    int rc = stat(path, &st);
    env->ReleaseStringUTFChars(jpath, path);
    if (rc != 0) return env->NewStringUTF("");
    char buf[128];
    snprintf(buf, sizeof(buf), "size=%lld,mtime=%lld,mode=%o",
             (long long) st.st_size, (long long) st.st_mtime, st.st_mode & 0777);
    return env->NewStringUTF(buf);
}

// ============================================================
// enumerateLoadedSos: dl_iterate_phdr() native 枚举 — 商业风控 SDK
// (同盾 / 数美)主用路径,绕过 Java /proc/self/maps 解析。返回 dlpi_name
// 列表(已加载 SO 的 realpath),verify 端比对 Java pLayer 读 /proc/self/maps
// 的列表 → 任何差异 = ghost soinfo 注入 / hide 没盖全。
// ============================================================
#include <link.h>

struct SoCollect {
    JNIEnv* env;
    std::vector<std::string>* names;
};

static int phdr_cb_collect(struct dl_phdr_info* info, size_t, void* data) {
    auto* ctx = (SoCollect*) data;
    if (info->dlpi_name && info->dlpi_name[0]) {
        ctx->names->emplace_back(info->dlpi_name);
    }
    return 0;
}

// ============================================================
// raw_syscall — 内联汇编 svc #0,绕过 libc 任何 hook
// Article 3 的核心攻击向量:libc open/read/openat 被 hook 也无效,
// svc #0 直接 trap 到内核,只有 ptrace / kernel 模块能拦截。
// ghost 当前 svc IO 重定向(KernelSU.redirectIO)如果做得完整,
// 这个 raw syscall 跟 fopen 应该拿到同样的结果;不一致 = ghost
// 只 hook 了 libc 层没拦 svc 层,商业风控立刻识破。
// ============================================================
#if defined(__aarch64__)
static inline long raw_syscall6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    register long x3 asm("x3") = d;
    register long x4 asm("x4") = e;
    register long x5 asm("x5") = f;
    asm volatile("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc");
    return x0;
}
#else
// 32 位 armv7 — 用 libc syscall() wrapper(可能被 hook,但 ghost 主要跑 arm64,
// 这里仅 fallback)
static inline long raw_syscall6(long n, long a, long b, long c, long d, long e, long f) {
    return syscall(n, a, b, c, d, e, f);
}
#endif

// ============================================================
// readFileViaSyscall: 完全用 raw svc syscall 读文件(绕 libc)
// openat(AT_FDCWD, path, O_RDONLY) → read 循环 → close,全走 svc #0
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_readFileViaSyscall(JNIEnv* env, jclass, jstring jpath, jint maxBytes) {
    if (!jpath) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    long fd = raw_syscall6(__NR_openat, (long) AT_FDCWD, (long) path, (long) O_RDONLY, 0, 0, 0);
    if (fd < 0) {
        env->ReleaseStringUTFChars(jpath, path);
        return env->NewStringUTF("");
    }
    const int cap = maxBytes > 0 && maxBytes < 65536 ? maxBytes : 4096;
    std::vector<char> buf(cap + 1, 0);
    long total = 0;
    while (total < cap) {
        long n = raw_syscall6(__NR_read, fd, (long)(buf.data() + total), (long)(cap - total), 0, 0, 0);
        if (n <= 0) break;
        total += n;
    }
    raw_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
    env->ReleaseStringUTFChars(jpath, path);
    buf[total] = 0;
    return env->NewStringUTF(buf.data());
}

// ============================================================
// statFileViaSyscall: 完全用 raw svc syscall 跑 newfstatat(绕 libc)
// 给 ghost svc IO 重定向 stat 路径做完整性验证。
// ============================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghost_verify_NativeBridge_statFileViaSyscall(JNIEnv* env, jclass, jstring jpath) {
    if (!jpath) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    long rc;
    char outbuf[128] = {0};
#if defined(__aarch64__)
    // arm64 用 newfstatat(AT_FDCWD, path, &st, 0)
    struct stat st {};
    rc = raw_syscall6(SYS_newfstatat, (long) AT_FDCWD, (long) path, (long) &st, 0, 0, 0);
    env->ReleaseStringUTFChars(jpath, path);
    if (rc != 0) return env->NewStringUTF("");
    snprintf(outbuf, sizeof(outbuf), "size=%lld,mtime=%lld,mode=%o",
             (long long) st.st_size, (long long) st.st_mtime, st.st_mode & 0777);
#else
    // armv7 没 newfstatat,fallback 走 fstatat64 — libc 包装可能被 hook,但 32 位很少跑
    struct stat64 st64 {};
    rc = syscall(SYS_fstatat64, AT_FDCWD, path, &st64, 0);
    env->ReleaseStringUTFChars(jpath, path);
    if (rc != 0) return env->NewStringUTF("");
    snprintf(outbuf, sizeof(outbuf), "size=%lld,mtime=%lld,mode=%o",
             (long long) st64.st_size, (long long) st64.st_mtime, st64.st_mode & 0777);
#endif
    return env->NewStringUTF(outbuf);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ghost_verify_NativeBridge_enumerateLoadedSos(JNIEnv* env, jclass) {
    std::vector<std::string> names;
    SoCollect ctx{env, &names};
    dl_iterate_phdr(phdr_cb_collect, &ctx);
    jclass strCls = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray((jsize) names.size(), strCls, nullptr);
    for (size_t i = 0; i < names.size(); ++i) {
        jstring js = env->NewStringUTF(names[i].c_str());
        env->SetObjectArrayElement(arr, (jsize) i, js);
        env->DeleteLocalRef(js);
    }
    return arr;
}
