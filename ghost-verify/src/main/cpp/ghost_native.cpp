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
