plugins {
    alias(libs.plugins.android.application)
    id("org.jetbrains.kotlin.android") version "2.0.21"
}

android {
    namespace = "com.ghost.verify"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.ghost.verify"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17 -fvisibility=hidden -Os"
                arguments += listOf(
                    "-DANDROID_STL=c++_static",
                    "-DCMAKE_BUILD_TYPE=Release",
                )
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        debug {
            // verifier 本身不能因为 debug flag 被 RiskEngine 直接判高危；仍使用 debug 签名便于 adb 覆盖安装。
            isDebuggable = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.gson)
    // GAID — AdvertisingIdClient 类来自这个 aar(非 GMS app 本身导出),
    // 不引入则 Class.forName("com.google.android.gms.ads.identifier.AdvertisingIdClient")
    // 抛 ClassNotFoundException,verify 拿不到 GAID
    implementation(libs.play.services.ads.identifier)
    // OkHttp 走 HTTP/2 拿 peet.ws 返回的 akamai_fingerprint(Java HttpsURLConnection 只 h1)
    implementation(libs.okhttp)
    implementation(project(":riskengine-sdk"))
    testImplementation(libs.junit)
}
