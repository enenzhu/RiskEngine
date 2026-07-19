package com.ghost.verify

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * 独立的 App 列表界面:列出 verify 视角能读到的所有已装 app(getInstalledPackages),
 * 每个可展开看 安装信息 / 签名 / 路径 / uid / flags 等 —— 用来肉眼核对 ghost 的隐藏/投影/
 * 路径重随机化效果。★真包 vs Stage2 伪造包一眼可辨:伪造包 uid=0 / signature=<none> /
 * sourceDir 是假的 /data/app/pkg-1/;真包有真 uid + ~~random 路径 + 真签名。
 */
class AppListActivity : AppCompatActivity() {

    private lateinit var container: LinearLayout
    private lateinit var summary: TextView
    private lateinit var btnType: Button
    private var apps: List<AppRow> = emptyList()
    private var searchText = ""
    private var typeFilter = 0 // 0=全部 1=仅第三方 2=仅系统
    private var iconPx = 96

    private data class AppRow(
        val pkg: String, val label: String, val system: Boolean,
        val pi: PackageInfo, val ai: ApplicationInfo,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        iconPx = (32 * resources.displayMetrics.density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            fitsSystemWindows = true
            androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(this) { v, insets ->
                val b = insets.getInsets(
                    androidx.core.view.WindowInsetsCompat.Type.systemBars()
                            or androidx.core.view.WindowInsetsCompat.Type.displayCutout()
                )
                v.setPadding(32 + b.left, 32 + b.top, 32 + b.right, 32 + b.bottom)
                insets
            }
        }
        val search = EditText(this).apply {
            hint = "搜索包名 / 名称…"
            textSize = 13f
        }
        btnType = Button(this).apply { text = "类型: 全部" }
        val btnExport = Button(this).apply { text = "导出" }
        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(search, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f))
            addView(btnType, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnExport, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        btnExport.setOnClickListener {
            btnExport.isEnabled = false
            thread {
                val ts = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())
                val model = runCatching { android.os.Build.MODEL }.getOrNull()
                val f = AppListExport.save(applicationContext, model, ts)
                runOnUiThread {
                    btnExport.isEnabled = true
                    summary.text = if (f != null) "已导出: ${f.absolutePath}" else "导出失败"
                }
            }
        }
        summary = TextView(this).apply { textSize = 13f; setPadding(0, 12, 0, 12) }
        container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val scroll = ScrollView(this).apply { addView(container) }
        root.addView(topRow)
        root.addView(summary)
        root.addView(scroll)
        setContentView(root)

        summary.text = "加载中…"
        search.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { searchText = s?.toString()?.trim().orEmpty(); render() }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        btnType.setOnClickListener {
            typeFilter = (typeFilter + 1) % 3
            btnType.text = "类型: " + when (typeFilter) { 0 -> "全部"; 1 -> "第三方"; else -> "系统" }
            render()
        }

        // ★可脚本化触发:adb shell am start -n com.ghost.verify/.AppListActivity --ez auto_export true
        //   → 以 verify(被 hook 的 farm caller)身份枚举 getInstalledPackages 并落文件,供归因/install-time 对抗测试自动化。
        val autoExport = intent.getBooleanExtra("auto_export", false)
        thread {
            val loaded = loadApps()
            runOnUiThread { apps = loaded; render() }
            if (autoExport) {
                val ts = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())
                val model = runCatching { android.os.Build.MODEL }.getOrNull()
                val f = AppListExport.save(applicationContext, model, ts)
                runOnUiThread { summary.text = "auto导出: ${f?.absolutePath ?: "失败"}" }
            }
        }
    }

    private fun loadApps(): List<AppRow> {
        val pm = packageManager
        val list = runCatching { pm.getInstalledPackages(0) }.getOrElse { emptyList() }
        return list.mapNotNull { pi ->
            val ai = pi.applicationInfo ?: return@mapNotNull null
            val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pi.packageName)
            val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            AppRow(pi.packageName, label, system, pi, ai)
        }.sortedWith(compareBy<AppRow> { it.system }.thenBy { it.label.lowercase() })
    }

    private fun render() {
        container.removeAllViews()
        val f = searchText.lowercase()
        val shown = apps.filter {
            (when (typeFilter) { 1 -> !it.system; 2 -> it.system; else -> true }) &&
            (f.isEmpty() || it.pkg.lowercase().contains(f) || it.label.lowercase().contains(f))
        }
        summary.text = "共 ${apps.size}(第三方 ${apps.count { !it.system }} / 系统 ${apps.count { it.system }})" +
                " · 显示 ${shown.size}"
        for (row in shown) addAppSection(row)
    }

    /** 每个 app 一行:图标 + 标题(点击展开详情,首次展开惰性构建含签名)。 */
    private fun addAppSection(row: AppRow) {
        val tag = if (row.system) "[sys]" else "[3rd]"
        val headerText = "$tag ${row.label}  ·  ${row.pkg}  ·  uid=${row.ai.uid}"

        val icon = ImageView(this).apply {
            layoutParams = LinearLayout.LayoutParams(iconPx, iconPx).apply { rightMargin = 16 }
            runCatching { setImageDrawable(packageManager.getApplicationIcon(row.ai)) }
                .onFailure { setImageResource(android.R.drawable.sym_def_app_icon) }
        }
        val title = TextView(this).apply {
            text = "▶ $headerText"
            textSize = 12f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 14, 0, 4)
            addView(icon)
            addView(title)
        }
        val body = TextView(this).apply {
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(iconPx + 16, 0, 0, 8)
            visibility = View.GONE
        }
        var built = false
        header.setOnClickListener {
            val show = body.visibility != View.VISIBLE
            if (show && !built) { body.text = buildDetails(row); built = true }
            body.visibility = if (show) View.VISIBLE else View.GONE
            title.text = (if (show) "▼ " else "▶ ") + headerText
        }
        container.addView(header)
        container.addView(body)
    }

    private fun buildDetails(row: AppRow): String {
        val ai = row.ai; val pi = row.pi
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
        val flags = buildList {
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) add("SYSTEM")
            if (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0) add("UPDATED_SYSTEM")
            if (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) add("DEBUGGABLE")
            if (ai.flags and ApplicationInfo.FLAG_HAS_CODE != 0) add("HAS_CODE")
        }
        val installer = runCatching {
            packageManager.getInstallSourceInfo(row.pkg).installingPackageName
        }.getOrNull()
        val sb = StringBuilder()
        sb.append("version    = ${pi.versionName} (code=${pi.longVersionCode})\n")
        sb.append("uid        = ${ai.uid}\n")
        sb.append("flags      = [${flags.joinToString(",")}]\n")
        sb.append("minSdk     = ${ai.minSdkVersion}   targetSdk=${ai.targetSdkVersion}\n")
        sb.append("firstInstall = ${fmt.format(Date(pi.firstInstallTime))}\n")
        sb.append("lastUpdate   = ${fmt.format(Date(pi.lastUpdateTime))}\n")
        sb.append("installer  = ${installer ?: "<null>"}\n")
        sb.append("sourceDir  = ${ai.sourceDir}\n")
        if (ai.publicSourceDir != null && ai.publicSourceDir != ai.sourceDir)
            sb.append("publicSrc  = ${ai.publicSourceDir}\n")
        ai.splitSourceDirs?.takeIf { it.isNotEmpty() }?.let {
            sb.append("splitDirs  = ${it.joinToString("\n             ")}\n")
        }
        sb.append("nativeLib  = ${ai.nativeLibraryDir}\n")
        sb.append("dataDir    = ${ai.dataDir}\n")
        sb.append("signature  = ${sigHash(row.pkg)}\n")
        return sb.toString()
    }

    /** 签名 SHA-256(前 16 hex);伪造包无签名 → <none>,正好暴露 name-level 伪造。 */
    private fun sigHash(pkg: String): String = runCatching {
        val pi = packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = pi.signingInfo?.apkContentsSigners
        if (signers.isNullOrEmpty()) "<none>"
        else {
            val md = MessageDigest.getInstance("SHA-256")
            signers.joinToString(", ") { s ->
                md.digest(s.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)
            }
        }
    }.getOrElse { "<err:${it.javaClass.simpleName}>" }
}
