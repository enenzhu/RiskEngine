package com.ghost.verify

object NativeBridge {
    init {
        System.loadLibrary("ghost_verify")
    }

    /** __system_property_get(key) — 不经过 Java getprop CLI,直接 libc */
    external fun getSystemProperty(key: String): String

    /**
     * __system_property_find + __system_property_read 双步路径 — 商业风控用来绕开
     * 只 hook 了 __system_property_get 的 spoof。ghost 必须两条都 hook,否则跟
     * getSystemProperty 不一致 = anchor。
     */
    external fun getSystemPropertyViaFind(key: String): String

    /**
     * popen(cmd) 执行 shell + 读 stdout。模拟商业风控用 getprop / uname -a /
     * cat /sys/devices/soc0/serial_number / ip a / ps -ef 等命令绕过 Java/native
     * 路径直接走 execve+svc_openat。ghost SVC IO 重定向覆盖不全在这里能看到。
     */
    external fun execShell(cmd: String, maxBytes: Int = 32768): String

    /** 直接 fopen,绕过 Java IO 抽象。maxBytes 默认 64KB */
    external fun readFile(path: String, maxBytes: Int = 65536): String

    /** uname() syscall:返回 [sysname, nodename, release, version, machine] */
    external fun getUname(): Array<String?>

    /** Native EGL pbuffer + glGetString:返回 [vendor, renderer, version, extensions] */
    external fun getGlesStrings(): Array<String?>

    /** stat() — 返回 "size=NNN,mtime=NNN,mode=NNN" 或空串 */
    external fun statFile(path: String): String

    /**
     * dl_iterate_phdr() native 枚举 — 商业风控主用路径。返回所有已加载 SO 的
     * dlpi_name 列表(空串 dlpi_name=main executable 自身,已过滤)。
     * 跟 java 层 /proc/self/maps 解析对比 → 发现 ghost 注入/隐藏的不一致。
     */
    external fun enumerateLoadedSos(): Array<String>
}
