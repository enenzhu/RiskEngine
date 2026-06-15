package com.ghost.verify

object NativeBridge {
    init {
        System.loadLibrary("ghost_verify")
    }

    /** __system_property_get(key) — 不经过 Java getprop CLI,直接 libc */
    external fun getSystemProperty(key: String): String

    /** 直接 fopen,绕过 Java IO 抽象。maxBytes 默认 64KB */
    external fun readFile(path: String, maxBytes: Int = 65536): String

    /** uname() syscall:返回 [sysname, nodename, release, version, machine] */
    external fun getUname(): Array<String?>

    /** Native EGL pbuffer + glGetString:返回 [vendor, renderer, version, extensions] */
    external fun getGlesStrings(): Array<String?>

    /** stat() — 返回 "size=NNN,mtime=NNN,mode=NNN" 或空串 */
    external fun statFile(path: String): String
}
