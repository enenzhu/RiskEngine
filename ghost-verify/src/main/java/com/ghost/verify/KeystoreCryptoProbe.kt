package com.ghost.verify

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * ★Keystore 加解密跨设备可移植性探针(备份/还原/新机验证)。
 *
 * 真机行为:AndroidKeyStore 密钥硬件绑定、不可导出、留在 TEE → app 数据(密文)随备份走,但密钥留在原设备
 *   → 还原/新机后**解密失败** → farm app 丢 token/登录态。
 *
 * ghost 行为(实测 KeyStoreHook):把 AndroidKeyStore 换成**常量 seed("fuck")派生的软件 AES 密钥** + 固定 GCM IV,
 *   每台设备派生同一密钥 → 密文确定性、跨设备可解;alias 映射存 /data/data/pkg/.alias(随备份走)。
 *   即使 app **删 alias 重生成**,ghost 仍用同 seed 派生同密钥 → 旧密文照样解得开。
 *
 * 本探针用**标准 AndroidKeyStore AES/GCM 流程**(与真 app 一致),让 ghost hook 生效,验证:
 *   1) 同会话 encrypt→decrypt 往返(基线能力)。
 *   2) **删 alias→重生成→解旧密文**仍成功(证明 seed 常量、删 alias 不破跨设备)。
 *   3) 跨设备:把密文存进快照(随备份走),还原后用当前设备密钥解 baseline 密文 == canary(见 SnapshotStore.diff)。
 */
object KeystoreCryptoProbe {
    private const val ALIAS = "ghost_verify_xdev_aes"
    const val CANARY = "GHOST_XDEV_CANARY_v1"

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return kg.generateKey()
    }

    /** 加密 → (cipherHex, ivHex);失败 null。 */
    fun encrypt(plain: String): Pair<String, String>? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val ct = c.doFinal(plain.toByteArray(Charsets.UTF_8))
        ct.toHex() to c.iv.toHex()
    }.getOrNull()

    /** 用当前设备的 alias 密钥解 (cipherHex, ivHex) → 明文;失败/密钥不匹配 null。 */
    fun decrypt(cipherHex: String, ivHex: String): String? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, ivHex.unhex()))
        String(c.doFinal(cipherHex.unhex()), Charsets.UTF_8)
    }.getOrNull()

    fun deleteAlias() {
        runCatching { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS) }
    }

    /** 同会话往返:encrypt(canary) → decrypt → ==canary ?(基线能力,含 ghost 软件密钥路径)。 */
    fun selfRoundTripOk(): Boolean {
        val e = encrypt(CANARY) ?: return false
        return decrypt(e.first, e.second) == CANARY
    }

    /** ★删 alias→重生成→解旧密文仍成功 ?(ghost seed 常量 → 删 alias 不破;真机硬件密钥则必失败)。 */
    fun deleteRegenDecryptOk(): Boolean {
        val e = encrypt(CANARY) ?: return false
        deleteAlias()                                  // 模拟 app 删 alias
        return decrypt(e.first, e.second) == CANARY    // 重生成的密钥能否解删前的密文
    }

    /** K10 KAT:同明文两次加密密文应**不同**(真 AES/GCM 每次随机 IV);相同=固定 IV 或空加密=锚。 */
    fun twoEncryptsDifferOk(): Boolean {
        val a = encrypt(CANARY) ?: return false
        val b = encrypt(CANARY) ?: return false
        return a.first != b.first
    }

    /** K10 KAT:GCM 密文长度应 == 明文 + 16(128-bit tag);等于明文长度=无 tag=空加密(NoEncryptionCipher)。 */
    fun gcmTagLengthOk(): Boolean {
        val e = encrypt(CANARY) ?: return false
        val ctLen = e.first.length / 2  // hex → 字节数
        val ptLen = CANARY.toByteArray(Charsets.UTF_8).size
        return ctLen == ptLen + 16
    }

    /**
     * K9:不带 attestation challenge 的 AndroidKeyStore EC keygen,返公钥 SHA-256。
     * ghost MyKeyPairGenerator 对未设 challenge 的 keygen 返**固定内嵌 keyPair** → 所有设备/安装同一把公钥
     *   = 跨用户唯一锚(真机应 per-device 唯一 + 跨一键新机必变)。检测器跨设备/跨新机比对此 hash。
     */
    fun nonAttestEcPubKeySha256(): String? = runCatching {
        val alias = "ghost_verify_nonattest_ec"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        runCatching { ks.deleteEntry(alias) }  // 每次重新生成,避免复用旧 entry
        val kpg = java.security.KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                // 故意不调 setAttestationChallenge → 命中 ghost 非认证固定密钥分支
                .build())
        val kp = kpg.generateKeyPair()
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(kp.public.encoded).joinToString("") { "%02x".format(it) }
    }.getOrNull()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun String.unhex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
