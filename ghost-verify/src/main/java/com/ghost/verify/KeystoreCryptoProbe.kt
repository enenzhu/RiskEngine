package com.ghost.verify

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
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

    // ============================================================================================
    // ★RSA(PRIVATE_RSA)加解密 —— 参照真 app SharedPrefUtils 的 RSA/ECB/PKCS1Padding。
    //   ghost 把它路由到 NoEncryptionCipher(no-op),密文与密钥值无关 → 跨备份/还原/新机可解。
    //   本次重构:RSA 密钥改每设备惰性派生 + 自签名占位证书。此探针验证:
    //     1) 同会话 encrypt(pubkey)→decrypt(privkey) 往返(惰性派生 + 自签名证书可用)。
    //     2) 跨备份:旧密文用当前设备 RSA 密钥解仍 ==canary(no-op 与密钥值无关 → 老备份能解)。
    // ============================================================================================
    private const val RSA_ALIAS = "ghost_verify_xdev_rsa"
    private const val RSA_TRANSFORM = "RSA/ECB/PKCS1Padding"

    /** 供 RSA(KeyPairGeneratorSpec 需要 Context)使用;GhostCollector 实例化时注入。 */
    @Volatile var appContext: android.content.Context? = null

    private fun getOrCreateRsaEntry(): KeyStore.PrivateKeyEntry {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(RSA_ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let { return it }
        // ★用真 app(参照 SharedPrefUtils)采用的**废弃 KeyPairGeneratorSpec** 生成 RSA keystore 键 ——
        //   这是旧 ghost MyKeyPairGenerator.initialize 唯一认得的 RSA spec 类型;现代 KeyGenParameterSpec
        //   在旧 ghost 会 ClassCastException(新 ghost 已修复两种都支持)。
        val ctx = appContext ?: throw IllegalStateException("KeystoreCryptoProbe.appContext not set")
        val start = java.util.Calendar.getInstance()
        val end = java.util.Calendar.getInstance().apply { add(java.util.Calendar.YEAR, 25) }
        @Suppress("DEPRECATION")
        val spec = android.security.KeyPairGeneratorSpec.Builder(ctx)
            .setAlias(RSA_ALIAS)
            .setSubject(javax.security.auth.x500.X500Principal("CN=$RSA_ALIAS"))
            .setSerialNumber(java.math.BigInteger.valueOf(1337))
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()
        val kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        kpg.initialize(spec)
        kpg.generateKeyPair()
        val ks2 = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ks2.getEntry(RSA_ALIAS, null) as KeyStore.PrivateKeyEntry
    }

    /** RSA 加密(用证书公钥)→ Base64;失败 null。 */
    fun rsaEncrypt(plain: String): String? = runCatching {
        val c = Cipher.getInstance(RSA_TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, getOrCreateRsaEntry().certificate.publicKey)
        Base64.encodeToString(c.doFinal(plain.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }.getOrNull()

    /** RSA 解密(用当前设备私钥)→ 明文;失败/不匹配 null。 */
    fun rsaDecrypt(b64: String): String? = runCatching {
        val c = Cipher.getInstance(RSA_TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, getOrCreateRsaEntry().privateKey)
        String(c.doFinal(Base64.decode(b64, Base64.NO_WRAP)), Charsets.UTF_8)
    }.getOrNull()

    /** 同会话 RSA encrypt→decrypt 往返 ==canary ?(惰性 RSA + 自签名证书基线能力)。 */
    fun rsaSelfRoundTripOk(): Boolean {
        val e = rsaEncrypt(CANARY) ?: return false
        return rsaDecrypt(e) == CANARY
    }

    // ============================================================================================
    // ★EC(PRIVATE_EC)签名/验签 —— 参照真 app KeystoreECManager 的 SHA256withECDSA。
    //   注意:EC 走 Signature(**真密钥相关**,no-op 不作用于签名)→ 签名值随密钥变。本次改动后
    //   EC 密钥每设备派生:
    //     1) 同会话/同设备 sign→verify 应通过(派生密钥 + 自签名证书可用、确定性跨重启稳定)。
    //     2) 跨设备/新机:公钥不同 → 旧签名验不过 = **预期**(per-device 反聚集);同设备 restore 应仍验过。
    // ============================================================================================
    private const val EC_ALIAS = "ghost_verify_xdev_ec"
    private const val EC_SIG_ALG = "SHA256withECDSA"

    private fun getOrCreateEcEntry(): KeyStore.PrivateKeyEntry {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(EC_ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let { return it }
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(EC_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build())
        kpg.generateKeyPair()
        val ks2 = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return ks2.getEntry(EC_ALIAS, null) as KeyStore.PrivateKeyEntry
    }

    /** EC 签名(当前设备私钥)→ Base64;失败 null。 */
    fun ecSign(data: String): String? = runCatching {
        val s = Signature.getInstance(EC_SIG_ALG)
        s.initSign(getOrCreateEcEntry().privateKey)
        s.update(data.toByteArray(Charsets.UTF_8))
        Base64.encodeToString(s.sign(), Base64.NO_WRAP)
    }.getOrNull()

    /** EC 验签(当前设备证书公钥)。 */
    fun ecVerify(data: String, sigB64: String): Boolean = runCatching {
        val s = Signature.getInstance(EC_SIG_ALG)
        s.initVerify(getOrCreateEcEntry().certificate.publicKey)
        s.update(data.toByteArray(Charsets.UTF_8))
        s.verify(Base64.decode(sigB64, Base64.NO_WRAP))
    }.getOrElse { false }

    /** 同会话 EC sign→verify 通过 ?(派生 EC 密钥 + 自签名证书基线能力)。 */
    fun ecSignVerifyOk(): Boolean {
        val sig = ecSign(CANARY) ?: return false
        return ecVerify(CANARY, sig)
    }

    // ============================================================================================
    // ★缓存优先(参照真 app SharedPrefUtils set/get:密文存 SharedPreferences、读时解缓存的密文)。
    //   密文随 ghost_verify 的 app 数据进备份 → 还原/新机后直接**解缓存的密文/验缓存的签名**
    //   = 无需依赖 SnapshotStore 显式带密文,一次采集即验证备份还原保真。
    //   缓存缺失(首次运行/被清)时**播种**:加密/签名 canary 存盘,本次即做基线往返。
    //   fromCache=true 的 ok 才是备份还原保真信号;false=本次刚播种(仅基线能力)。
    // ============================================================================================
    private const val CACHE_PREFS = "ghost_verify_crypto_cache"

    /** 缓存探针结果:来自缓存还是本次播种 + 解密/验签是否 ==canary。 */
    data class CacheProbe(val fromCache: Boolean, val ok: Boolean, val detail: String = "") {
        override fun toString(): String =
            "${if (fromCache) "cache" else "seeded"} ok=$ok" + if (detail.isNotEmpty()) " ($detail)" else ""
    }

    private fun cachePrefs(): android.content.SharedPreferences? =
        appContext?.getSharedPreferences(CACHE_PREFS, android.content.Context.MODE_PRIVATE)

    /** AES 缓存优先:有缓存(密文+IV)→解缓存(验备份还原);无→加密 canary 存盘并往返。 */
    fun aesCachedDecrypt(): CacheProbe {
        val p = cachePrefs() ?: return CacheProbe(false, false, "no ctx")
        val ct = p.getString("aes_ct", null); val iv = p.getString("aes_iv", null)
        if (ct != null && iv != null) {
            val dec = decrypt(ct, iv)
            return CacheProbe(true, dec == CANARY, if (dec == CANARY) "" else "got=$dec")
        }
        val e = encrypt(CANARY) ?: return CacheProbe(false, false, "encrypt fail")
        p.edit().putString("aes_ct", e.first).putString("aes_iv", e.second).apply()
        return CacheProbe(false, decrypt(e.first, e.second) == CANARY)
    }

    /** RSA 缓存优先:有缓存密文→解缓存;无→加密 canary 存盘并往返。 */
    fun rsaCachedDecrypt(): CacheProbe {
        val p = cachePrefs() ?: return CacheProbe(false, false, "no ctx")
        val ct = p.getString("rsa_ct", null)
        if (ct != null) {
            val dec = rsaDecrypt(ct)
            return CacheProbe(true, dec == CANARY, if (dec == CANARY) "" else "got=$dec")
        }
        val e = rsaEncrypt(CANARY) ?: return CacheProbe(false, false, "encrypt fail")
        p.edit().putString("rsa_ct", e).apply()
        return CacheProbe(false, rsaDecrypt(e) == CANARY)
    }

    /** EC 缓存优先:有缓存签名→验缓存签名(同设备/还原应过、跨新机应变);无→签 canary 存盘并验。 */
    fun ecCachedVerify(): CacheProbe {
        val p = cachePrefs() ?: return CacheProbe(false, false, "no ctx")
        val sig = p.getString("ec_sig", null)
        if (sig != null) return CacheProbe(true, ecVerify(CANARY, sig))
        val s = ecSign(CANARY) ?: return CacheProbe(false, false, "sign fail")
        p.edit().putString("ec_sig", s).apply()
        return CacheProbe(false, ecVerify(CANARY, s))
    }

    /** 清缓存(强制下次重新播种;调试用)。 */
    fun clearCryptoCache() { cachePrefs()?.edit()?.clear()?.apply() }

    /** RSA 公钥 SHA-256(聚集锚:每设备应不同、同设备 restore 应相同、跨新机应变)。 */
    fun rsaPubKeyHash(): String? =
        runCatching { sha256Hex(getOrCreateRsaEntry().certificate.publicKey.encoded) }.getOrNull()

    /** EC 公钥 SHA-256(聚集锚,同上)。 */
    fun ecPubKeyHash(): String? =
        runCatching { sha256Hex(getOrCreateEcEntry().certificate.publicKey.encoded) }.getOrNull()

    /**
     * getCertificate 与 getCertificateChain 一致性(验证本次新增的 getCertificateChain hook):
     * 真机非 attestation 密钥两者都非 null、链长=1;若 getCertificate 非 null 而 chain==null = 穿帮。
     * 返回如 "rsa cert=true chain=1 subject=CN=Fake | ec cert=true chain=1"。
     */
    fun certChainConsistency(): String = runCatching {
        getOrCreateRsaEntry(); getOrCreateEcEntry()  // 确保 alias 存在
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val rsaCert = ks.getCertificate(RSA_ALIAS)
        val rsaChain = ks.getCertificateChain(RSA_ALIAS)
        val ecCert = ks.getCertificate(EC_ALIAS)
        val ecChain = ks.getCertificateChain(EC_ALIAS)
        val subj = (rsaCert as? java.security.cert.X509Certificate)?.subjectX500Principal?.name ?: "?"
        "rsa cert=${rsaCert != null} chain=${rsaChain?.size} subject=$subj | " +
            "ec cert=${ecCert != null} chain=${ecChain?.size}"
    }.getOrElse { "err: ${it.message}" }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun String.unhex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
