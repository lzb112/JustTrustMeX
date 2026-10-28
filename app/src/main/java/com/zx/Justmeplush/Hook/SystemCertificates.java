package com.zx.Justmeplush.Hook;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * 读取系统根证书。
 *
 * 为什么需要它：
 * 自定义 TrustManager 如果 getAcceptedIssuers() 返回空数组，表面上"信任一切"很方便，
 * 但很多库（微信 mmtls、部分 Conscrypt 路径、OkHttp 的证书链清理）会把这个列表当作
 * 「可接受的根证书集合」去校验，空集合会直接判定失败，表现为整个网络不可用。
 *
 * 所以这里返回真实的系统根证书列表，保证：
 *   - checkServerTrusted 仍然是空实现（不校验，绕过 pinning）；
 *   - getAcceptedIssuers 看起来完全正常（不触发上层的一致性检查）。
 */
final class SystemCertificates {

    private static volatile X509Certificate[] cache;

    private SystemCertificates() {
    }

    static X509Certificate[] acceptedIssuers() {
        X509Certificate[] local = cache;
        if (local != null) {
            return local;
        }
        synchronized (SystemCertificates.class) {
            local = cache;
            if (local != null) {
                return local;
            }
            List<X509Certificate> list = new ArrayList<X509Certificate>();
            try {
                KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
                keyStore.load(null, null);
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases != null && aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    try {
                        Object cert = keyStore.getCertificate(alias);
                        if (cert instanceof X509Certificate) {
                            list.add((X509Certificate) cert);
                        }
                    } catch (Throwable ignore) {
                    }
                }
            } catch (Throwable t) {
                HookUtils.log("load system CAs failed: " + t);
            }
            local = list.toArray(new X509Certificate[0]);
            cache = local;
            HookUtils.log("system CAs loaded=" + local.length);
            return local;
        }
    }
}
