package com.zx.Justmeplush.Hook;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * 只信任一切的 TLS 组件集合。
 *
 * 注意 getAcceptedIssuers 不能返回 null：OkHttp 4/5 的
 * AndroidCertificateChainCleaner 以及部分 Conscrypt 路径会对它做非空校验。
 */
public final class TrustAll {

    private static volatile X509TrustManager trustManager;
    private static volatile SSLSocketFactory socketFactory;
    private static volatile HostnameVerifier hostnameVerifier;

    private TrustAll() {
    }

    public static X509TrustManager trustManager() {
        X509TrustManager local = trustManager;
        if (local == null) {
            synchronized (TrustAll.class) {
                local = trustManager;
                if (local == null) {
                    local = new TrustManagerImpl();
                    trustManager = local;
                }
            }
        }
        return local;
    }

    public static SSLSocketFactory socketFactory() {
        SSLSocketFactory local = socketFactory;
        if (local == null) {
            synchronized (TrustAll.class) {
                local = socketFactory;
                if (local == null) {
                    local = createSocketFactory();
                    socketFactory = local;
                }
            }
        }
        return local;
    }

    private static SSLSocketFactory createSocketFactory() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trustManager()}, new SecureRandom());
            return context.getSocketFactory();
        } catch (NoSuchAlgorithmException e) {
            HookUtils.log("TrustAll: TLS not available, fallback to TLSv1.2");
        } catch (KeyManagementException e) {
            HookUtils.log("TrustAll: init failed: " + e);
        }
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            context.init(null, new TrustManager[]{trustManager()}, new SecureRandom());
            return context.getSocketFactory();
        } catch (Throwable t) {
            HookUtils.log("TrustAll: cannot create SSLSocketFactory: " + t);
            return null;
        }
    }

    public static HostnameVerifier hostnameVerifier() {
        HostnameVerifier local = hostnameVerifier;
        if (local == null) {
            synchronized (TrustAll.class) {
                local = hostnameVerifier;
                if (local == null) {
                    local = new AcceptAllHostnameVerifier();
                    hostnameVerifier = local;
                }
            }
        }
        return local;
    }

    /** 客户端证书（mTLS）场景下也安全：不碰 KeyManager。 */
    public static void initContextIgnoringServer(SSLContext context, javax.net.ssl.KeyManager[] keyManagers)
            throws KeyManagementException {
        context.init(keyManagers, new TrustManager[]{trustManager()}, new SecureRandom());
    }

    public static KeyStore emptyKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            return keyStore;
        } catch (Throwable t) {
            return null;
        }
    }

    public static final class TrustManagerImpl implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            // 不能返回空数组：微信 mmtls / OkHttp 的证书链清理会把它当作
            // 「可接受根证书集合」使用，空集合会直接导致握手失败。
            return SystemCertificates.acceptedIssuers();
        }
    }

    public static final class AcceptAllHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }
}
