package com.zx.Justmeplush.Hook;

import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;

import java.io.IOException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.XC_MethodHook;

/**
 * 系统 TLS 层绕过。
 *
 * Android 7 之后证书校验的真实入口是 Conscrypt 的 TrustManagerImpl，而旧实现只挂了
 * 三个固定签名（X509Certificate[]、String、SSLSession）的 checkServerTrusted。
 * Android 14/15 上 Conscrypt 把校验拆成了 checkTrusted / checkTrustedRecursive /
 * verifyChain / checkPinnedCertificates 一整条链，并且新增了带 ocsp/tlsSct 参数的
 * checkServerTrusted 变体，只挂那三个旧签名根本拦不全。
 *
 * 这里改成「按方法名全量替换」，并对返回值按声明的返回类型生成合法值：
 *  - void            -> null
 *  - List<X509Certificate> -> 原样返回输入的证书链
 * 这样无论 Conscrypt 内部怎么重构，只要方法名还在就拦得住。
 */
public final class SystemTlsHook {

    private static final Set<Class<?>> hookedWebViewClients = Collections.synchronizedSet(
            Collections.newSetFromMap(new WeakHashMap<Class<?>, Boolean>()));

    private static final Set<Class<?>> hookedCleaners = Collections.synchronizedSet(
            Collections.newSetFromMap(new WeakHashMap<Class<?>, Boolean>()));

    private static volatile boolean installed = false;

    private SystemTlsHook() {
    }

    public static void install(ClassLoader loader) {
        if (installed) {
            return;
        }
        installed = true;

        // 最终形态：完全不触碰 TLS 证书链。
        //
        // 踩过的两个坑（都会让微信「无法打开页面」）：
        //  1) 整体替换 TrustManagerImpl.checkServerTrusted / verifyChain，
        //     必须返回「补全后的证书链」，直接返回服务器链会被判定缺根证书；
        //  2) 替换 SSLContext.init 后 getAcceptedIssuers() 返回空数组，
        //     微信 mmtls 会拿这个列表做根证书校验，空集合直接拒绝连接。
        //
        // 所以这里只做三件事，全部与证书链无关：
        //   - 绕过 NSC 的 pin-set（方法存在时）
        //   - WebView 的证书错误自动 proceed
        //   - Apache HTTP 的 SSLSocketFactory 放行
        // 证书链校验交给系统，抓包工具 CA 装进系统信任区即可。
        hookTrustManagerPin(loader);
        hookWebViewClient(loader);
        hookApache(loader);
    }

    /** 由类加载监听回调：app 自己写的 WebViewClient 子类 / 自定义 TrustManager 在这里补挂。 */
    public static boolean examineLoadedClass(Class<?> clazz) {
        if (clazz == null || clazz.isPrimitive() || clazz.isArray() || clazz.isInterface()) {
            return false;
        }
        boolean hooked = false;
        try {
            Class<?> webViewClient = HookUtils.findClass("android.webkit.WebViewClient", null);
            if (webViewClient != null && webViewClient.isAssignableFrom(clazz) && clazz != webViewClient) {
                if (hookWebViewClientSubclass(clazz)) {
                    hooked = true;
                }
            }
        } catch (Throwable ignore) {
        }
        return hooked;
    }

    // ------------------------------------------------------------ Conscrypt

    /**
     * 只绕过 Network Security Config 的 pin-set 校验，不动证书链本身。
     *
     * checkPinnedCertificates 返回 void，替换成空实现是安全的：
     * 调用它的 checkTrusted 之后仍会正常走系统证书链验证，
     * 所以「正常证书」不受影响，「额外 pin」被跳过。
     */
    private static void hookTrustManagerPin(ClassLoader loader) {
        Class<?> impl = HookUtils.findClass("com.android.org.conscrypt.TrustManagerImpl", loader);
        if (impl == null) {
            HookUtils.log("TrustManagerImpl not found (non-Conscrypt runtime?)");
            return;
        }
        int count = 0;
        for (Method m : HookUtils.methodsNamed(impl, "checkPinnedCertificates")) {
            Class<?> returnType;
            try {
                returnType = m.getReturnType();
            } catch (Throwable t) {
                continue;
            }
            if (returnType == void.class && HookUtils.replace(m, NULL_PROVIDER)) {
                count++;
            }
        }
        HookUtils.log("conscrypt pin bypass hooked=" + count);
    }

    private static final HookUtils.ResultProvider NULL_PROVIDER = new HookUtils.ResultProvider() {
        @Override
        public Object get(XC_MethodHook.MethodHookParam param) {
            return null;
        }
    };

    private static final HookUtils.ResultProvider CHAIN_LIST_PROVIDER = new HookUtils.ResultProvider() {
        @Override
        public Object get(XC_MethodHook.MethodHookParam param) {
            X509Certificate[] chain = findCertificateChain(param.args);
            if (chain != null) {
                return new ArrayList<X509Certificate>(Arrays.asList(chain));
            }
            return new ArrayList<X509Certificate>();
        }
    };

    private static X509Certificate[] findCertificateChain(Object[] args) {
        if (args == null) {
            return null;
        }
        for (Object arg : args) {
            if (arg instanceof X509Certificate[]) {
                return (X509Certificate[]) arg;
            }
        }
        return null;
    }

    private static void hookTrustManagerFactory(ClassLoader loader) {
        Class<?> factory = HookUtils.findClass("javax.net.ssl.TrustManagerFactory", loader);
        if (factory == null) {
            return;
        }
        for (Method m : HookUtils.methodsNamed(factory, "getTrustManagers")) {
            HookUtils.after(m, new HookUtils.AfterAction() {
                @Override
                public void after(XC_MethodHook.MethodHookParam param) {
                    param.setResult(new TrustManager[]{TrustAll.trustManager()});
                }
            });
        }
    }

    // ------------------------------------------------------------ JSSE

    private static void hookSslContext(ClassLoader loader) {
        Class<?> context = HookUtils.findClass("javax.net.ssl.SSLContext", loader);
        if (context == null) {
            return;
        }
        int count = 0;
        for (Method m : HookUtils.methodsNamed(context, "init")) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length != 3) {
                continue;
            }
            if (KeyManager[].class != p[0] || TrustManager[].class != p[1] || SecureRandom.class != p[2]) {
                continue;
            }
            if (HookUtils.before(m, new HookUtils.BeforeAction() {
                @Override
                public void before(XC_MethodHook.MethodHookParam param) {
                    // 只换 TrustManager，保留 KeyManager：否则 mTLS（客户端证书）会被打断
                    param.args[1] = new TrustManager[]{TrustAll.trustManager()};
                }
            })) {
                count++;
            }
        }
        HookUtils.log("SSLContext.init hooked=" + count);
    }

    private static void hookHttpsUrlConnection(ClassLoader loader) {
        Class<?> connection = HookUtils.findClass("javax.net.ssl.HttpsURLConnection", loader);
        if (connection == null) {
            return;
        }
        for (Method m : HookUtils.methodsNamed(connection, "setDefaultHostnameVerifier")) {
            HookUtils.before(m, new HookUtils.BeforeAction() {
                @Override
                public void before(XC_MethodHook.MethodHookParam param) {
                    param.args[0] = TrustAll.hostnameVerifier();
                }
            });
        }
        for (Method m : HookUtils.methodsNamed(connection, "setHostnameVerifier")) {
            HookUtils.before(m, new HookUtils.BeforeAction() {
                @Override
                public void before(XC_MethodHook.MethodHookParam param) {
                    param.args[0] = TrustAll.hostnameVerifier();
                }
            });
        }
        for (Method m : HookUtils.methodsNamed(connection, "setDefaultSSLSocketFactory")) {
            HookUtils.before(m, new HookUtils.BeforeAction() {
                @Override
                public void before(XC_MethodHook.MethodHookParam param) {
                    SSLSocketFactory sf = TrustAll.socketFactory();
                    if (sf != null) {
                        param.args[0] = sf;
                    }
                }
            });
        }
        for (Method m : HookUtils.methodsNamed(connection, "setSSLSocketFactory")) {
            HookUtils.before(m, new HookUtils.BeforeAction() {
                @Override
                public void before(XC_MethodHook.MethodHookParam param) {
                    SSLSocketFactory sf = TrustAll.socketFactory();
                    if (sf != null) {
                        param.args[0] = sf;
                    }
                }
            });
        }
    }

    // ------------------------------------------------------------ WebView

    private static void hookWebViewClient(ClassLoader loader) {
        Class<?> client = HookUtils.findClass("android.webkit.WebViewClient", loader);
        if (client == null) {
            return;
        }
        hookWebViewClientSubclass(client);
    }

    private static boolean hookWebViewClientSubclass(Class<?> client) {
        if (client == null || !hookedWebViewClients.add(client)) {
            return false;
        }
        int count = 0;
        for (Method m : HookUtils.methodsNamed(client, "onReceivedSslError")) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length != 3) {
                continue;
            }
            if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                @Override
                public Object get(XC_MethodHook.MethodHookParam param) {
                    Object handler = HookUtils.arg(param, 1);
                    if (handler instanceof SslErrorHandler) {
                        try {
                            ((SslErrorHandler) handler).proceed();
                        } catch (Throwable ignore) {
                        }
                    }
                    return null;
                }
            })) {
                count++;
            }
        }
        if (count > 0) {
            HookUtils.log("WebViewClient hooked: " + client.getName());
        }
        return count > 0;
    }

    // ------------------------------------------------------------ WebView 证书扩展

    private static void hookX509TrustManagerExtensions(ClassLoader loader) {
        Class<?> ext = HookUtils.findClass("android.net.http.X509TrustManagerExtensions", loader);
        if (ext == null) {
            return;
        }
        int count = 0;
        for (Method m : HookUtils.methodsNamed(ext, "checkServerTrusted")) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length == 3
                    && p[0] == X509Certificate[].class
                    && p[1] == String.class
                    && p[2] == String.class) {
                if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                    @Override
                    public Object get(XC_MethodHook.MethodHookParam param) {
                        Object chain = HookUtils.arg(param, 0);
                        if (chain instanceof X509Certificate[]) {
                            return new ArrayList<X509Certificate>(Arrays.asList((X509Certificate[]) chain));
                        }
                        return new ArrayList<X509Certificate>();
                    }
                })) {
                    count++;
                }
            }
        }
        HookUtils.log("X509TrustManagerExtensions hooked=" + count);
    }

    // ------------------------------------------------------------ Apache HTTP（app 自带）

    private static void hookApache(ClassLoader loader) {
        String[] factories = {
                "org.apache.http.conn.ssl.SSLSocketFactory",
                "ch.boye.httpclientandroidlib.conn.ssl.SSLSocketFactory",
                "cz.msebera.android.httpclient.conn.ssl.SSLSocketFactory",
        };
        for (String name : factories) {
            Class<?> factory = HookUtils.findClass(name, loader);
            if (factory == null) {
                continue;
            }
            int count = 0;
            for (Method m : HookUtils.methodsNamed(factory, "createSocket")) {
                Class<?>[] p = m.getParameterTypes();
                if (p.length == 4
                        && p[0] == Socket.class
                        && p[1] == String.class
                        && p[2] == int.class
                        && p[3] == boolean.class) {
                    if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                        @Override
                        public Object get(XC_MethodHook.MethodHookParam param) {
                            Socket raw = (Socket) HookUtils.arg(param, 0);
                            String host = (String) HookUtils.arg(param, 1);
                            int port = (Integer) HookUtils.arg(param, 2);
                            boolean autoClose = (Boolean) HookUtils.arg(param, 3);
                            SSLSocketFactory sf = TrustAll.socketFactory();
                            if (sf == null) {
                                return raw;
                            }
                            try {
                                return sf.createSocket(raw, host, port, autoClose);
                            } catch (IOException e) {
                                return raw;
                            }
                        }
                    })) {
                        count++;
                    }
                }
            }
            for (Method m : HookUtils.methodsNamed(factory, "isSecure")) {
                HookUtils.replace(m, new HookUtils.ResultProvider() {
                    @Override
                    public Object get(XC_MethodHook.MethodHookParam param) {
                        return Boolean.TRUE;
                    }
                });
            }
            HookUtils.log("Apache SSLSocketFactory hooked: " + name + " (" + count + ")");
        }
    }

    /** 供外部读取当前是否已挂过系统层。 */
    public static boolean isInstalled() {
        return installed;
    }

    public static List<String> describe() {
        List<String> out = new ArrayList<String>();
        out.add("WebViewClient subclasses: " + hookedWebViewClients.size());
        return out;
    }
}
