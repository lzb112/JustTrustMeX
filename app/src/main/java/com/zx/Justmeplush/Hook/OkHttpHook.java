package com.zx.Justmeplush.Hook;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.XC_MethodHook;

/**
 * OkHttp 2.x / 3.x / 4.x / 5.x 的证书校验绕过。
 *
 * 旧实现的根本问题：用「字段数量等于某个魔法值」去认 OkHttpClient / Builder，
 * 但 OkHttp 4.x 起字段数量早就变了（Builder 有 6 个 List 字段，不是 4 个），
 * 于是 isClient()/isBuilder() 永远返回 false，证书相关的 hook 一条都没挂上。
 *
 * 新实现的三条路径：
 *  A. 已知类名直连（未混淆，覆盖 99% 的开源 app），按「参数类型」匹配方法，不依赖方法名；
 *  B. ClassLoader.loadClass 动态捕获（混淆 / 加固 / 动态下发 dex），拿到 Class 对象后按结构指纹识别；
 *  C. dex 类名扫描补漏（类名保留但用独立 ClassLoader 加载的场景）。
 *
 * 识别特征全部基于「类型结构」而不是名字与字段数量常量：
 *  - OkHttpClient：内部类有 build() 返回外部类，且自身有 >=3 个 List 字段；
 *  - Builder：有 build() 返回外部类，且外部类的内部类包含自己；
 *  - CertificatePinner：有静态字段类型指向自身（DEFAULT），且有 (String, List) 方法；
 *  - CertificateChainCleaner：实现类的 clean(List, String) 直接放行；
 *  - OkHostnameVerifier：实现 HostnameVerifier 且带 INSTANCE 静态自引用。
 */
public final class OkHttpHook {

    private static final Set<Class<?>> hookedPinners = newSafeSet();
    private static final Set<Class<?>> hookedVerifiers = newSafeSet();
    private static final Set<Class<?>> hookedBuilders = newSafeSet();
    private static final Set<Class<?>> hookedCleaners = newSafeSet();
    private static final Set<Class<?>> examined = newSafeSet();

    private static final AtomicBoolean dexScanned = new AtomicBoolean(false);

    private OkHttpHook() {
    }

    private static Set<Class<?>> newSafeSet() {
        return Collections.synchronizedSet(
                Collections.newSetFromMap(new WeakHashMap<Class<?>, Boolean>()));
    }

    // ------------------------------------------------------------ 入口 A：已知类名

    public static void installKnown(ClassLoader loader) {
        if (loader == null) {
            return;
        }
        Class<?> builder;
        Class<?> pinner;
        Class<?> verifier;
        Class<?> cleaner;

        // ---------- OkHttp 3.x / 4.x / 5.x ----------
        pinner = HookUtils.findClass("okhttp3.CertificatePinner", loader);
        if (pinner != null) {
            hookCertificatePinner(pinner);
        }
        verifier = HookUtils.findClass("okhttp3.internal.tls.OkHostnameVerifier", loader);
        if (verifier != null) {
            hookHostnameVerifier(verifier);
        }
        builder = HookUtils.findClass("okhttp3.OkHttpClient$Builder", loader);
        if (builder != null) {
            hookBuilder(builder);
        }
        cleaner = HookUtils.findClass("okhttp3.internal.tls.CertificateChainCleaner", loader);
        if (cleaner != null) {
            hookCleanerAndSubclasses(cleaner, loader);
        }
        for (String name : new String[]{
                "okhttp3.internal.tls.BasicCertificateChainCleaner",
                "okhttp3.internal.platform.android.AndroidCertificateChainCleaner",
                "okhttp3.internal.platform.android.AndroidCertificateChainCleaner$Companion",
        }) {
            Class<?> c = HookUtils.findClass(name, loader);
            if (c != null) {
                hookCleaner(c);
            }
        }

        // ---------- OkHttp 2.x（com.squareup.okhttp） ----------
        pinner = HookUtils.findClass("com.squareup.okhttp.CertificatePinner", loader);
        if (pinner != null) {
            hookCertificatePinner(pinner);
        }
        verifier = HookUtils.findClass("com.squareup.okhttp.internal.tls.OkHostnameVerifier", loader);
        if (verifier != null) {
            hookHostnameVerifier(verifier);
        }
        builder = HookUtils.findClass("com.squareup.okhttp.OkHttpClient$Builder", loader);
        if (builder != null) {
            hookBuilder(builder);
        }
        Class<?> legacyClient = HookUtils.findClass("com.squareup.okhttp.OkHttpClient", loader);
        if (legacyClient != null) {
            // OkHttp 2.x 直接把 SSLSocketFactory / HostnameVerifier 存在 Client 上
            hookBuilderInternals(legacyClient);
        }
    }

    // ------------------------------------------------------------ 入口 B：dex 补漏

    /** 供外部（JustHook）在 Application 创建后触发一次全量 dex 扫描补漏。 */
    public static void installFromDex(ClassLoader loader) {
        if (loader == null || !dexScanned.compareAndSet(false, true)) {
            return;
        }
        try {
            Set<String> names = DexClassScanner.scan(loader, "okhttp", "squareup", "CertificatePinner");
            int count = 0;
            for (String name : names) {
                Class<?> c = HookUtils.findClass(name, loader);
                if (c == null) {
                    continue;
                }
                if (examineLoadedClass(c)) {
                    count++;
                }
            }
            HookUtils.log("dex scan: candidates=" + names.size() + ", hooked=" + count);
        } catch (Throwable t) {
            HookUtils.log("dex scan failed: " + t);
        }
    }

    // ------------------------------------------------------------ 结构指纹识别

    /**
     * @return true 表示这个类上挂了新的 hook
     */
    public static boolean examineLoadedClass(Class<?> clazz) {
        if (clazz == null || clazz.isPrimitive() || clazz.isArray() || clazz.isEnum()) {
            return false;
        }
        if (!examined.add(clazz)) {
            return false;
        }
        String name = clazz.getName();
        // 系统类走结构判断没有意义，直接跳过（conscrypt 由 SystemTlsHook 处理）
        if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("sun.")
                || name.startsWith("android.") || name.startsWith("androidx.")
                || name.startsWith("kotlin.") || name.startsWith("kotlinx.")
                || name.startsWith("dalvik.")) {
            return false;
        }

        boolean hooked = false;
        try {
            // 1) HostnameVerifier 实现（OkHostnameVerifier 及其混淆版本）
            if (HostnameVerifier.class.isAssignableFrom(clazz) && !clazz.isInterface()) {
                if (hookHostnameVerifier(clazz)) {
                    hooked = true;
                }
            }

            // 2) CertificateChainCleaner 实现
            Class<?> cleanerType = HookUtils.findClass(
                    "okhttp3.internal.tls.CertificateChainCleaner", clazz.getClassLoader());
            if (cleanerType != null && cleanerType.isAssignableFrom(clazz) && cleanerType != clazz) {
                if (hookCleaner(clazz)) {
                    hooked = true;
                }
            }

            // 3) 字段特征：List / Set / 静态自引用
            List<Field> fields = HookUtils.declaredFields(clazz);
            int listFields = 0;
            int setFields = 0;
            boolean selfStatic = false;
            for (Field f : fields) {
                Class<?> type = f.getType();
                try {
                    if (List.class.isAssignableFrom(type)) {
                        listFields++;
                    } else if (Set.class.isAssignableFrom(type)) {
                        setFields++;
                    }
                    if (Modifier.isStatic(f.getModifiers()) && type == clazz) {
                        selfStatic = true;
                    }
                } catch (Throwable ignore) {
                }
            }

            // 4) CertificatePinner：静态 DEFAULT + Set 字段
            if (selfStatic && setFields >= 1) {
                if (hookCertificatePinner(clazz)) {
                    hooked = true;
                }
            }

            // 5) OkHttpClient / Builder：>=3 个 List 字段，再确认 build()/newBuilder() 关系
            if (listFields >= 3) {
                if (hookOkHttpClientIfMatches(clazz)) {
                    hooked = true;
                }
            }
        } catch (Throwable ignore) {
        }
        return hooked;
    }

    // ------------------------------------------------------------ 具体 hook

    /** CertificatePinner：把本类里所有 (String, ...) 入口全部吞掉。 */
    private static boolean hookCertificatePinner(Class<?> clazz) {
        if (clazz == null || !hookedPinners.add(clazz)) {
            return false;
        }
        int count = 0;
        for (Method m : HookUtils.declaredMethods(clazz)) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length < 2 || p[0] != String.class) {
                continue;
            }
            // check / -deprecated_check / check$okhttp 都是 (String, 第二参数)
            if (List.class.isAssignableFrom(p[1])
                    || "kotlin.jvm.functions.Function0".equals(p[1].getName())
                    || p[1] == byte[].class) {
                if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                    @Override
                    public Object get(XC_MethodHook.MethodHookParam param) {
                        return null;
                    }
                })) {
                    count++;
                }
            }
        }
        if (count > 0) {
            HookUtils.log("CertificatePinner hooked: " + clazz.getName() + " (" + count + " methods)");
        }
        return count > 0;
    }

    /** OkHostnameVerifier：verify(String, SSLSession) 和 verify(String, X509Certificate) 恒为 true。 */
    private static boolean hookHostnameVerifier(Class<?> clazz) {
        if (clazz == null || !hookedVerifiers.add(clazz)) {
            return false;
        }
        int count = 0;
        for (Method m : HookUtils.declaredMethods(clazz)) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length != 2 || p[0] != String.class) {
                continue;
            }
            if (javax.net.ssl.SSLSession.class.isAssignableFrom(p[1])
                    || java.security.cert.X509Certificate.class.isAssignableFrom(p[1])) {
                if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                    @Override
                    public Object get(XC_MethodHook.MethodHookParam param) {
                        return Boolean.TRUE;
                    }
                })) {
                    count++;
                }
            }
        }
        if (count > 0) {
            HookUtils.log("HostnameVerifier hooked: " + clazz.getName() + " (" + count + " methods)");
        }
        return count > 0;
    }

    /** CertificateChainCleaner：clean(List, String) 原样返回。 */
    private static boolean hookCleaner(Class<?> clazz) {
        if (clazz == null || clazz.isInterface() || !hookedCleaners.add(clazz)) {
            return false;
        }
        int count = 0;
        for (Method m : HookUtils.declaredMethods(clazz)) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length == 2 && List.class.isAssignableFrom(p[0]) && p[1] == String.class) {
                if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                    @Override
                    public Object get(XC_MethodHook.MethodHookParam param) {
                        return param.args[0];
                    }
                })) {
                    count++;
                }
            }
        }
        if (count > 0) {
            HookUtils.log("CertificateChainCleaner hooked: " + clazz.getName());
        }
        return count > 0;
    }

    private static void hookCleanerAndSubclasses(Class<?> cleaner, ClassLoader loader) {
        hookCleaner(cleaner);
        for (String name : new String[]{
                "okhttp3.internal.tls.BasicCertificateChainCleaner",
                "okhttp3.internal.platform.android.AndroidCertificateChainCleaner",
        }) {
            Class<?> c = HookUtils.findClass(name, loader);
            if (c != null && cleaner.isAssignableFrom(c)) {
                hookCleaner(c);
            }
        }
    }

    /** OkHttpClient$Builder（含 OkHttp 2.x 的 Client 本体）：替换 sslSocketFactory / hostnameVerifier / certificatePinner。 */
    private static boolean hookBuilder(Class<?> clazz) {
        if (clazz == null || !hookedBuilders.add(clazz)) {
            return false;
        }
        int count = hookBuilderInternals(clazz);
        if (count > 0) {
            HookUtils.log("OkHttp Builder hooked: " + clazz.getName() + " (" + count + " methods)");
        }
        return count > 0;
    }

    private static int hookBuilderInternals(final Class<?> clazz) {
        int count = 0;
        for (final Method m : HookUtils.declaredMethods(clazz)) {
            Class<?>[] p;
            try {
                p = m.getParameterTypes();
            } catch (Throwable t) {
                continue;
            }

            // sslSocketFactory(SSLSocketFactory, X509TrustManager)
            if (p.length == 2
                    && SSLSocketFactory.class.isAssignableFrom(p[0])
                    && X509TrustManager.class.isAssignableFrom(p[1])) {
                if (HookUtils.before(m, new HookUtils.BeforeAction() {
                    @Override
                    public void before(XC_MethodHook.MethodHookParam param) {
                        SSLSocketFactory factory = TrustAll.socketFactory();
                        if (factory != null) {
                            param.args[0] = factory;
                        }
                        param.args[1] = TrustAll.trustManager();
                    }
                })) {
                    count++;
                }
                continue;
            }

            // sslSocketFactory(SSLSocketFactory)
            //
            // 注意：OkHttp 4.x/5.x 的 build() 里有
            //   check(sslSocketFactory != null || x509TrustManager != null)
            // 而 Platform.trustManager(SSLSocketFactory) 在 Android 上取不到
            // sun.security.ssl.SSLContextImpl，会返回 null。只换 factory 不补
            // trustManager 会让 builder.build() 直接抛 IllegalStateException。
            if (p.length == 1 && SSLSocketFactory.class.isAssignableFrom(p[0])) {
                boolean hookedBefore = HookUtils.before(m, new HookUtils.BeforeAction() {
                    @Override
                    public void before(XC_MethodHook.MethodHookParam param) {
                        SSLSocketFactory factory = TrustAll.socketFactory();
                        if (factory != null) {
                            param.args[0] = factory;
                        }
                    }
                });
                boolean hookedAfter = HookUtils.after(m, new HookUtils.AfterAction() {
                    @Override
                    public void after(XC_MethodHook.MethodHookParam param) {
                        fillTrustManagerField(param.thisObject);
                    }
                });
                if (hookedBefore || hookedAfter) {
                    count++;
                }
                continue;
            }

            // hostnameVerifier(HostnameVerifier)
            if (p.length == 1 && HostnameVerifier.class.isAssignableFrom(p[0])) {
                if (HookUtils.before(m, new HookUtils.BeforeAction() {
                    @Override
                    public void before(XC_MethodHook.MethodHookParam param) {
                        param.args[0] = TrustAll.hostnameVerifier();
                    }
                })) {
                    count++;
                }
                continue;
            }

            // certificatePinner(CertificatePinner)
            if (p.length == 1 && looksLikeCertificatePinner(p[0])) {
                // 老实现这里 return null，链式调用 .build() 会直接 NPE。builder 必须返回自身。
                if (HookUtils.replace(m, new HookUtils.ResultProvider() {
                    @Override
                    public Object get(XC_MethodHook.MethodHookParam param) {
                        return param.thisObject;
                    }
                })) {
                    count++;
                }
            }
        }
        return count;
    }

    /** 把 builder 里类型为 X509TrustManager 且仍为 null 的字段补成信任所有的实现。 */
    private static void fillTrustManagerField(Object builder) {
        if (builder == null) {
            return;
        }
        for (Field f : HookUtils.declaredFields(builder.getClass())) {
            if (!X509TrustManager.class.isAssignableFrom(f.getType())) {
                continue;
            }
            try {
                f.setAccessible(true);
                if (f.get(builder) == null) {
                    f.set(builder, TrustAll.trustManager());
                }
            } catch (Throwable ignore) {
            }
        }
    }

    /** OkHttpClient 本体本身不需要额外 hook，Builder 与 CertificatePinner 已覆盖全部访问点。 */

    private static boolean hookOkHttpClientIfMatches(Class<?> clazz) {
        // Builder：存在 0 参数方法，其返回类型的内部类又包含自己。
        // 这里刻意不看方法名（混淆后 build() 会被改名），只靠类型闭环判断。
        for (Method m : HookUtils.declaredMethods(clazz)) {
            if (m.getParameterTypes().length != 0) {
                continue;
            }
            Class<?> ret;
            try {
                ret = m.getReturnType();
            } catch (Throwable t) {
                continue;
            }
            if (ret == void.class || ret.isPrimitive() || ret == clazz) {
                continue;
            }
            if (containsDeclaredClass(ret, clazz)) {
                return hookBuilder(clazz);
            }
        }
        // Client：内部类里有 0 参数方法返回自己（即 newBuilder() -> Builder）
        for (Class<?> inner : safeDeclaredClasses(clazz)) {
            for (Method m : HookUtils.declaredMethods(inner)) {
                if (m.getParameterTypes().length == 0 && m.getReturnType() == clazz) {
                    return hookBuilder(inner);
                }
            }
        }
        return false;
    }

    private static boolean containsDeclaredClass(Class<?> owner, Class<?> target) {
        for (Class<?> c : safeDeclaredClasses(owner)) {
            if (c == target) {
                return true;
            }
        }
        return false;
    }

    private static Class<?>[] safeDeclaredClasses(Class<?> clazz) {
        try {
            Class<?>[] arr = clazz.getDeclaredClasses();
            return arr == null ? new Class<?>[0] : arr;
        } catch (Throwable t) {
            return new Class<?>[0];
        }
    }

    private static boolean looksLikeCertificatePinner(Class<?> candidate) {
        if (candidate == null || candidate == String.class || candidate.isPrimitive()) {
            return false;
        }
        boolean selfStatic = false;
        for (Field f : HookUtils.declaredFields(candidate)) {
            if (Modifier.isStatic(f.getModifiers()) && f.getType() == candidate) {
                selfStatic = true;
                break;
            }
        }
        if (!selfStatic) {
            return false;
        }
        for (Method m : HookUtils.declaredMethods(candidate)) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length == 2 && p[0] == String.class && List.class.isAssignableFrom(p[1])) {
                return true;
            }
        }
        return false;
    }

    /** 供 JustHook 判断是否还需要启用类加载监听。 */
    public static boolean hasEffectiveHook() {
        return !hookedPinners.isEmpty() || !hookedBuilders.isEmpty();
    }

    public static String describe() {
        List<String> parts = new ArrayList<String>();
        parts.add("pinner=" + hookedPinners.size());
        parts.add("hostname=" + hookedVerifiers.size());
        parts.add("builder=" + hookedBuilders.size());
        parts.add("cleaner=" + hookedCleaners.size());
        return parts.toString();
    }
}
