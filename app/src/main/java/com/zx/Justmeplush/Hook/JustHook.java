package com.zx.Justmeplush.Hook;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Process;

import java.lang.reflect.Method;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 模块入口。
 *
 * 旧版的问题不是"少了几个 hook 点"，而是整套识别与挂载逻辑都建立在 Android 7 时代
 * 的 OkHttp 3.0 字段布局上，Android 14/15 + OkHttp 4/5 下会静默失效（不报错，但一个
 * 证书校验点都没挂上）。这一版按「先系统层、再框架层、最后动态补挂」三层顺序执行：
 *
 *   1. SystemTlsHook：Conscrypt / JSSE / WebView / X509TrustManagerExtensions / Apache，
 *      这一层不依赖任何第三方库的类名，先保证系统级 TLS 一定被绕过；
 *   2. OkHttpHook.installKnown：已知类名直连，覆盖未混淆的 OkHttp 2/3/4/5；
 *   3. ClassLoader.loadClass 监听 + Application 创建后的延迟重试：覆盖混淆、加固壳、
 *      动态下发 dex、以及 app 自己写的 WebViewClient 子类。
 */
public class JustHook implements IXposedHookLoadPackage {

    private static final String MODULE_PACKAGE = "com.lzb.Justmeplush";

    /** 类加载监听窗口：只覆盖启动阶段，避免长期影响 100% 类加载路径。 */
    private static final long CLASS_LOAD_WINDOW_MS = 30_000L;

    private static volatile boolean classLoadListenerInstalled = false;
    private static volatile long classLoadDeadline = 0L;

    private static volatile Context sContext;
    private static volatile ClassLoader sLoader;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null || lpparam.packageName == null) {
            return;
        }
        if (MODULE_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        HiddenApiBypass.exempt();

        final ClassLoader appLoader = lpparam.classLoader;
        sLoader = appLoader;
        HookUtils.log("load " + lpparam.packageName
                + " sdk=" + Build.VERSION.SDK_INT
                + " pid=" + Process.myPid());

        // ---------- 第一层：系统 TLS（不依赖第三方库） ----------
        try {
            SystemTlsHook.install(appLoader);
        } catch (Throwable t) {
            HookUtils.log(t);
        }

        // ---------- 第二层：OkHttp 已知类名 ----------
        try {
            OkHttpHook.installKnown(appLoader);
        } catch (Throwable t) {
            HookUtils.log(t);
        }

        // ---------- 特例：闲鱼/淘系 spdy ----------
        try {
            hookTaobaoSpdy(lpparam);
        } catch (Throwable t) {
            HookUtils.log("taobao hook skipped: " + t);
        }

        // ---------- 第三层：动态补挂 ----------
        try {
            installClassLoadListener(appLoader);
        } catch (Throwable t) {
            HookUtils.log(t);
        }
        try {
            installApplicationHooks(lpparam);
        } catch (Throwable t) {
            HookUtils.log(t);
        }
    }

    // ------------------------------------------------------------ 类加载监听

    private static void installClassLoadListener(final ClassLoader appLoader) {
        if (classLoadListenerInstalled) {
            return;
        }
        classLoadListenerInstalled = true;
        classLoadDeadline = System.currentTimeMillis() + CLASS_LOAD_WINDOW_MS;

        XC_MethodHook listener = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                try {
                    if (System.currentTimeMillis() > classLoadDeadline) {
                        return;
                    }
                    Object result = param.getResult();
                    if (!(result instanceof Class)) {
                        return;
                    }
                    Class<?> clazz = (Class<?>) result;
                    try {
                        OkHttpHook.examineLoadedClass(clazz);
                    } catch (Throwable ignore) {
                    }
                    try {
                        SystemTlsHook.examineLoadedClass(clazz);
                    } catch (Throwable ignore) {
                    }
                } catch (Throwable ignore) {
                }
            }
        };

        int hooked = 0;
        for (Method m : HookUtils.methodsNamed(ClassLoader.class, "loadClass")) {
            Class<?>[] p = m.getParameterTypes();
            if (p.length == 2 && p[1] == boolean.class) {
                // loadClass(String, boolean) 覆盖了 Class.forName 在内的全部路径
                if (HookUtils.hook(m, listener)) {
                    hooked++;
                }
            }
        }
        HookUtils.log("ClassLoader.loadClass listener hooked=" + hooked);
    }

    // ------------------------------------------------------------ Application 时机

    private void installApplicationHooks(final XC_LoadPackage.LoadPackageParam lpparam) {
        int attach = HookUtils.hookByName(Application.class, "attach", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object context = HookUtils.arg(param, 0);
                if (context instanceof Context) {
                    sContext = (Context) context;
                    sLoader = ((Context) context).getClassLoader();
                }
            }
        });

        int onCreate = HookUtils.hookByName(Application.class, "onCreate", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                onApplicationReady(lpparam.classLoader);
            }
        });

        // 有些加固框架会替换 Application / 跳过 attach，用 Instrumentation 兜底
        Class<?> instrumentation = HookUtils.findClass("android.app.Instrumentation", lpparam.classLoader);
        int instrumented = 0;
        if (instrumentation != null) {
            for (Method m : HookUtils.methodsNamed(instrumentation, "callApplicationOnCreate")) {
                if (HookUtils.after(m, new HookUtils.AfterAction() {
                    @Override
                    public void after(XC_MethodHook.MethodHookParam param) {
                        onApplicationReady(lpparam.classLoader);
                    }
                })) {
                    instrumented++;
                }
            }
        }
        HookUtils.log("Application hooks: attach=" + attach + " onCreate=" + onCreate + " instrumentation=" + instrumented);
    }

    private static volatile boolean readyScheduled = false;

    private static void onApplicationReady(final ClassLoader loader) {
        final ClassLoader effective = loader != null ? loader : sLoader;
        if (effective == null) {
            return;
        }
        if (readyScheduled) {
            // 只做一次立即补挂，不重复起线程
            try {
                OkHttpHook.installKnown(effective);
            } catch (Throwable ignore) {
            }
            return;
        }
        readyScheduled = true;

        try {
            OkHttpHook.installKnown(effective);
        } catch (Throwable ignore) {
        }

        Thread retry = new Thread(new Runnable() {
            @Override
            public void run() {
                // 加固壳 / 插件化会在 onCreate 之后异步解密并加载真实 dex，这里分三次补挂
                long[] delays = {300L, 1500L, 4000L};
                for (int i = 0; i < delays.length; i++) {
                    try {
                        Thread.sleep(delays[i]);
                    } catch (InterruptedException e) {
                        return;
                    }
                    try {
                        OkHttpHook.installKnown(effective);
                        OkHttpHook.installFromDex(effective);
                    } catch (Throwable t) {
                        HookUtils.log(t);
                    }
                }
                HookUtils.log("retry finished: " + OkHttpHook.describe());
            }
        }, "JustTrustMeX-retry");
        retry.setDaemon(true);
        retry.start();
    }

    // ------------------------------------------------------------ 淘系 spdy

    private void hookTaobaoSpdy(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!"com.taobao.idlefish".equals(lpparam.packageName)
                && !"com.taobao.taobao".equals(lpparam.packageName)) {
            return;
        }
        Class<?> clazz = HookUtils.findClass("mtopsdk.mtop.global.SwitchConfig", lpparam.classLoader);
        if (clazz == null) {
            return;
        }
        for (Method m : HookUtils.methodsNamed(clazz, "isGlobalSpdySwitchOpen")) {
            HookUtils.replace(m, new HookUtils.ResultProvider() {
                @Override
                public Object get(XC_MethodHook.MethodHookParam param) {
                    return Boolean.FALSE;
                }
            });
        }
        HookUtils.log("taobao spdy disabled");
    }
}
