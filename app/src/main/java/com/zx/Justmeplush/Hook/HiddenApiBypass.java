package com.zx.Justmeplush.Hook;

import java.lang.reflect.Method;

/**
 * 解除 ART 隐藏 API 反射限制。
 *
 * Android 9 起 BaseDexClassLoader.pathList / DexPathList.dexElements 都是隐藏 API，
 * LSPosed 默认会解除限制，但用户可能关掉这个开关；一旦关掉，枚举 dex 会直接抛
 * NoSuchFieldException，整个类名发现逻辑就废了。这里用 VMRuntime 自己再兜一层。
 */
public final class HiddenApiBypass {

    private static volatile boolean done = false;

    private HiddenApiBypass() {
    }

    public static void exempt() {
        if (done) {
            return;
        }
        done = true;
        try {
            Class<?> vmRuntime = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = vmRuntime.getDeclaredMethod("getRuntime");
            getRuntime.setAccessible(true);
            Object runtime = getRuntime.invoke(null);

            Method setExemptions = vmRuntime.getDeclaredMethod("setHiddenApiExemptions", String[].class);
            setExemptions.setAccessible(true);
            // "L" 是通配前缀，等于解除全部限制
            setExemptions.invoke(runtime, (Object) new String[]{"L"});
            HookUtils.log("hiddenapi exemptions installed");
        } catch (Throwable t) {
            HookUtils.log("hiddenapi exemptions skipped: " + t);
        }
    }
}
