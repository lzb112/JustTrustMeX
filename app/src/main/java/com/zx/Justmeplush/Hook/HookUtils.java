package com.zx.Justmeplush.Hook;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;

/**
 * Hook 基础设施。
 *
 * 所有反射 / hook 操作都做异常隔离：单点失败只记录日志，不影响其它 hook 点。
 * 原实现里大量 findAndHookMethod 直接抛出，是一个失败就整段崩掉，这里改成逐点安全执行。
 */
public final class HookUtils {

    private HookUtils() {
    }

    public static void log(String msg) {
        try {
            XposedBridge.log("[JustTrustMeX] " + msg);
        } catch (Throwable ignore) {
        }
    }

    public static void log(Throwable t) {
        try {
            XposedBridge.log("[JustTrustMeX] " + (t == null ? "null" : t.toString()));
        } catch (Throwable ignore) {
        }
    }

    // ---------------------------------------------------------------- 类加载

    /** 按类名找类，找不到返回 null（不会抛异常）。 */
    public static Class<?> findClass(String name, ClassLoader loader) {
        if (name == null || name.length() == 0) {
            return null;
        }
        if (loader != null) {
            try {
                return Class.forName(name, false, loader);
            } catch (Throwable ignore) {
            }
        }
        try {
            return Class.forName(name, false, HookUtils.class.getClassLoader());
        } catch (Throwable ignore) {
        }
        try {
            return Class.forName(name);
        } catch (Throwable ignore) {
        }
        return null;
    }

    /** 类存在性判断，不触发初始化。 */
    public static boolean classExists(String name, ClassLoader loader) {
        return findClass(name, loader) != null;
    }

    // ---------------------------------------------------------------- 方法枚举

    public static List<Method> declaredMethods(Class<?> clazz) {
        if (clazz == null) {
            return new ArrayList<Method>();
        }
        try {
            Method[] arr = clazz.getDeclaredMethods();
            if (arr == null) {
                return new ArrayList<Method>();
            }
            return new ArrayList<Method>(Arrays.asList(arr));
        } catch (Throwable t) {
            return new ArrayList<Method>();
        }
    }

    public static List<Field> declaredFields(Class<?> clazz) {
        if (clazz == null) {
            return new ArrayList<Field>();
        }
        try {
            Field[] arr = clazz.getDeclaredFields();
            if (arr == null) {
                return new ArrayList<Field>();
            }
            return new ArrayList<Field>(Arrays.asList(arr));
        } catch (Throwable t) {
            return new ArrayList<Field>();
        }
    }

    /** 按名字找声明方法（只找本类声明，不找父类）。 */
    public static List<Method> methodsNamed(Class<?> clazz, String name) {
        List<Method> out = new ArrayList<Method>();
        for (Method m : declaredMethods(clazz)) {
            if (m.getName().equals(name)) {
                out.add(m);
            }
        }
        return out;
    }

    /** 参数个数 + 每个参数类型都能被给定类型接收（用于不依赖方法名的签名匹配）。 */
    public static boolean paramsMatch(Method m, Class<?>... expected) {
        Class<?>[] actual = m.getParameterTypes();
        if (actual.length != expected.length) {
            return false;
        }
        for (int i = 0; i < actual.length; i++) {
            if (expected[i] != null && !expected[i].isAssignableFrom(actual[i])) {
                return false;
            }
        }
        return true;
    }

    // ---------------------------------------------------------------- hook 封装

    public interface BeforeAction {
        void before(XC_MethodHook.MethodHookParam param) throws Throwable;
    }

    public interface AfterAction {
        void after(XC_MethodHook.MethodHookParam param) throws Throwable;
    }

    public interface ResultProvider {
        Object get(XC_MethodHook.MethodHookParam param) throws Throwable;
    }

    public static boolean hook(Method method, XC_MethodHook callback) {
        if (method == null) {
            return false;
        }
        try {
            XposedBridge.hookMethod(method, callback);
            return true;
        } catch (Throwable t) {
            log("hook method failed: " + method + " -> " + t);
            return false;
        }
    }

    public static boolean before(Method method, final BeforeAction action) {
        return hook(method, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                action.before(param);
            }
        });
    }

    public static boolean after(Method method, final AfterAction action) {
        return hook(method, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                action.after(param);
            }
        });
    }

    /** 让方法直接返回 provider 给的值，不执行原实现。 */
    public static boolean replace(Method method, final ResultProvider provider) {
        return hook(method, new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return provider.get(param);
            }
        });
    }

    /** 按方法名批量 hook，返回命中数量。 */
    public static int hookByName(Class<?> clazz, String name, XC_MethodHook callback) {
        int count = 0;
        for (Method m : methodsNamed(clazz, name)) {
            if (hook(m, callback)) {
                count++;
            }
        }
        return count;
    }

    /** 按方法名批量替换，返回命中数量。 */
    public static int replaceByName(Class<?> clazz, String name, ResultProvider provider) {
        int count = 0;
        for (Method m : methodsNamed(clazz, name)) {
            if (replace(m, provider)) {
                count++;
            }
        }
        return count;
    }

    // ---------------------------------------------------------------- 反射取值

    /**
     * 读字段值，按候选名依次尝试，并向上遍历父类。
     * 用于兼容不同 Android 版本 / 不同混淆状态下的字段名（dexFile / mDexFile、path / mPath）。
     */
    public static Object readField(Object target, String... names) {
        if (target == null) {
            return null;
        }
        Class<?> clazz;
        Object instance;
        if (target instanceof Class) {
            clazz = (Class<?>) target;
            instance = null;
        } else {
            clazz = target.getClass();
            instance = target;
        }
        for (String name : names) {
            Class<?> walk = clazz;
            while (walk != null) {
                try {
                    Field f = walk.getDeclaredField(name);
                    f.setAccessible(true);
                    return f.get(instance);
                } catch (Throwable ignore) {
                    walk = walk.getSuperclass();
                }
            }
        }
        return null;
    }

    public static boolean hasField(Class<?> clazz, String... names) {
        if (clazz == null) {
            return false;
        }
        for (String name : names) {
            Class<?> walk = clazz;
            while (walk != null) {
                try {
                    walk.getDeclaredField(name);
                    return true;
                } catch (Throwable ignore) {
                    walk = walk.getSuperclass();
                }
            }
        }
        return false;
    }

    /** 供 hook 内部用：安全取方法参数。 */
    public static Object arg(XC_MethodHook.MethodHookParam param, int index) {
        if (param == null || param.args == null || index < 0 || index >= param.args.length) {
            return null;
        }
        return param.args[index];
    }

    public static boolean isStatic(Method m) {
        try {
            return java.lang.reflect.Modifier.isStatic(m.getModifiers());
        } catch (Throwable t) {
            return false;
        }
    }
}
