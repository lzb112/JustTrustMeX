package com.zx.Justmeplush.Hook;

import java.util.Collections;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexFile;

/**
 * dex 类名扫描。
 *
 * 相比原实现的关键改动：
 * 1. 沿 ClassLoader 父链遍历所有 BaseDexClassLoader，而不是只看当前 loader 的一个父类；
 * 2. Element.dexFile 取不到时回退到 Element.path + DexFile.loadDex（Android 14+ 部分场景 dexFile 为 null）；
 * 3. 支持 InMemoryDexClassLoader（加固壳、插件化、动态下发 dex 的 okhttp）；
 * 4. 按关键字过滤，避免把整个 app 的类名都拉进内存。
 */
public final class DexClassScanner {

    private DexClassScanner() {
    }

    public static Set<String> scan(ClassLoader loader, String... nameHints) {
        Set<String> result = new LinkedHashSet<String>();
        if (loader == null) {
            return result;
        }
        Set<ClassLoader> visited = Collections.newSetFromMap(new IdentityHashMap<ClassLoader, Boolean>());
        ClassLoader current = loader;
        while (current != null && visited.add(current)) {
            if (current instanceof BaseDexClassLoader) {
                scanBaseDex((BaseDexClassLoader) current, result, nameHints);
            }
            ClassLoader parent;
            try {
                parent = current.getParent();
            } catch (Throwable t) {
                parent = null;
            }
            if (parent == null) {
                break;
            }
            current = parent;
        }
        return result;
    }

    private static void scanBaseDex(BaseDexClassLoader loader, Set<String> out, String... nameHints) {
        Object pathList;
        try {
            pathList = HookUtils.readField(loader, "pathList");
        } catch (Throwable t) {
            return;
        }
        if (pathList == null) {
            return;
        }
        Object[] elements;
        try {
            Object value = HookUtils.readField(pathList, "dexElements");
            elements = (Object[]) value;
        } catch (Throwable t) {
            return;
        }
        if (elements == null) {
            return;
        }
        for (Object element : elements) {
            if (element == null) {
                continue;
            }
            DexFile dexFile = null;
            try {
                Object value = HookUtils.readField(element, "dexFile", "mDexFile");
                if (value instanceof DexFile) {
                    dexFile = (DexFile) value;
                }
            } catch (Throwable ignore) {
            }
            if (dexFile != null) {
                collect(dexFile, out, nameHints);
                continue;
            }
            // Android 14+ 上部分 Element 的 dexFile 为 null，退回用 path 重新打开
            String path = null;
            try {
                Object value = HookUtils.readField(element, "path", "mPath");
                if (value instanceof String) {
                    path = (String) value;
                } else if (value instanceof java.io.File) {
                    path = ((java.io.File) value).getPath();
                }
            } catch (Throwable ignore) {
            }
            if (path == null) {
                continue;
            }
            try {
                DexFile reopened = DexFile.loadDex(path, null, 0);
                if (reopened != null) {
                    collect(reopened, out, nameHints);
                }
            } catch (Throwable ignore) {
            }
        }
    }

    private static void collect(DexFile dexFile, Set<String> out, String... nameHints) {
        Enumeration<String> entries;
        try {
            entries = dexFile.entries();
        } catch (Throwable t) {
            return;
        }
        if (entries == null) {
            return;
        }
        while (true) {
            boolean hasNext;
            try {
                hasNext = entries.hasMoreElements();
            } catch (Throwable t) {
                return;
            }
            if (!hasNext) {
                return;
            }
            String name;
            try {
                name = entries.nextElement();
            } catch (Throwable t) {
                return;
            }
            if (name == null) {
                continue;
            }
            if (matches(name, nameHints)) {
                out.add(name);
            }
        }
    }

    private static boolean matches(String className, String... nameHints) {
        if (nameHints == null || nameHints.length == 0) {
            return true;
        }
        for (String hint : nameHints) {
            if (hint != null && className.contains(hint)) {
                return true;
            }
        }
        return false;
    }
}
