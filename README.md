# JustTrustMeX

Xposed / LSPosed 模块：绕过 SSL Pinning，配合 Charles / Fiddler / mitmproxy / HttpCanary 抓 HTTPS 包。

**当前版本：4.0（Android 15 / API 35 适配版）**

## 重要设计约束（Android 14/15 上踩过的坑）

这一版最重要的工作不是"加 hook"，而是"删 hook"。旧思路里那些看起来最直接的绕过手段，
在 Android 14/15 上会让**整个应用的网络直接不可用**（微信表现为"无法打开页面"）：

| 不要做的事 | 后果 |
| --- | --- |
| 替换 `TrustManagerImpl.checkServerTrusted` / `checkTrusted` / `verifyChain` | 这些方法必须返回**补全后的证书链**（含可信根证书）。直接返回服务器发来的链（只有叶子 + 中间证书）会被 Chromium / 微信 WebView 判定链不完整，直接 `ERR_CERT_AUTHORITY_INVALID` |
| 替换 `X509TrustManagerExtensions.checkServerTrusted` | 同上，Chromium 的 `X509Util` 依赖它返回完整链 |
| 替换 `SSLContext.init` 且 `getAcceptedIssuers()` 返回空数组 | 微信 mmtls 会把这个列表当"可接受根证书集合"做校验，空集合直接拒绝连接 |
| 替换 `WebViewClient.onReceivedError` | 会把 WebView 的错误处理一起吞掉，页面白屏且无提示 |

**正确的分工**：

- 证书链校验交给系统 —— 把抓包工具的 CA 装进系统信任区（root）即可；
- 模块只负责绕过「额外的」pinning：OkHttp `CertificatePinner`、`OkHostnameVerifier`、
  `CertificateChainCleaner`、Apache `SSLSocketFactory`、WebView 的证书错误回调。

## 支持范围

| 层面 | 覆盖 |
| --- | --- |
| Android 版本 | 5.0 (API 21) ~ 15 (API 35) |
| OkHttp | 2.x（`com.squareup.okhttp`）、3.x、4.x、5.x（含 Kotlin 版） |
| 系统 TLS | 只绕过 NSC 的 pin-set（`checkPinnedCertificates`，方法存在时），不动证书链 |
| WebView | `WebViewClient` 本体与 app 自定义子类的 `onReceivedSslError` → `proceed()` |
| Apache HTTP | `org.apache.http`、`ch.boye.httpclientandroidlib`、`cz.msebera.android.httpclient` 的 `SSLSocketFactory` |
| 混淆 / 加固 | `ClassLoader.loadClass` 动态捕获 + 结构指纹识别 + dex 类名扫描兜底 |

## 这一版修掉的历史失效点

1. **OkHttp 指纹识别失效**
   `isClient()` 要求「final List 字段数 == 6」，`isBuilder()` 要求「List 字段 == 4 且 final == 2」。
   OkHttp 4.x/5.x 的字段数量早已不同，两个判断恒为 false → 证书相关 hook 一条都没挂上。
   新版改为按「内部类 `build()` 与外部类互相引用」的结构闭环识别，与字段数量、方法名都无关。

2. **`certificatePinner(...)` 返回 null** → 链式 `.build()` 直接 NPE。改为返回 `thisObject`。

3. **`check$okhttp` 从未生效**
   旧代码把 `"kotlin.jvm.functions.Function0"` 当 `Class` 传给 `findAndHookMethod`，必然抛异常被吞。
   新版按参数类型匹配，不依赖方法名（4.x 里 `check` 的 JVM 名其实是 `-deprecated_check`）。

4. **单参 `sslSocketFactory(SSLSocketFactory)` 会崩**
   OkHttp 4/5 的 `build()` 里有 `check(sslSocketFactory == null || x509TrustManager != null)`，
   而 `Platform.trustManager()` 在 Android 上取不到值。新版在 after 回调里补齐 builder 的
   `X509TrustManager` 字段，避免 `IllegalStateException`。

5. **类名发现失效**
   旧版 `DexFile.entries()` 只看一个 dex，且用 `Class.forName(..., true, ...)` 触发静态初始化。
   新版沿 ClassLoader 父链遍历全部 `BaseDexClassLoader`（含 `InMemoryDexClassLoader`），
   `dexFile` 为 null 时回退到 `Element.path` + `DexFile.loadDex`。

6. **`MODE_WORLD_READABLE`**
   Android 7 起用该模式创建 SharedPreferences 会抛 `SecurityException`，模块界面一点列表就崩。已改为 `MODE_PRIVATE`。

7. **构建系统**
   AGP 3.4.1 + Gradle 5.1.1 + compileSdk 22 在新版 Android Studio 里无法打开；
   `settings.gradle` 引用不存在的 `:test` 模块导致同步失败。
   现升级为 AGP 8.7.3 + Gradle 8.9 + compileSdk/targetSdk 35 + AndroidX。

## 构建

```bash
# JDK 17+，Android SDK Platform 35
./gradlew :app:assembleDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`

## 使用（必须配合系统证书）

1. 把抓包工具的 CA 证书装进**系统信任区**（不是用户证书，微信等 targetSdk 24+ 的应用不信任用户证书）：

   ```sh
   # 以 HttpCanary 为例，subject_hash_old = 87bc3517
   su -c "cp /path/HttpCanary.pem /apex/com.android.conscrypt/cacerts/87bc3517.0"
   su -c "chmod 644 /apex/com.android.conscrypt/cacerts/87bc3517.0"
   ```

   `/apex` 是 tmpfs，**重启会丢**。要做成 Magisk 模块在 `service.sh` 里重新复制。

2. 安装本模块，在 LSPosed 里启用并勾选目标应用；
3. 强制停止目标应用后重新打开；
4. 开始抓包。

看 LSPosed 日志确认生效，关键行形如：

```
[JustTrustMeX] load com.tencent.mm sdk=35 pid=19888
[JustTrustMeX] WebViewClient hooked: android.webkit.WebViewClient
[JustTrustMeX] Apache SSLSocketFactory hooked: org.apache.http.conn.ssl.SSLSocketFactory (1)
[JustTrustMeX] CertificatePinner hooked: okhttp3.CertificatePinner (3 methods)
[JustTrustMeX] OkHttp Builder hooked: okhttp3.OkHttpClient$Builder (4 methods)
```

## 已知限制（Xposed 层面无解）

以下场景的证书校验在 native 代码里完成，Java 层 hook 拦不到，需要 Frida 或改 so：

- **微信主网络 mars / mmtls**（native BoringSSL + 自有 pinning）
- **Cronet**（`libcronet.so`）
- **Flutter / dart:io**（`libflutter.so`）
- **阿里 MMTLS / 腾讯自研协议**
- 把证书 hash 写进 `.so` 做校验的加固应用
- 应用在 `SSLSession` 建立后自行比对 `getPeerCertificates()` 的逻辑

这类情况只能改用 Frida（hook `SSL_get_verify_result` / `X509_verify_cert`）或直接改包。
