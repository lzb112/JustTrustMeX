# Android 15 上 SSL 抓包完全失效的排查与修复

> 记录一次真实排查：微信主界面正常，但**小程序内所有 HTTPS 请求全部失败**，HttpCanary 报
> `SSL证书不可信 / SSLV3_ALERT_CERTIFICATE_UNKNOWN`。最终定位到**三层相互叠加**的独立问题，
> 全部修复后才恢复。

---

## TL;DR

| # | 问题层 | 根因 | 修复 |
|---|---|---|---|
| 1 | 证书内容 | 抓包工具重新生成过 CA，系统里是旧的那张 | 重新安装当前 CA |
| 2 | Magisk 模块 | `mount --rbind` 少了挂载点参数，注入从未执行 | 修正参数与变量 |
| 3 | Android 15 隔离 | app 进程独立 mount namespace + erofs 原始视图 | 改为逐进程注入，且**源必须是模块目录** |

---

## 一、环境

| 项 | 值 |
|---|---|
| 设备 | OPPO PKX110 |
| 系统 | Android 15（API 35） |
| 微信 | 8.0.77（targetSdk 34，minSdk 24） |
| 抓包工具 | HttpCanary Premium 3.1.4 |
| Root | Magisk + LSPosed |
| 抓包证书模块 | AlwaysTrustUserCerts（mineketchup fork v1.3） |
| Pinning 绕过 | JustTrustMeX（本仓库，v4.0） |

---

## 二、现象

```
Read error: ssl=0x7d6857f9c8: Failure in SSL library, usually a protocol error
error:10000416:SSL routines:OPENSSL_internal:SSLV3_ALERT_CERTIFICATE_UNKNOWN
(external/boringssl/src/ssl/tls_record.cc:592 ...)
```

- 失败域名：`regionlbs.map.qq.com`、`htwkop.xiaojukeji.com`、`omgup.xiaojukeji.com`
- 微信主界面、聊天正常
- 小程序内页面打不开

**关键线索**：报错路径是 `external/boringssl`（native 层），说明校验发生在 JNI 之下，
纯 Java 层 Xposed hook 天然覆盖不到。

---

## 三、三层叠加的根因

### 3.1 第一层：CA 本身就不匹配

系统里装的证书和抓包工具当前使用的证书，**文件名一样，内容完全不是一张**。

| | 系统里那张 | HttpCanary 当前用的 |
|---|---|---|
| 路径 | `/system/etc/security/cacerts/87bc3517.0` | `…/cache/HttpCanary.pem` |
| 格式 | DER / 886 B | PEM / 1257 B |
| 序列号 | `0x2cd4ce290dd` | **`0x90565cfd7466`** |
| notBefore | 2025-06-24 | **2025-10-30 01:15** |
| 公钥指纹 | `da571720db08…` | `6b4889766914…` |

**为什么"看起来装好了"**：两张证书的 Subject 完全相同（`CN=HttpCanary Root CA`），
所以 `subject_hash_old` 都是 `87bc3517` —— 文件名撞在一起。文件在、大小对、SELinux 标签对、
Magisk 不报错，但验签必然失败。

```bash
# 判定方法：比对序列号而不是文件名
openssl x509 -noout -serial -subject -fingerprint /path/to/cert.pem
```

### 3.2 第二层：Magisk 模块的注入从未真正执行

`AlwaysTrustUserCerts`（mineketchup Android 15 fork）的 `service.sh` 里有两个 bug：

```sh
# bug 1：$pid 未定义（应为 $zp），导致检查恒为 false，每 5 秒空转
if ! has_mount "$pid"; then

# bug 2：mount --rbind 只给了一个参数，缺挂载点，必然失败
/system/bin/nsenter --mount=/proc/$zp/ns/mnt -- /bin/mount --rbind $SYS_CERT_DIR
```

对比上游 NVISOsecurity 原版，参数是完整的：

```sh
mount --rbind $SYS_CERT_DIR $APEX_CERT_DIR
```

**证据**：模块日志里几百条 `Injecting into child XXX` 反复出现，但设备上没有任何一次挂载生效。

### 3.3 第三层：Android 15 的 namespace 隔离（最难的一层）

即使参数修好，仍然失败。原因是 Android 15 上 app 进程的 mount namespace 是**独立重建**的：

```
init    mnt_ns=[4026533147]  bind=1
zygote  mnt_ns=[4026534794]  bind=1
wechat  mnt_ns=[4026536242]  bind=0     ← 全新 namespace
```

更致命的是**源本身就没有证书**。app 进程看到的 `/system` 是 **erofs 原始视图**，
magisk 的 overlay 根本没有传播过去：

| 视角 | `/system/etc/security/cacerts` | `/apex/…/cacerts` |
|---|---|---|
| root | 146（含用户证书） | 146 |
| **微信进程** | **145（无用户证书）** | **145（loop4 ext4 原始）** |

所以 `mount --bind /system/etc/security/cacerts /apex/…` 即使 `rc=0`，bind 过来的也是
**只有 145 个、没有抓包 CA 的目录**。

---

## 四、诊断方法（可复用）

### 4.1 看某个进程实际看到的证书

不需要 `nsenter`（对多线程进程会 setns 失败），用 `/proc/PID/root` 直接看：

```bash
P=$(pidof com.tencent.mm)
ls /proc/$P/root/apex/com.android.conscrypt/cacerts/ | wc -l
ls -l /proc/$P/root/apex/com.android.conscrypt/cacerts/87bc3517.0
md5sum /proc/$P/root/apex/com.android.conscrypt/cacerts/87bc3517.0
```

### 4.2 对比 namespace 关系

```bash
for p in 1 $(pidof zygote64) $(pidof com.tencent.mm); do
  echo "$p $(readlink /proc/$p/ns/mnt)"
  grep -c "cacerts" /proc/$p/mountinfo
done
```

namespace inode 不同 = 独立挂载空间，父进程的 bind 不会被继承。

### 4.3 静态分析 so 的证书策略

```bash
# 是否读系统证书目录
strings libxxx.so | grep -E "security/cacerts|conscrypt"

# 是否内嵌根证书
strings libxxx.so | grep -cE "Root Certificate Authority"

# 是否有 pinning
strings libxxx.so | grep -iE "pinning|X509_verify|SSL_get_verify"
```

本次结论：

| 库 | 证书策略 |
|---|---|
| `libssl.so` / `libcrypto.so`（微信自带） | OpenSSL 1.0.x 特征（GOST/CMS），**不含任何系统证书路径** |
| `libilink_network.so` | **硬编码 27 个公共根 CA**（DigiCert/GlobalSign/ISRG/GoDaddy…），无 pinning 标记 |
| `libxwebcore.so`（Chromium 内核） | 含 JNI 签名 `Lorg/chromium/net/AndroidCertVerifyResult;` → 会回调 Java 层验证器 |
| `libAdvanceP2P.so` / `libflutter.so` | 是仅有的两个含 `/system/etc/security/cacerts` 的库 |

---

## 五、最终方案

### 5.1 `post-fs-data.sh`：收集证书 + 给 init/zygote 层 bind

关键点：**bind 源用模块目录，不用 `$SYS_CERT_DIR`**。

```sh
link_apex_certs(){
    APEX_CERT_DIR=/apex/com.android.conscrypt/cacerts
    # post-fs-data 阶段 /system 仍是 erofs 原始内容（无用户证书）
    # 而模块目录此刻已 collect_user_certs 复制完成（系统 + 用户证书）
    SRC="$MODDIR$SYS_CERT_DIR"

    [ -d "$APEX_CERT_DIR" ] || { log "apex: dir missing"; return; }
    [ -d "$SRC" ] || { log "apex: source missing"; return; }

    # 目录本身也要有正确标签，否则 app 无法遍历
    chcon u:object_r:system_security_cacerts_file:s0 "$SRC" 2>>"$MODDIR/log.txt"

    if /system/bin/mount --bind "$SRC" "$APEX_CERT_DIR" 2>>"$MODDIR/log.txt"; then
        log "apex: bind OK, certs=$(/system/bin/ls "$APEX_CERT_DIR" | /system/bin/wc -l)"
    else
        log "apex: bind FAILED"
    fi
}
```

### 5.2 `service.sh`：逐进程注入（关键修复）

因为 app 进程不继承 zygote 的挂载，必须遍历注入：

```sh
SRC_DIR="$MODDIR$SYS_CERT_DIR"   # 模块目录（146 个，含用户证书）
MARKER=87bc3517.0                # 判断是否已注入

has_ours() { [ -f "/proc/$1/root$APEX_CERT_DIR/$MARKER" ]; }

inject() {
    /system/bin/nsenter --target "$1" --mount -- \
        /system/bin/mount --bind "$SRC_DIR" "$APEX_CERT_DIR" 2>/dev/null
}

inject_apps_once() {
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ -r "$d/status" ] || continue
        has_ours "$pid" && continue                    # 已有则跳过
        [ -d "$d/root$APEX_CERT_DIR" ] || continue     # 必须有 apex 目录
        uid=$(awk '/^Uid:/{print $2; exit}' "$d/status" 2>/dev/null)
        [ -z "$uid" ] && continue
        [ "$uid" -lt 10000 ] 2>/dev/null && continue   # 只处理 app 进程
        inject "$pid" && log "injected pid=$pid $(tr '\0' ' ' < /proc/$pid/cmdline)"
    done
}

monitor_apps() {
    ( while true; do inject_apps_once; /system/bin/sleep 1; done )&
}
```

三个要点：

1. **源是 `$MODDIR$SYS_CERT_DIR`**（模块目录），不是 `$SYS_CERT_DIR`
2. **`nsenter --target PID --mount`**（不是 `--mount=/proc/PID/ns/mnt`，前者会 fork，对多线程进程更可靠）
3. **轮询间隔 1 秒**，只挑 uid ≥ 10000 的 app 进程，每个进程只注入一次

---

## 六、验证

```bash
for p in $(ps -A | grep tencent.mm | awk '{print $2}'); do
  cnt=$(ls /proc/$p/root/apex/com.android.conscrypt/cacerts/ | wc -l)
  md5=$(md5sum /proc/$p/root/apex/com.android.conscrypt/cacerts/87bc3517.0 | cut -d' ' -f1)
  echo "pid=$p cnt=$cnt md5=$md5"
done
```

期望输出：

```
pid=11163 cnt=146 md5=aea5e6a389404be64406915618071cd5   com.tencent.mm
pid=15025 cnt=146 md5=aea5e6a389404be64406915618071cd5   :push
pid=16651 cnt=146 md5=aea5e6a389404be64406915618071cd5   :appbrand0
pid=16654 cnt=146 md5=aea5e6a389404be64406915618071cd5   :appbrand1
```

`146 = 145 系统证书 + 1 抓包 CA`，md5 与抓包工具当前 CA 一致即成功。

---

## 七、仍未解决的部分

以下走 **native 层**，装证书无效，需要 Frida hook（`X509_verify_cert` / `SSL_get_verify_result`）：

- **`libilink_network.so`** 内嵌 27 个公共根 CA，编译进 so，不认识任何系统证书
- **微信主网络 mars**（`libmarscomm.so` + 自带 OpenSSL）
- Cronet、Flutter / dart:io、阿里 MMTLS 等自建 TLS 栈
- 把证书 hash 写进 `.so` 做校验的加固应用

判断方法：如果某个域名的请求始终抓不到，而其他域名正常，基本就是走了内嵌 CA 的 native 栈。

---

## 八、命令速查

| 目的 | 命令 |
|---|---|
| 看进程实际证书 | `ls /proc/PID/root/apex/com.android.conscrypt/cacerts/ \| wc -l` |
| 比对证书序列号 | `openssl x509 -in cert.pem -noout -serial` |
| 算 subject hash（文件名） | `openssl x509 -in cert.pem -noout -subject_hash_old` |
| 看 namespace | `readlink /proc/PID/ns/mnt` |
| 看挂载来源 | `grep cacerts /proc/PID/mountinfo` |
| 跨 namespace 执行 | `nsenter --target PID --mount -- cmd` |
| so 证书策略 | `strings lib.so \| grep -cE "Root Certificate Authority"` |
| SELinux 标签 | `ls -Z /apex/com.android.conscrypt/cacerts/` |
| 正确标签 | `chcon u:object_r:system_security_cacerts_file:s0 <path>` |

---

## 九、经验教训

1. **证书"装好了"不等于装对了** —— 必须比对序列号或公钥指纹，不能只看文件名/大小
2. **native 报错要顺着路径找库** —— `external/boringssl` 说明问题在 JNI 之下，Java hook 无效
3. **Android 14+ 的 mount namespace 完全隔离** —— 任何"改一次全局生效"的假设都要验证
4. **`/proc/PID/root` 是看进程真实视图的最佳工具** —— 比 `nsenter` 可靠且无副作用
5. **社区模块不等于没有 bug** —— 那个 fork 名为 "Android 15 Fix"，核心 `mount` 参数却是错的
