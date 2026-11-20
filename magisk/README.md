# Magisk 证书注入脚本（Android 14 / 15 修复版）

这两个脚本是 [`AlwaysTrustUserCerts`](https://github.com/NVISOsecurity/AlwaysTrustUserCerts)
在上游基础上修复后的版本，用于把「用户证书」注入到 Conscrypt 实际读取的
`/apex/com.android.conscrypt/cacerts`，让 `targetSdk ≥ 24` 的应用（微信、Chrome 等）
也能信任抓包工具的 CA。

完整排查过程见 [`../docs/android15-ssl-capture-troubleshooting.md`](../docs/android15-ssl-capture-troubleshooting.md)。

## 为什么需要修复

上游 `mineketchup/AlwaysTrustUserCerts-Android-15-Fix` 有两个致命 bug：

```sh
# bug 1：$pid 未定义（应为 $zp），检查恒为 false，每 5 秒空转
if ! has_mount "$pid"; then

# bug 2：mount --rbind 缺挂载点参数，必然失败
mount --rbind $SYS_CERT_DIR
```

而且即使修好参数，`bind` 源用 `/system/etc/security/cacerts` 在 **app 进程视角**也只有
145 个证书（erofs 原始视图，不含 magisk overlay 的用户证书），所以必须改为模块目录。

## 文件说明

| 文件 | 作用 |
|---|---|
| `post-fs-data.sh` | 收集用户证书到模块目录，并 bind 到 `/apex/…/cacerts`（对 init/zygote 层） |
| `service.sh` | 每秒遍历 `uid ≥ 10000` 的 app 进程，逐进程注入（app 进程不继承 zygote 的挂载） |
| `module.prop` | 模块信息 |

## 部署

```bash
# 覆盖到已安装的模块目录
adb push post-fs-data.sh /data/local/tmp/
adb push service.sh /data/local/tmp/
adb shell "su -c 'cp /data/local/tmp/post-fs-data.sh /data/adb/modules/trustusercerts/ && \
                  cp /data/local/tmp/service.sh /data/adb/modules/trustusercerts/ && \
                  chmod 755 /data/adb/modules/trustusercerts/*.sh'"
adb reboot
```

## 验证

```bash
for p in $(ps -A | grep tencent.mm | awk '{print $2}'); do
  echo "pid=$p cnt=$(ls /proc/$p/root/apex/com.android.conscrypt/cacerts/ | wc -l)"
done
```

期望每个进程都是 `cnt=146`（145 系统证书 + 1 抓包 CA）。

## 设计要点

1. **源必须是模块目录**（`$MODDIR$SYS_CERT_DIR`），不是 `/system/etc/security/cacerts`
2. **`nsenter --target PID --mount`** 而不是 `--mount=/proc/PID/ns/mnt`，前者会 fork，对多线程进程更可靠
3. **轮询 1 秒**，只处理 `uid ≥ 10000` 的 app 进程，已注入的用 marker 文件跳过
4. **目录本身**也要 `chcon u:object_r:system_security_cacerts_file:s0`，否则 app 无法遍历

## 注意

- 抓包工具重新生成 CA 后，只需替换 `/data/misc/user/0/cacerts-added/<hash>.0`，重启即自动同步
- 证书文件名是 `subject_hash_old`（`openssl x509 -noout -subject_hash_old`）
- 上述方案对 **native 层**的 TLS 栈无效（如微信 ilink 内嵌 27 个根 CA），那类需要 Frida
