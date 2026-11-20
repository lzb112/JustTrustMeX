#!/system/bin/sh
MODDIR=${0%/*}
SYS_CERT_DIR=/system/etc/security/cacerts
APEX_CERT_DIR=/apex/com.android.conscrypt/cacerts

# bind 的源必须是「模块目录」：
#   - post-fs-data 阶段 /system 还是 erofs 原始内容（只有系统证书）
#   - 而模块目录此时已经 collect_user_certs 复制完成（系统 + 用户证书）
# 用 $SYS_CERT_DIR 作源是上游模块在 Android 15 失效的根本原因。
SRC_DIR="$MODDIR$SYS_CERT_DIR"

# 用来判断某个进程是否已经拿到我们的证书集
MARKER=87bc3517.0

log() {
    echo "$(date '+%m-%d %H:%M:%S ')" "$@" >> "$MODDIR/log.txt"
}

# 该进程的 /apex 是否已包含我们的证书
has_ours() {
    local pid="$1"
    [ -f "/proc/$pid/root$APEX_CERT_DIR/$MARKER" ]
}

inject() {
    local pid="$1"
    /system/bin/nsenter --target "$pid" --mount -- \
        /system/bin/mount --bind "$SRC_DIR" "$APEX_CERT_DIR" 2>/dev/null
}

# 只处理 app 进程（uid >= 10000），避免触碰系统进程
inject_apps_once() {
    for d in /proc/[0-9]*; do
        local pid=${d#/proc/}
        [ -r "$d/status" ] || continue

        # 跳过已有证书的
        has_ours "$pid" && continue

        # 必须有 apex 证书目录
        [ -d "$d/root$APEX_CERT_DIR" ] || continue

        local uid
        uid=$(/system/bin/awk '/^Uid:/{print $2; exit}' "$d/status" 2>/dev/null)
        [ -z "$uid" ] && continue
        [ "$uid" -lt 10000 ] 2>/dev/null && continue

        inject "$pid" && log "injected pid=$pid $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"
    done
}

monitor_apps() {
    (
        while true; do
            inject_apps_once
            /system/bin/sleep 1
        done
    )&
}

main() {
    log "MagiskTrustUserCerts - service.sh (module-dir source)"

    while [ "$(getprop sys.boot_completed)" != 1 ]; do
        /system/bin/sleep 1
    done

    if [ ! -d "$APEX_CERT_DIR" ]; then
        log "no apex cacerts dir, nothing to do"
        return
    fi

    if [ ! -d "$SRC_DIR" ]; then
        log "missing source dir $SRC_DIR"
        return
    fi

    # 目录与文件都要有正确的 SELinux 标签，否则 app 无法遍历/读取
    chcon u:object_r:system_security_cacerts_file:s0 "$SRC_DIR" 2>/dev/null
    chcon u:object_r:system_security_cacerts_file:s0 "$SRC_DIR"/* 2>/dev/null

    monitor_apps
}

main
