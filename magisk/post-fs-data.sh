# Certificates are collected during post-fs-data so that they are auto-mounted on top of /system for non-conscrypt devices
MODDIR=${0%/*}
SYS_CERT_DIR=/system/etc/security/cacerts

log() {
    echo "$(date '+%m-%d %H:%M:%S ')" "$@" >> $MODDIR/log.txt
}

collect_user_certs(){

    mkdir -p $MODDIR$SYS_CERT_DIR

    # Clean directory so that deleted certs actually disappear
    rm -rf $MODDIR$SYS_CERT_DIR/*

    log "Grabbing user certs"
    # Add the user-defined certs, looping over all available users
    for dir in /data/misc/user/*; do
        if [ -d "$dir/cacerts-added" ]; then
            for cert in "$dir/cacerts-added"/*; do
                cp "$cert" $MODDIR$SYS_CERT_DIR/
                log "Grabbing user cert: $(basename "$cert")"
            done
        fi
    done
}

# /apex/com.android.conscrypt/cacerts 是 Android 14+ Conscrypt 实际读取的路径。
# 它是 ext4 只读挂载，无法直接写；在 zygote 启动之前 bind 到 /system 的证书目录，
# 这样所有 app 进程都会继承，且以后只需要维护 /system 一份。
link_apex_certs(){
    APEX_CERT_DIR=/apex/com.android.conscrypt/cacerts
    # 注意：post-fs-data 阶段 /system/etc/security/cacerts 仍是 erofs 原始内容
    # （magisk 的 magic mount 此时尚未生效，里面只有系统证书、没有用户证书）。
    # 而本模块目录已经由 collect_user_certs 复制完成（系统 + 用户证书），
    # 所以 bind 源必须用模块目录，不能用 $SYS_CERT_DIR。
    SRC="$MODDIR$SYS_CERT_DIR"

    if [ ! -d "$APEX_CERT_DIR" ]; then
        log "apex: $APEX_CERT_DIR missing, skipped"
        return
    fi
    if [ ! -d "$SRC" ]; then
        log "apex: source $SRC missing, skipped"
        return
    fi

    # 目录本身也要有正确的 SELinux 标签，否则 app 无法遍历
    chcon u:object_r:system_security_cacerts_file:s0 "$SRC" 2>>"$MODDIR/log.txt"

    if /system/bin/mount --bind "$SRC" "$APEX_CERT_DIR" 2>>"$MODDIR/log.txt"; then
        log "apex: bind OK, certs=$(/system/bin/ls "$APEX_CERT_DIR" | /system/bin/wc -l)"
    else
        log "apex: bind FAILED"
    fi
}

main(){
    echo "" > $MODDIR/log.txt
    log "MagiskTrustUserCerts - post-fs-data.sh"

    collect_user_certs

    log "Grabbing /system certs"
    cp $SYS_CERT_DIR/* $MODDIR$SYS_CERT_DIR
    
    chcon u:object_r:system_security_cacerts_file:s0 $SYS_CERT_DIR/*
    chcon u:object_r:system_security_cacerts_file:s0 $MODDIR$SYS_CERT_DIR/*

    link_apex_certs
}
main