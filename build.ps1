$ErrorActionPreference = 'Stop'

function log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogMessage
    )
    Write-Output ("[{0}] {1}" -f (Get-Date), $LogMessage)
}

if ( (Test-Path build) -ne "True" ) {
    mkdir build
}

log "Building..."

$id = Get-Content magiskModule/module.prop | Where-Object { $_ -match "id=" }
$id = $id.split('=')[1]
$version = Get-Content magiskModule/module.prop | Where-Object { $_ -match "version=" }
$version = $version.split('=')[1]
$versionCode = Get-Content magiskModule/module.prop | Where-Object { $_ -match "versionCode=" }
$versionCode = $versionCode.split('=')[1]
$zipFile = "${id}_${version}.zip"

# 下载最新工具链
# https://developer.android.com/ndk/downloads
# https://github.com/android/ndk/wiki

# 将 NDK 与其他构建系统配合使用
# https://developer.android.com/ndk/guides/other_build_systems
# https://android.googlesource.com/platform/ndk/+/master/docs/BuildSystemMaintainers.md
$NDK_PATH = "E:\NDK\android-ndk-r27"
$clang = "${NDK_PATH}/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe"

# Android 10+ Q+ SDK29+ (如果最低支持SDK是28或以下，则需要进行align_fix)
& $clang --target=aarch64-linux-android29 -std=c++20 -static -s -O2 -Wall -Iinclude src/*.cc -o build/$id
if ( -not $? ) {
    log "Compile fail"
    exit
}
log "Compile success"

# (如果最低支持SDK是28或以下，则需要进行align_fix)
# $res=./align_fix.exe build/$id
# if ( -not $? ) {
#     log "align_fix失败"
#     exit
# }
# log $res
# log "align_fix完成"

log "Packing zip..."
Copy-Item build/$id magiskModule/$id -force

& ./7za.exe a $zipFile ./magiskModule/* | Out-Null
if ( -not $? ) {
    log "Pack fail"
    exit
}
log "Packed: $zipFile"

# 从压缩包中删除 webroot/ksu.js 文件
& ./7za.exe d $zipFile webroot/ksu.js | Out-Null
if ( -not $? ) {
    log "Remove origin js from zip fail"
    exit
}
log "Removed webroot/ksu.js from $zipFile"

Remove-Item magiskModule/$id -Force

log "Done"