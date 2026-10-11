<#
                   Power By DXL
               The mkversion.sh same functions.
#>

param(
    [string]$Destination,
    [switch]$Short,
    [switch]$Force,
    [switch]$Undecided
)

# 默认 fork 名称（可自定义）
$fullgitinfo = "Iceman"
$clean = 2  # 2 = undecided, 1 = clean, 0 = dirty

# 获取脚本所在目录
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pm3Root = Join-Path $ScriptDir ".."

# 检查是否在 Git 工作目录中
$inGit = $false
$gitDir = Join-Path $pm3Root ".git"
if (Test-Path $gitDir -PathType Container) {
    # 尝试执行 git 命令
    $result = $null
    try {
        $result = git -C $pm3Root rev-parse --is-inside-work-tree 2>$null
    } catch { }
    if ($result -eq "true") {
        $inGit = $true
    }
}

if ($inGit) {
    try {
        $gitVersion = (git -C $pm3Root describe --dirty --always).Trim()
        $gitBranch = (git -C $pm3Root rev-parse --abbrev-ref HEAD).Trim()

        if ($Undecided) {
            if ($gitVersion -like "*-dirty") {
                $clean = 0
            } else {
                $clean = 1
            }
        }

        $fullgitinfo = "$fullgitinfo/$gitBranch/$gitVersion"

        # 使用 FORCED_DATE 或当前时间
        if ($env:FORCED_DATE -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$') {
            $ctime = $env:FORCED_DATE
        } else {
            $ctime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    } catch {
        $fullgitinfo = "$fullgitinfo/master/release (git_error)"
        $ctime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
} else {
    $fullgitinfo = "$fullgitinfo/master/release (no_git)"
    $readmePath = Join-Path $pm3Root "README.md"
    if (Test-Path $readmePath) {
        $dl_time = (Get-Item $readmePath).LastWriteTime
        $ctime = $dl_time.ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        $ctime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# --short 模式：只输出版本字符串
if ($Short) {
    if ($fullgitinfo.Length -gt 49) {
        $fullgitinfo = $fullgitinfo.Substring(0, 46) + "..."
    }
    Write-Output $fullgitinfo
    exit 0
}

# 检查是否提供了输出文件路径
if (-not $Destination) {
    Write-Error "Error: missing destination filename"
    exit 1
}

# 计算 ARM 源码的 SHA256 哈希（前 9 位）
$armSrc = Join-Path $pm3Root "armsrc"
$commonArm = Join-Path $pm3Root "common_arm"
$files = @()

if (Test-Path $armSrc) {
    $files += Get-ChildItem $armSrc | Where-Object {
        ($_.Extension -eq ".c" -or $_.Extension -eq ".h") -and
        $_.Name -notmatch "^(disabled|version_pm3|fpga_version_info)"
    }
}

if (Test-Path $commonArm) {
    $files += Get-ChildItem $commonArm | Where-Object {
        ($_.Extension -eq ".c" -or $_.Extension -eq ".h") -and
        $_.Name -notmatch "^(disabled|version_pm3|fpga_version_info)"
    }
}

$sha = "no sha256"
if ($files.Count -gt 0) {
    # 按文件名排序（确保一致性）
    $sortedFiles = $files | Sort-Object Name

    # 创建 SHA256 实例
    $sha256 = New-Object System.Security.Cryptography.SHA256Managed

    foreach ($file in $sortedFiles) {
        try {
            $content = [System.IO.File]::ReadAllBytes($file.FullName)
            $sha256.TransformBlock($content, 0, $content.Length, $null, 0) | Out-Null
        } catch {
            Write-Warning "Failed to read file: $($file.FullName)"
        }
    }

    # 完成哈希计算
    $sha256.TransformFinalBlock([byte[]]@(), 0, 0)
    $hashBytes = $sha256.Hash
    $shaHex = -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
    $sha = $shaHex.Substring(0, 9)
}

# 截断 fullgitinfo 到最多 49 字符
if ($fullgitinfo.Length -gt 49) {
    $fullgitinfo = $fullgitinfo.Substring(0, 46) + "..."
}

# 检查是否需要重新生成文件（避免无意义更新）
$regenerate = $true

if (-not $Force -and (Test-Path $Destination)) {
    try {
        $content = Get-Content $Destination -Raw

        # 提取 clean 状态（第13行附近）
        if ($content -match '^\s*(\d+)\s*$' -and $matches[1] -eq $clean) {
            # 提取 fullgitinfo（第14行）
            if ($content -match '^\s*"([^"]+)"\s*$' -and $matches[1] -eq $fullgitinfo) {
                # 提取 sha（第16行）
                if ($content -match '^\s*"([^"]+)"\s*$' -and $matches[1] -eq $sha) {
                    $regenerate = $false
                }
            }
        }
    } catch {
        $regenerate = $true
    }
}

# 仅当需要时才写入文件
if ($regenerate) {
    $tmpFile = "$Destination.tmp"
    $output = @"
#include "common.h"
/* Generated file, do not edit */
#ifndef ON_DEVICE
#define SECTVERSINFO
#else
#define SECTVERSINFO __attribute__((section(".version_information")))
#endif

const struct version_information_t SECTVERSINFO g_version_information = {
    VERSION_INFORMATION_MAGIC,
    1,
    1,
    $clean,
    "$fullgitinfo",
    "$ctime",
    "$sha"
};
"@

    try {
        $output | Out-File -FilePath $tmpFile -Encoding ASCII -Force
        Move-Item -Path $tmpFile -Destination $Destination -Force
    } catch {
        Write-Error "Failed to write version file: $_"
        if (Test-Path $tmpFile) {
            Remove-Item $tmpFile -Force
        }
        exit 1
    }
}

exit 0