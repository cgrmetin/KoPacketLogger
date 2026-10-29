# KoPacketLogger derleme betiği.
#
# cmake PATH'te olmadığı için Visual Studio 18 (2026) içindeki CMake aranır,
# ardından vcvars64.bat yüklenir. Kullanım:
#   .\build.ps1                 # Release derle
#   .\build.ps1 -Config Debug   # Debug derle
#   .\build.ps1 -Clean          # build dizinini sil, baştan yapılandır

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Config = 'Release',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $root 'build'

function Find-CMake {
    $cmd = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }

    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * -property installationPath
        if ($installPath) {
            $found = Join-Path $installPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
            if (Test-Path $found) { return $found }
        }
    }

    throw 'cmake bulunamadi. winget install Kitware.CMake ile kurun veya VS CMake bilesenini ekleyin.'
}

function Import-VcVars {
    # cl PATH'te yok; derleme ortamini vcvars64.bat ile kur.
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) { return }

    $vcvarsCandidates = @(
        'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
    )
    $vcvars = $vcvarsCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $vcvars) { throw 'vcvars64.bat bulunamadi.' }

    Write-Host "vcvars: $vcvars"
    $temp = Join-Path $env:TEMP ("vcvars_{0}.cmd" -f ([guid]::NewGuid().ToString('N')))
    try {
        $lines = @(
            "@echo off",
            "call `"$vcvars`" >nul",
            "set"
        )
        Set-Content -LiteralPath $temp -Value $lines -Encoding OEM

        $output = & cmd.exe /c "`"$temp`""
        foreach ($line in $output) {
            if ($line -match '^([^=]+)=(.*)$') {
                [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }

    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw 'vcvars64.bat kaynagi sonrasi cl.exe hala PATH te degil.'
    }
}

Push-Location $root
try {
    $cmake = Find-CMake
    Write-Host "cmake: $cmake"
    Import-VcVars

    if ($Clean -and (Test-Path $buildDir)) {
        Remove-Item -Recurse -Force $buildDir
    }

    $configureArgs = @(
        '-S', $root,
        '-B', $buildDir,
        '-G', 'Visual Studio 18 2026',
        '-A', 'x64',
        "-DCMAKE_CONFIGURATION_TYPES=$Config"
    )

    & $cmake @configureArgs
    if ($LASTEXITCODE -ne 0) { throw "cmake yapilandirmasi basarisiz (exit $LASTEXITCODE)." }

    & $cmake --build $buildDir --config $Config --parallel
    if ($LASTEXITCODE -ne 0) { throw "cmake derlemesi basarisiz (exit $LASTEXITCODE)." }

    Write-Host ''
    Write-Host "Tamamlandi: $Config -> $(Join-Path $buildDir 'out')"
}
finally {
    Pop-Location
}
