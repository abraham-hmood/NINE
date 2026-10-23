# One-shot on-device verification of the light-shell flow (run after adb reconnect).
param(
    [string]$DeviceId = "",
    [string]$Apk = "$env:TEMP\nine-build\app\outputs\apk\debug\app-debug.apk"
)
$ErrorActionPreference = "SilentlyContinue"
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$sel = @()
if ($DeviceId -ne "") { $sel = @("-s", $DeviceId) }
$d = & $adb devices
if ($DeviceId -eq "") {
    $DeviceId = ($d | Select-String "_tcp\s+device$").ToString().Split([char[]]@(" "`n"))[0].Trim()
    if ($DeviceId -eq "") { Write-Output "no device online"; exit 1 }
    $sel = @("-s", $DeviceId)
}
$sc = { param($out) cmd.exe /c "adb -s $DeviceId exec-out screencap -p > %TEMP%\nine-screen.png"; Add-Type -AssemblyName System.Drawing; $img = [System.Drawing.Image]::FromFile("$env:TEMP\nine-screen.png"); $bmp = New-Object System.Drawing.Bitmap(540, 1170); $g = [System.Drawing.Graphics]::FromImage($bmp); $g.DrawImage($img, 0, 0, 540, 1170); $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Jpeg); $g.Dispose(); $img.Dispose(); $bmp.Dispose() }

Write-Output "== install =="
& $adb @sel install -r $Apk 2>&1 | Select-Object -Last 1

Write-Output "== launch + clear logs =="
& $adb @sel logcat -c
& $adb @sel shell am start -n com.nine.dbt/.MainActivity | Out-Null
Start-Sleep -Seconds 3
& $adb @sel shell dumpsys activity activities | Select-String topResumedActivity | Select-Object -First 1

Write-Output "== drive relink (library -> select hello -> relink) =="
& $adb @sel shell input tap 234 2062; Start-Sleep -Seconds 2
& $adb @sel shell input tap 149 2085; Start-Sleep -Seconds 2
& $adb @sel shell input tap 724 1822; Start-Sleep -Seconds 8
& $adb @sel shell input keyevent KEYCODE_BACK; Start-Sleep -Seconds 1   # dismiss possible SAF dialog
& $adb @sel shell input keyevent KEYCODE_BACK; Start-Sleep -Seconds 1

Write-Output "== logcat (shell/sign) =="
& $adb @sel logcat -d | Select-String -Pattern 'light shell|sign:|NINE Shell|PackageInstaller' | Select-Object -Last 20

Write-Output "== shells dir =="
& $adb @sel shell ls -la /sdcard/NINE/shells
