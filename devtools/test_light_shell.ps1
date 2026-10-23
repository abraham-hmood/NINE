# One-shot on-device verification of the light-shell flow (run after adb reconnect).
$ErrorActionPreference = "Continue"
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$devLine = (& $adb devices) | Where-Object { $_ -match "_tcp\s+device$" } | Select-Object -First 1
if (-not $devLine) { Write-Output "no device online"; exit 1 }
$DeviceId = ($devLine -split "\s+")[0]
Write-Output "device: $DeviceId"
$s = @("-s", $DeviceId)

function Shot($tag) {
    $png = "$env:TEMP\nine-screen.png"
    $jpg = "$env:TEMP\nine-screen-$tag.jpg"
    cmd.exe /c "adb -s $DeviceId exec-out screencap -p > $env:TEMP\nine-screen.png" | Out-Null
    Add-Type -AssemblyName System.Drawing
    $img = [System.Drawing.Image]::FromFile($png)
    $bmp = New-Object System.Drawing.Bitmap(540, 1170)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.DrawImage($img, 0, 0, 540, 1170)
    $bmp.Save($jpg, [System.Drawing.Imaging.ImageFormat]::Jpeg)
    $g.Dispose(); $img.Dispose(); $bmp.Dispose()
    Write-Output "shot: $jpg"
}

Write-Output "== wake + launch =="
& $adb @s shell input keyevent KEYCODE_WAKEUP | Out-Null
Start-Sleep -Seconds 1
Shot "wake"
& $adb @s install -r "$env:TEMP\nine-build\app\outputs\apk\debug\app-debug.apk" 2>&1 | Select-Object -Last 1
& $adb @s logcat -c
& $adb @s shell am start -n com.nine.dbt/.MainActivity | Out-Null
Start-Sleep -Seconds 3
& $adb @s shell dumpsys activity activities | Select-String topResumedActivity | Select-Object -First 1
Shot "launched"

Write-Output "== drive relink =="
& $adb @s shell input tap 234 2062; Start-Sleep -Seconds 2
& $adb @s shell input tap 149 2085; Start-Sleep -Seconds 2
Shot "selected"
& $adb @s shell input tap 724 1822; Start-Sleep -Seconds 8
Shot "afterrelink"
& $adb @s shell input keyevent KEYCODE_BACK; Start-Sleep -Seconds 1
& $adb @s shell input keyevent KEYCODE_BACK; Start-Sleep -Seconds 1

Write-Output "== logcat =="
& $adb @s logcat -d | Select-String -Pattern "light shell|sign:|NINE Shell" | Select-Object -Last 12

Write-Output "== shells dir =="
& $adb @s shell ls -la /sdcard/NINE/shells
