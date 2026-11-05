$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$roots = @(ConvertFrom-Json $env:BUILDFIT_PROBE_ROOTS)
$owner = [uint32]$env:BUILDFIT_PROBE_OWNER
$values = [Collections.Generic.HashSet[string]]::new()
$errors = [Collections.Generic.List[string]]::new()
$busy = $false
$homes = [Collections.Generic.HashSet[string]]::new()
function Add-Value($value) {
    if ($null -ne $value) {
        foreach ($text in @($value)) { if ($text -is [string]) { [void]$values.Add([Environment]::ExpandEnvironmentVariables($text)) } }
    }
}
try {
    foreach ($process in Get-CimInstance Win32_Process) {
        if ($process.ProcessId -ne $owner -and $process.ProcessId -ne $PID -and $process.Name -match '^(cargo|rustc|rust-analyzer|cargo-nextest|xtask|cl|link|lld-link|ninja|cmake)\.exe$') { $busy = $true }
    }
} catch { $errors.Add('Process inventory unavailable') }
try { foreach ($service in Get-CimInstance Win32_Service) { Add-Value $service.PathName } } catch { $errors.Add('Installed service inventory unavailable') }
try {
    foreach ($task in Get-ScheduledTask) { foreach ($action in $task.Actions) { Add-Value $action.Execute; Add-Value $action.Arguments; Add-Value $action.WorkingDirectory } }
} catch { $errors.Add('Scheduled task inventory unavailable') }
try {
    foreach ($userProfileEntry in Get-CimInstance Win32_UserProfile) { if ($userProfileEntry.LocalPath) { [void]$homes.Add($userProfileEntry.LocalPath) } }
} catch { $errors.Add('User profile inventory unavailable') }
[void]$homes.Add($env:USERPROFILE)
$registries = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths')
try {
    foreach ($user in Get-ChildItem Registry::HKEY_USERS) {
        foreach ($suffix in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\App Paths')) { $registries += ('Registry::'+$user.Name+'\'+$suffix) }
    }
    foreach ($key in $registries) {
        if (Test-Path -LiteralPath $key) {
            $keys = @((Get-Item -LiteralPath $key)) + @(Get-ChildItem -LiteralPath $key -Recurse)
            foreach ($entry in $keys) { foreach ($name in $entry.GetValueNames()) { Add-Value $entry.GetValue($name) } }
        }
    }
} catch { $errors.Add('Installed registry entry inventory unavailable') }
$locations = @((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu'),(Join-Path $env:PUBLIC 'Desktop'))
foreach ($userDirectory in $homes) { $locations += (Join-Path $userDirectory 'Desktop'); $locations += (Join-Path $userDirectory 'AppData\Roaming\Microsoft\Windows\Start Menu') }
try {
    $shell = New-Object -ComObject WScript.Shell
    $count = 0
    foreach ($location in $locations) {
        if (Test-Path -LiteralPath $location) {
            foreach ($entry in Get-ChildItem -LiteralPath $location -Recurse -File) {
                $count++; if ($count -gt 50000) { throw 'Entry scan budget exceeded' }
                if ($entry.Extension -eq '.lnk') { $shortcut = $shell.CreateShortcut($entry.FullName); Add-Value $shortcut.TargetPath; Add-Value $shortcut.Arguments; Add-Value $shortcut.WorkingDirectory }
                elseif ($entry.Extension -in @('.cmd','.bat','.ps1')) { if ($entry.Length -le 1048576) { Add-Value ([IO.File]::ReadAllText($entry.FullName)) } else { throw 'Oversized startup script' } }
            }
        }
    }
} catch { $errors.Add('Desktop or startup entry inventory unavailable') }
[Console]::Out.WriteLine((ConvertTo-Json -Depth 5 -Compress -InputObject @{ Busy=$busy; Incomplete=@($errors.ToArray()); Installed=@($values); Homes=@($homes) }))
