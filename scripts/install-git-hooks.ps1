# Install repo git hooks (strip Cursor/agent co-author trailers).
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Src = Join-Path $Root "scripts\git-hooks\commit-msg"
$Dest = Join-Path $Root ".git\hooks\commit-msg"
Copy-Item -Force $Src $Dest
Write-Host "Installed commit-msg hook -> $Dest"
