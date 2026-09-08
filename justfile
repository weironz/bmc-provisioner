set shell := ["powershell", "-NoProfile", "-Command"]

# Build the service sidecar, stop an existing development desktop shell, then launch Tauri.
app:
    $desktop = Get-Process -Name bmc-provisioner,bmc-provisioner-desktop -ErrorAction SilentlyContinue; if ($desktop) { $desktop | Stop-Process -Force }; exit 0
    cargo build
    New-Item -ItemType Directory -Force ui/src-tauri/binaries | Out-Null
    Copy-Item target/debug/bmc-provisionerd.exe ui/src-tauri/binaries/bmc-provisionerd-x86_64-pc-windows-msvc.exe -Force
    Set-Location ui; bun run tauri dev

# Run the service and Vite UI separately for fast browser-based development.
dev:
    Start-Process -FilePath cargo -ArgumentList 'run', '--bin', 'bmc-provisionerd' -WorkingDirectory (Get-Location) -WindowStyle Hidden
    Set-Location ui; bun run dev
