$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Py = Join-Path $env:LocalAppData "Programs\Python\Python312\python.exe"
if (-not (Test-Path $Py)) {
  $Py = "python"
}

$env:PYTHONPATH = $Root
$env:PYTHONUTF8 = "1"

Write-Host "Installing Python dependencies..."
& $Py -m pip install -r (Join-Path $Root "engine\requirements.txt") -r (Join-Path $Root "sensors\http_gateway\requirements.txt") -r (Join-Path $Root "sensors\windows_agent\requirements.txt")

if (-not (Test-Path (Join-Path $Root "dashboard\node_modules"))) {
  Write-Host "Installing dashboard dependencies..."
  Push-Location (Join-Path $Root "dashboard")
  npm install
  Pop-Location
}

function Start-WhJob($Title, $Command) {
  Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$Root'; `$env:PYTHONPATH='$Root'; `$env:PYTHONUTF8='1'; Write-Host '$Title'; $Command"
  ) | Out-Null
}

Start-WhJob "WH engine :8000" "& '$Py' -m engine.app.main"
Start-Sleep -Seconds 2
Start-WhJob "WH HTTP gateway :8080" "& '$Py' sensors\http_gateway\main.py"
Start-WhJob "WH Windows agent" "& '$Py' sensors\windows_agent\agent.py"
Start-WhJob "WH dashboard :5173" "Set-Location '$Root\dashboard'; npm run dev"

Start-Sleep -Seconds 2
Start-Process "http://127.0.0.1:5173"
Write-Host "Started engine, gateway, Windows agent, and dashboard."
