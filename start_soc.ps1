# MESI SOCHAI Platform - Script de Arranque
# Usa o ambiente virtual do projeto (.venv)

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  MESI SOCHAI Platform - A iniciar..." -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$projectDir = $PSScriptRoot
$python    = Join-Path $projectDir ".venv\Scripts\python.exe"
$streamlit = Join-Path $projectDir ".venv\Scripts\streamlit.exe"

if (-not (Test-Path $python)) {
    Write-Host "ERRO: Ambiente virtual nao encontrado em .venv" -ForegroundColor Red
    Write-Host "Execute primeiro: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

# Janela 1: API FastAPI
Write-Host "`n[1] A iniciar API SOCHAI em http://localhost:8000 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$projectDir'; Write-Host 'SOCHAI API -- porta 8000' -ForegroundColor Cyan; & '$python' api_main.py"
)

Start-Sleep -Seconds 3

# Janela 2: Dashboard Streamlit
Write-Host "[2] A iniciar Dashboard em http://localhost:8501 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$projectDir'; Write-Host 'SOCHAI Dashboard -- porta 8501' -ForegroundColor Cyan; & '$streamlit' run dashboard.py --server.port 8501"
)

Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host "  API:       http://localhost:8000" -ForegroundColor Green
Write-Host "  API Docs:  http://localhost:8000/docs" -ForegroundColor Green
Write-Host "  Dashboard: http://localhost:8501" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
