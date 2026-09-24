@echo off
title MESI SOCHAI Platform
echo.
echo  =====================================================
echo   MESI SOCHAI Platform - Arranque
echo  =====================================================
echo.

REM Activa o ambiente virtual se existir
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

echo  [1/2] A iniciar API (FastAPI)...
start "MESI API" cmd /k "python api_main.py"

echo  A aguardar que a API fique disponivel...
set /a _tries=0
:wait_api
curl -s -o nul -w "%{http_code}" http://localhost:8000/health > "%TEMP%\mesi_health.txt" 2>nul
set /p _code=<"%TEMP%\mesi_health.txt"
if "%_code%"=="200" goto api_ready
set /a _tries+=1
if %_tries% GEQ 60 (
    echo  Aviso: API nao respondeu apos 60s — a continuar na mesma.
    goto api_ready
)
timeout /t 1 /nobreak > nul
goto wait_api
:api_ready
echo  API disponivel ^(%_tries%s^).

echo  [2/2] A abrir Dashboard (Streamlit)...
start "MESI Dashboard" cmd /k "streamlit run dashboard.py --server.headless false"

echo  A aguardar que o Streamlit arranque...
set /a _tries=0
:wait_dash
curl -s -o nul -w "%{http_code}" http://localhost:8501 > "%TEMP%\mesi_dash.txt" 2>nul
set /p _code=<"%TEMP%\mesi_dash.txt"
if "%_code%"=="200" goto dash_ready
set /a _tries+=1
if %_tries% GEQ 60 (
    echo  Aviso: Streamlit nao respondeu apos 60s — a abrir na mesma.
    goto dash_ready
)
timeout /t 1 /nobreak > nul
goto wait_dash
:dash_ready
echo  Streamlit disponivel ^(%_tries%s^).
del /q "%TEMP%\mesi_health.txt" "%TEMP%\mesi_dash.txt" >nul 2>&1

echo  [3/3] A abrir browser...
start "" "http://localhost:8501"

echo.
echo  =====================================================
echo   Servicos disponiveis:
echo     Dashboard : http://localhost:8501
echo     API docs  : http://localhost:8000/docs
echo  =====================================================
echo.
echo  Opcoes adicionais (nesta janela):
echo    [D] Gerar incidentes de DEMO (12 cenarios INCIBE)
echo    [S] Fazer seed de ativos PME
echo    [Q] Sair
echo.

:menu
set /p opcao="Escolha [D/S/Q]: "
if /i "%opcao%"=="D" goto demo
if /i "%opcao%"=="S" goto seed
if /i "%opcao%"=="Q" goto fim
goto menu

:demo
echo.
echo  A gerar 12 incidentes simulados...
python demo_incidentes.py
echo.
goto menu

:seed
echo.
echo  A adicionar ativos PME...
python seed_pme.py
echo.
goto menu

:fim
echo  Para parar os servicos, feche as janelas "MESI API" e "MESI Dashboard".
