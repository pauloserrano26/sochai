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

echo  A aguardar que a API fique disponivel (5s)...
timeout /t 5 /nobreak > nul

echo  [2/2] A abrir Dashboard (Streamlit)...
start "MESI Dashboard" cmd /k "streamlit run dashboard.py --server.headless false"

echo  A aguardar que o Streamlit arranque (6s)...
timeout /t 6 /nobreak > nul

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
