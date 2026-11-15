@echo off
TITLE Ile Egbe - Servidor
color 06
echo ========================================================
echo   Iniciando o Sistema Ilê Egbé Óiyá e Ólúáíwè
echo ========================================================
echo.
if not exist node_modules (
    echo [INFO] Instalando dependencias pela primeira vez...
    call npm install
)
echo [INFO] Iniciando servidor Node.js...
node server.js
pause
