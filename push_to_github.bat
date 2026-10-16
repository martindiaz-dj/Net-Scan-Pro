@echo off
title Subir NetScan Pro a GitHub
cls
echo ====================================================================
echo  Subiendo NetScan Pro a GitHub
echo  Repositorio: https://github.com/martindiaz-dj/Net-Scan-Pro.git
echo ====================================================================
echo.
set "PATH=C:\Users\Martin\AppData\Local\Programs\Git\cmd;C:\Users\Martin\AppData\Local\Programs\Git\mingw64\bin;%PATH%"

git push -u origin main

echo.
echo ====================================================================
echo  Completado. Presione cualquier tecla para cerrar esta ventana.
echo ====================================================================
pause
