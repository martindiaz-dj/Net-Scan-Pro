@echo off
title NetScan Pro - Network Administrator Console
mode con: cols=120 lines=36
chcp 65001 >nul
cls
python "%~dp0main.py"
pause
