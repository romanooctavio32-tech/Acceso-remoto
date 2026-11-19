@echo off
cd /d "%~dp0"
title Acceso Remoto - Servidor
python servidor.py %*
pause
