@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0crear_certificado.ps1" %*
pause
