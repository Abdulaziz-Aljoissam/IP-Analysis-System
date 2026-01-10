@echo off
chcp 65001 >nul
title IP Analysis System v1.0

echo.
echo ════════════════════════════════════════════════════════════════
echo.
echo           🛡️  IP ANALYSIS SYSTEM v1.0 🛡️
echo.
echo           Abdulaziz Aljoissam - Security Tool
echo.
echo ════════════════════════════════════════════════════════════════
echo.
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0IP_Analyzer.ps1"

pause
