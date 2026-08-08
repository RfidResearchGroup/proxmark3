@echo off
setlocal

::                  Power by DXL
::  The mkversion.ps1 wrapper. why not mkversion.bat implement all function?
::    > Not good idea to call sha256 for arm src, so you known..

:: Did not output localization
set LC_ALL=C
set LANG=C

:: Where are this script?
set "SCRIPT_DIR=%~dp0"

:: Call PowerShell script, and send params
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%mkversion.ps1" %*

if %ERRORLEVEL% NEQ 0 (
    exit /b %ERRORLEVEL%
)