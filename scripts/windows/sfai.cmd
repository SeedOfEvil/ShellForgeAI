@echo off
setlocal
rem Official ShellForgeAI Windows wrapper.
rem Resolve runtime root from this wrapper's own location: <runtime>\bin\sfai.cmd
set "SFAI_WRAPPER_DIR=%~dp0"
for %%I in ("%SFAI_WRAPPER_DIR%..") do set "SHELLFORGEAI_RUNTIME_ROOT=%%~fI"
rem Durable state is always owned by this installation, never by the caller's CWD.
set "SHELLFORGEAI_DATA_DIR=%SHELLFORGEAI_RUNTIME_ROOT%\data"
if not exist "%SHELLFORGEAI_DATA_DIR%" mkdir "%SHELLFORGEAI_DATA_DIR%" >nul 2>&1
set "SFAI_PYTHON=python"
if exist "%SHELLFORGEAI_RUNTIME_ROOT%\Python314\python.exe" set "SFAI_PYTHON=%SHELLFORGEAI_RUNTIME_ROOT%\Python314\python.exe"
"%SFAI_PYTHON%" -m shellforgeai %*
exit /b %ERRORLEVEL%
