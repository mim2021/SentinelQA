@echo off
rem Easy way to run the netguard Wi-Fi checker, no setup needed.
rem   Double-click this file             -> checks the network you are on now
rem   .\netguard                          -> same, from a terminal in this folder
rem   .\netguard check --host <site>      -> check a specific site
rem   .\netguard trust                    -> accept a router IT replaced
pushd "%~dp0netguard"
if "%~1"=="" (python -m netguard check) else (python -m netguard %*)
set CODE=%ERRORLEVEL%
popd
rem Keep the window open when started by double-click (VS Code's terminal sets TERM_PROGRAM).
if not defined TERM_PROGRAM pause
exit /b %CODE%
