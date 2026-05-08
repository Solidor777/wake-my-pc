if "%1" == "elevated" goto start
powershell -command "Start-Process %~nx0 elevated -Verb runas"
goto :EOF
:start

cd C:\Dev\wake-my-pc
claude --resume