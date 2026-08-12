@echo off
cd /d D:\AvScan52\bin
for /L %%i in (1,1,30) do start "job%%i" cmd /c "client.exe scan C:\Windows\explorer.exe & timeout /t 25 >nul"