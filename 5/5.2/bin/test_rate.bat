@echo off
cd /d D:\AvScan52\bin
for /L %%i in (1,1,20) do client.exe scan "C:\Windows\explorer.exe"