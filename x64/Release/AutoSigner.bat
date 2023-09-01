@echo off
echo.
echo *** Auto Signer Shit By Manhattan ***
echo.
date 02-04-2012
setlocal
cd /d %~dp0
signtool sign /v /ac "MSVC.cer" /f my.pfx /p password /n "HT Srl"  "Spoofer.sys"
net start w32time
w32tm /config /update
w32tm /resync /rediscover
pause
echo.
