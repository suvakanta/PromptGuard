@echo off
cd /d "%~dp0"
set WRANGLER_LOG_PATH=.wrangler/wrangler.log
start "" /b cmd /c "timeout /t 5 /nobreak >nul & start http://localhost:3000"
npm exec vinext dev
