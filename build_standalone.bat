@echo off
echo Starting standalone build process...

echo.
echo === Building Frontend ===
cd frontend
call npm install
if errorlevel 1 (
    echo Frontend build failed!
    pause
    exit /b 1
)
call npm run build
if errorlevel 1 (
    echo Frontend build failed!
    pause
    exit /b 1
)
cd ..
echo Frontend build completed successfully!

echo.
echo === Installing Dependencies ===
call pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install dependencies!
    pause
    exit /b 1
)

echo.
echo === Creating Standalone Executable ===
echo Current directory: %CD%
echo Checking if PyInstaller is installed...
pyinstaller --version
if errorlevel 1 (
    echo PyInstaller not found! Installing...
    pip install pyinstaller
)

echo Creating executable...
pyinstaller --noconfirm --onefile --windowed ^
    --add-data "frontend/build;frontend/build" ^
    --add-data "backend;backend" ^
    --name "NetworkVulnerabilityScanner" ^
    backend/server.py

if errorlevel 1 (
    echo Failed to create executable!
    pause
    exit /b 1
)

echo.
echo === Build Completed Successfully! ===
echo The standalone executable is in the 'dist' directory
echo Users can simply double-click 'NetworkVulnerabilityScanner.exe' to run the application
dir dist
pause
exit /b 0 