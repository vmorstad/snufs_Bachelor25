@echo off
echo Starting build process...

echo.
echo === Building Frontend ===
cd frontend
call npm install
if errorlevel 1 (
    echo Frontend build failed!
    exit /b 1
)
call npm run build
if errorlevel 1 (
    echo Frontend build failed!
    exit /b 1
)
cd ..
echo Frontend build completed successfully!

echo.
echo === Building Backend ===
call pip install -r requirements.txt
if errorlevel 1 (
    echo Backend build failed!
    exit /b 1
)

echo Creating distribution package...
if exist dist rmdir /s /q dist
mkdir dist
mkdir dist\backend
mkdir dist\frontend

echo Copying backend files...
copy backend\server.py dist\backend\
copy backend\cve_api.py dist\backend\
copy backend\cpe_api.py dist\backend\
copy backend\port_scan.py dist\backend\
copy backend\device_discovery.py dist\backend\
copy requirements.txt dist\backend\

echo Copying frontend build...
xcopy /E /I frontend\build dist\frontend

echo Creating README...
echo # Network Vulnerability Scanner > dist\README.md
echo. >> dist\README.md
echo ## Setup Instructions >> dist\README.md
echo. >> dist\README.md
echo 1. Install Python 3.8 or higher >> dist\README.md
echo 2. Install required Python packages: >> dist\README.md
echo    ``` >> dist\README.md
echo    cd backend >> dist\README.md
echo    pip install -r requirements.txt >> dist\README.md
echo    ``` >> dist\README.md
echo 3. Install Nmap (required for port scanning): >> dist\README.md
echo    - Windows: Download and install from https://nmap.org/download.html >> dist\README.md
echo    - Linux: `sudo apt-get install nmap` >> dist\README.md
echo    - macOS: `brew install nmap` >> dist\README.md
echo. >> dist\README.md
echo ## Running the Application >> dist\README.md
echo. >> dist\README.md
echo 1. Start the backend server: >> dist\README.md
echo    ``` >> dist\README.md
echo    cd backend >> dist\README.md
echo    python server.py >> dist\README.md
echo    ``` >> dist\README.md
echo 2. Open the frontend: >> dist\README.md
echo    - Open `frontend/index.html` in your web browser >> dist\README.md
echo. >> dist\README.md
echo ## Notes >> dist\README.md
echo - The backend server runs on port 8000 >> dist\README.md
echo - Make sure Nmap is installed and accessible from the command line >> dist\README.md
echo - The application requires administrator/root privileges for network scanning >> dist\README.md

echo Creating start script...
echo @echo off > dist\start.bat
echo echo Starting Network Vulnerability Scanner... >> dist\start.bat
echo cd backend >> dist\start.bat
echo start /B python server.py >> dist\start.bat
echo cd .. >> dist\start.bat
echo start frontend\index.html >> dist\start.bat
echo echo Application started! >> dist\start.bat
echo echo Backend server running on http://localhost:8000 >> dist\start.bat
echo echo Frontend opened in your default browser >> dist\start.bat
echo pause >> dist\start.bat

echo.
echo === Build Completed Successfully! ===
echo The application package is in the 'dist' directory
echo Your teacher can run the application by:
echo 1. Installing Python and Nmap
echo 2. Running 'start.bat' in the dist directory
exit /b 0 