# Network Vulnerability Scanner - How to Run

## 1. Setup Python and Nmap

- Open a terminal (Command Prompt or PowerShell).
- Navigate to the main project folder (the one with `requirements.txt`).

### Install Python dependencies:
```
pip install -r requirements.txt
```

### Install Nmap:
- Download and install from https://nmap.org/download.html
- Make sure to add Nmap to your system PATH during installation.

---

## 2. Running the Application
### Production Mode
If you want to run the application in production mode (single server):

1. Build the frontend:
```
cd frontend
npm install  # Only needed first time
npm run build
```

### Development Mode (Recommended for Development, can be skipped if not developing)
You'll need two terminal windows:

1. Start the backend server:
```
python backend/server.py
```
This will start the backend server on http://localhost:8000

2. Start the frontend development server:
```
cd frontend
npm install  # Only needed first time
npm start
```
This will start the frontend development server on http://localhost:3000 with hot-reloading enabled.



2. Start the backend server:
```
python backend/server.py
```
The backend will serve both the API and the built frontend files on http://localhost:8000

---

## 3. Accessing the Application
- In production mode: Open http://localhost:8000 in your browser
  - Everything runs through port 8000
  - The backend serves both the API and frontend files
  - Only the backend server needs to be running

- In development mode: Open http://localhost:3000 in your browser
  - The frontend runs on port 3000
  - The backend API runs on port 8000
  - Both servers must be running
  
---

## 4. Development Notes

- The frontend development server (npm start) provides hot-reloading for easier development
- The backend server (server.py) handles API requests and serves the frontend in production mode
- Make sure both servers are running when developing (frontend on port 3000, backend on port 8000)
