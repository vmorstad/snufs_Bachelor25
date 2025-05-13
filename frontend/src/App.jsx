import React from "react";
import { Route, Routes } from "react-router-dom";
import { DeviceProvider } from "./context/DeviceContext";
import { NotificationProvider } from "./context/NotificationContext";
import "./styles/App.css";
import Home from "./components/Home";
import Vulnerabilities from "./components/Vulnerabilities";
import Guide from "./components/Guide";
import "./styles/Guide.css";
import Sidebar from "./components/Sidebar";

function App() {
  return (
    <DeviceProvider>
      <NotificationProvider>
        <div className="layout">
          <Sidebar />
          <div className="main-content">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/guide" element={<Guide />} />
            </Routes>
          </div>
        </div>
      </NotificationProvider>
    </DeviceProvider>
  );
}

export default App;
