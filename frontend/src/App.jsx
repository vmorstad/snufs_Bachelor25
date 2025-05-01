import React from "react";
import { Route, Routes, Link } from "react-router-dom";
import { DeviceProvider } from "./context/DeviceContext";
import "./styles/App.css";
import Home from "./components/Home";
import Vulnerabilities from "./components/Vulnerabilities";
import Guide from "./components/Guide";
import "./styles/Guide.css";

function App() {
  return (
    <DeviceProvider>
      <div className="layout">
        <div className="sidebar">
          <nav className="nav-items">
            <Link to="/" className="nav-item">Home</Link>
            <Link to="/guide" className="nav-item">Guide</Link>
          </nav>
        </div>
        <div className="main-content">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/guide" element={<Guide />} />
          </Routes>
        </div>
      </div>
    </DeviceProvider>
  );
}

export default App;
