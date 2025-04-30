import React from "react";
import { Route, Routes } from "react-router-dom";
import { DeviceProvider } from "./context/DeviceContext";
import "./styles/App.css";
import Home from "./components/Home";
import Vulnerabilities from "./components/Vulnerabilities";

function App() {
  return (
    <DeviceProvider>
      <div className="App">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        </Routes>
      </div>
    </DeviceProvider>
  );
}

export default App;
