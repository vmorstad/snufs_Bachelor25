import React from "react";
import { Route, Routes } from "react-router-dom";
import Home from "./components/home";
import { DeviceProvider } from "./context/DeviceContext";
import "./styles/App.css";

function App() {
  return (
    <DeviceProvider>
      <div className="App">
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </div>
    </DeviceProvider>
  );
}

export default App;
