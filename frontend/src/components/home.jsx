import React from 'react';
import { useDevices } from '../context/DeviceContext';
import DeviceList from './DeviceList';
import Vulnerabilities from './Vulnerabilities';
import Visualization from './Visualization';
import '../styles/Home.css';

const Home = () => {
  const {
    searchInput,
    setSearchInput,
    isLoading,
    handleSearch,
    selectedDevice
  } = useDevices();

  // Prepare vulnerability data for visualization
  const vulnerabilityData = selectedDevice && selectedDevice.vulnerabilities ? selectedDevice.vulnerabilities : [];

  return (
    <div className="home-container">
      <div className="search-section">
        <div className="search-bar">
          <input
            type="text"
            placeholder="Enter IP addresses (e.g., 192.168.0.110,192.168.0.220)"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <button onClick={handleSearch} disabled={isLoading}>
            {isLoading ? 'Scanning...' : 'Scan Network'}
          </button>
        </div>
      </div>

      <div className="content-grid">
        <DeviceList />
        <Vulnerabilities />
        <div className="heatmap-section">
          <h2>Vulnerability Visualization</h2>
          <Visualization data={vulnerabilityData} />
        </div>
      </div>
    </div>
  );
};

export default Home;
