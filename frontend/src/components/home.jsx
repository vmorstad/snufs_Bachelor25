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
    <main className="home-container">
      <section className="search-section">
        <form className="search-bar" onSubmit={e => { e.preventDefault(); handleSearch(); }}>
          <input
            type="text"
            placeholder="Enter IP addresses (e.g., 192.168.0.110,192.168.0.220)"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <button type="submit" disabled={isLoading}>
            {isLoading ? 'Scanning...' : 'Scan Network'}
          </button>
        </form>
      </section>

      <section className="content-grid">
        <DeviceList />
        <Vulnerabilities />
        <section className="heatmap-section">
          <h2>Vulnerability Visualization</h2>
          <Visualization data={vulnerabilityData} />
        </section>
      </section>
    </main>
  );
};

export default Home;
