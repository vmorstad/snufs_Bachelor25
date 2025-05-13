import React from 'react';
import { useDevices } from '../context/DeviceContext';
import { useNotification } from '../context/NotificationContext';
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

  const { showNotification } = useNotification();

  const handleScan = async (e) => {
    e.preventDefault();
    try {
      await handleSearch();
      showNotification('Network scan completed successfully!', 'success');
    } catch (error) {
      showNotification('Error during network scan. Please try again.', 'error');
    }
  };

  // Prepare vulnerability data for visualization
  const vulnerabilityData = selectedDevice && selectedDevice.vulnerabilities ? selectedDevice.vulnerabilities : [];

  return (
    <main className="home-container">
      <section className="search-section">
        <form className="search-bar" onSubmit={handleScan}>
          <input
            type="text"
            placeholder="Enter IP addresses (e.g., 192.168.0.110,192.168.0.220)"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <button type="submit" disabled={isLoading}>
            {isLoading ? (
              <span className="button-content">
                <span className="spinner"></span>
                Scanning...
              </span>
            ) : (
              'Scan Network'
            )}
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
