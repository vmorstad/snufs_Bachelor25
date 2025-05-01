import React from 'react';
import { useDevices } from '../context/DeviceContext';
import DeviceList from './DeviceList';
import Vulnerabilities from './Vulnerabilities';
import Heatmap from './Heatmap';
import '../styles/Home.css';

const Home = () => {
  const {
    searchInput,
    setSearchInput,
    isLoading,
    handleSearch
  } = useDevices();

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
        <Heatmap />
      </div>
    </div>
  );
};

export default Home;
