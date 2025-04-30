import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useDevices } from '../context/DeviceContext';
import DeviceList from './DeviceList';
import Anomalies from './anomalies';

const Home = () => {
  const navigate = useNavigate();
  const {
    searchInput,
    setSearchInput,
    isLoading,
    handleSearch
  } = useDevices();

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="nav-items">
          <div className="nav-item active" onClick={() => navigate('/')}>
            <i className="icon home-icon"></i>
            <span>Home</span>
          </div>
          <div className="nav-item" onClick={() => navigate('/devices')}>
            <i className="icon devices-icon"></i>
            <span>Devices</span>
          </div>
          <div className="nav-item" onClick={() => navigate('/settings')}>
            <i className="icon settings-icon"></i>
            <span>Setting</span>
          </div>
        </div>
      </nav>
      
      <main className="main-content">
        <div className="top-bar">
          <div className="help-section">
            <span>Help</span>
            <i className="icon notification-icon"></i>
          </div>
        </div>
        
        <div className="search-section">
          <div className="search-bar">
            <input
              type="text"
              placeholder="Enter IP addresses (e.g., 192.168.0.110,192.168.0.220)"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button onClick={handleSearch} disabled={isLoading}>
              {isLoading ? 'Scanning...' : 'Scan Network'}
            </button>
          </div>
        </div>

        <div className="content-grid">
          <DeviceList />
          
          <Anomalies />
          
          <div className="graph-section">
            <div className="graph-container">
              {/* Graph will be implemented later with a charting library */}
              <canvas id="deviceGraph"></canvas>
              <div className="graph-label">Devices</div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Home;
