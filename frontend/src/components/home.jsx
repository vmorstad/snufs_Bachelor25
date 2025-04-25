import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDevices } from '../context/DeviceContext';

const Home = () => {
  const navigate = useNavigate();
  const {
    searchInput,
    setSearchInput,
    searchResults,
    isLoading,
    handleSearch
  } = useDevices();
  const [expandedDeviceIndex, setExpandedDeviceIndex] = useState(null);

  const renderDeviceInfo = (device) => {
    return (
      <div>
        <div><strong>Name:</strong> {device.name}</div>
        <div><strong>OS:</strong> {device.os}</div>
        <div><strong>Open Ports:</strong></div>
        <ul>
          {device.ports?.map((port, idx) => (
            <li key={idx}>{port}</li>
          ))}
        </ul>
      </div>
    );
  };

  const renderDeviceCards = () => {
    if (searchResults.length === 0) {
      // Show only one box when no devices are found
      return (
        <div className="device-card empty">
          <h3>No scanned device</h3>
          <div className="device-content">
            Scan network to see device information
          </div>
        </div>
      );
    }

    // Show all found devices in the scrollable container
    return searchResults.map((device, index) => (
      <div 
        key={index} 
        className={`device-card ${expandedDeviceIndex === index ? 'expanded' : ''}`}
        onClick={() => setExpandedDeviceIndex(expandedDeviceIndex === index ? null : index)}
      >
        <h3>{device.ip} - {device.name || 'Unknown device'}</h3>
        {expandedDeviceIndex === index && (
          <div className="device-content">
            {renderDeviceInfo(device)}
          </div>
        )}
      </div>
    ));
  };

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
          <div className="devices-section">
            <div className="devices-list">
              {renderDeviceCards()}
            </div>
          </div>
          
          <div className="anomalies-section">
            <h2>Here will be anomolies detetected</h2>
          </div>
          
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
