import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useDevices } from '../context/DeviceContext';

const Devices = () => {
  const navigate = useNavigate();
  const {
    searchInput,
    setSearchInput,
    searchResults,
    isLoading,
    handleSearch
  } = useDevices();

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

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="nav-items">
          <div className="nav-item" onClick={() => navigate('/')}>
            <i className="icon home-icon"></i>
            <span>Home</span>
          </div>
          <div className="nav-item active" onClick={() => navigate('/devices')}>
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
        
        <div className="devices-page">
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

          {searchResults.length > 0 ? (
            <div className="devices-grid">
              {searchResults.map((device, index) => (
                <div key={index} className="device-card">
                  <h3>{device.ip} - {device.name || 'Unknown device'}</h3>
                  <div className="device-content">
                    {renderDeviceInfo(device)}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="no-devices">
              <p>No devices found. Use the search bar above to scan for devices.</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Devices;
