import React from 'react';
import { useDevices } from '../context/DeviceContext';
import '../styles/DeviceList.css';

const DeviceList = () => {
  const { searchResults, selectedDevice, handleDeviceSelect } = useDevices();

  const renderDeviceInfo = (device) => {
    if (selectedDevice?.ip !== device.ip) {
      // Only show IP and name if not selected
      return null;
    }
    return (
      <div>
        <div><strong>Name:</strong> {device.name}</div>
        <div><strong>OS:</strong> {device.os}</div>
        <div><strong>Open Ports:</strong></div>
        <ul>
          {device.ports?.map((port, idx) => (
            <li key={idx}>
              {port.port} - {port.service}
              {port.version && ` (${port.version})`}
            </li>
          ))}
        </ul>
      </div>
    );
  };

  return (
    <div className="devices-section">
      <h2>Device List</h2>
      <div className="devices-list">
        {searchResults.length > 0 ? (
          searchResults.map((device, index) => (
            <div 
              key={index} 
              className={`device-card${selectedDevice?.ip === device.ip ? ' selected' : ''}`}
              onClick={() => handleDeviceSelect(device)}
            >
              <h3>{device.ip} - {device.name || 'Unknown device'}</h3>
              {selectedDevice?.ip === device.ip && (
                <div className="device-content">
                  {renderDeviceInfo(device)}
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="device-card empty">
            <h3>No scanned device</h3>
            <div className="device-content">
              Scan network to see device information
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DeviceList; 