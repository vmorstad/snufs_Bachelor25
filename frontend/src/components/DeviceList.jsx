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
      <section>
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
      </section>
    );
  };

  return (
    <section className="devices-section">
      <h2>Device List</h2>
      <ul className="devices-list">
        {searchResults.length > 0 ? (
          searchResults.map((device, index) => (
            <li 
              key={index} 
              className={`device-card${selectedDevice?.ip === device.ip ? ' selected' : ''}`}
              onClick={() => handleDeviceSelect(device)}
              tabIndex={0}
              role="button"
              aria-pressed={selectedDevice?.ip === device.ip}
            >
              <header>
                <h3>{device.ip} - {device.name || 'Unknown device'}</h3>
              </header>
              {selectedDevice?.ip === device.ip && (
                <section className="device-content">
                  {renderDeviceInfo(device)}
                </section>
              )}
            </li>
          ))
        ) : (
          <li className="device-card empty">
            <h3>No scanned device</h3>
            <section className="device-content">
              Scan network to see device information
            </section>
          </li>
        )}
      </ul>
    </section>
  );
};

export default DeviceList; 