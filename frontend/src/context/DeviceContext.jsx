import React, { createContext, useState, useContext } from 'react';

const DeviceContext = createContext();

export const DeviceProvider = ({ children }) => {
  const [searchInput, setSearchInput] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);

  const handleSearch = async () => {
    if (!searchInput.trim()) return;
    setIsLoading(true);
    try {
      const response = await fetch(
        `http://localhost:8000/scan?auth_ips=${encodeURIComponent(searchInput)}`
      );
      const data = await response.json();
      if (Array.isArray(data)) {
        setSearchResults(data);
      } else {
        console.error('Unexpected response format:', data);
        setSearchResults([]);
      }
    } catch (error) {
      console.error('Error scanning devices:', error);
      setSearchResults([]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeviceSelect = (device) => {
    setSelectedDevice(device);
  };

  return (
    <DeviceContext.Provider 
      value={{
        searchInput,
        setSearchInput,
        searchResults,
        setSearchResults,
        isLoading,
        setIsLoading,
        handleSearch,
        selectedDevice,
        handleDeviceSelect
      }}
    >
      {children}
    </DeviceContext.Provider>
  );
};

export const useDevices = () => {
  const context = useContext(DeviceContext);
  if (!context) {
    throw new Error('useDevices must be used within a DeviceProvider');
  }
  return context;
}; 