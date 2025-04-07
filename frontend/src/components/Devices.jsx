import React, { useState } from "react";

export default function DeviceList() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [authorizedIPs, setAuthorizedIPs] = useState("");

  const handleScan = () => {
    if (!authorizedIPs.trim()) {
      alert("Please provide authorized IP addresses.");
      return;
    }
    setLoading(true);
    const encodedIPs = encodeURIComponent(authorizedIPs);
    fetch(`http://localhost:8000/scan?auth_ips=${encodedIPs}`)
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          alert(data.error);
          setDevices([]);
        } else {
          setDevices(data);
        }
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching devices:", error);
        setLoading(false);
      });
  };

  return (
    <div>
      <h2>Devices in the Network</h2>
      <div style={{ marginBottom: "1rem" }}>
        <label>
          Authorized IP Addresses (comma separated):
          <input
            type="text"
            value={authorizedIPs}
            onChange={(e) => setAuthorizedIPs(e.target.value)}
            placeholder="e.g. 192.168.0.101,192.168.0.102"
          />
        </label>
        <button onClick={handleScan} style={{ marginLeft: "1rem" }}>
          Scan Network
        </button>
      </div>
      {loading ? (
        <p>Loading devices...</p>
      ) : devices.length > 0 ? (
        <ul>
          {devices.map((device, idx) => (
            <li key={idx}>
              <strong>IP:</strong> {device.ip} | <strong>Device Name:</strong> {device.name} | <strong>OS Info:</strong> {device.os}
            </li>
          ))}
        </ul>
      ) : (
        <p>No devices found.</p>
      )}
    </div>
  );
}
