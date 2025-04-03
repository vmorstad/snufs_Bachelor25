import React, {useState, useEffect} from "react";

export default function DeviceList() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:8000/scan")
      .then((response) => response.json())
      .then((data) => {
        setDevices(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching devices:", error);
        setLoading(false);
      });
  }, []);

  if (loading) return <p>Loading devices...</p>;
  if (!devices.length) return <p>No devices found.</p>;

  return (
    <div>
      <h2>Devices in the Network</h2>
      <ul>
        {devices.map((device, idx) => (
          <li key={idx}>
            <strong>IP:</strong> {device.ip} | <strong>MAC:</strong> {device.mac}
            {device.os && <p><strong>OS Info:</strong> {device.os}</p>}
          </li>
        ))}
      </ul>
    </div>
  );
}