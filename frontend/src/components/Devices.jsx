// frontend/src/components/Devices.jsx
import React, { useState } from "react";

export default function DeviceList() {
  const [ips, setIps]       = useState("");
  const [devices, setDevices] = useState([]);  // always an array
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    if (!ips.trim()) {
      return alert("Enter one or more IP addresses first");
    }
    setLoading(true);

    try {
      const res  = await fetch(
        `http://localhost:8000/scan?auth_ips=${encodeURIComponent(ips)}`
      );
      const data = await res.json();
      console.log("Backend returned:", data);

      // Normalize into an array:
      let list = [];
      if (Array.isArray(data)) {
        list = data;
      } else if (Array.isArray(data.devices)) {
        list = data.devices;
      } else {
        console.warn("Unexpected scan result shape, setting to []");
      }
      setDevices(list);
    } catch (err) {
      console.error("Fetch error", err);
      setDevices([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Devices in the Network</h2>

      <div style={{ marginBottom: 12 }}>
        <input
          style={{ width: 300, marginRight: 8 }}
          placeholder="e.g. 192.168.1.10,192.168.1.11"
          value={ips}
          onChange={(e) => setIps(e.target.value)}
        />
        <button onClick={scan}>Scan Network</button>
      </div>

      {loading && <p>Scanning… please wait.</p>}

      {/* Only map if devices is an array with items */}
      {!loading && Array.isArray(devices) && devices.length > 0 ? (
        devices.map((d, idx) => (
          <div
            key={idx}
            style={{
              border: "1px solid #ccc",
              padding: 12,
              marginBottom: 12,
              borderRadius: 4,
            }}
          >
            <p>
              <strong>IP:</strong> {d.ip} — <strong>Name:</strong> {d.name}
            </p>
            <p>
              <strong>OS:</strong> {d.os}
            </p>
            <p>
              <strong>Open Ports:</strong>
            </p>
            <ul>
              {Array.isArray(d.ports) &&
                d.ports.map((p, j) => (
                  <li key={j}>
                    {p.port} <em>{p.service}</em> {p.version}
                  </li>
                ))}
            </ul>
            <p>
              <strong>Top CVEs:</strong>
            </p>
            <ul>
              {Array.isArray(d.vulns) &&
                d.vulns.map((v, j) => (
                  <li key={j}>
                    <code>{v.id}</code> (CVSS {v.cvss}) — {v.summary}
                  </li>
                ))}
            </ul>
          </div>
        ))
      ) : (
        !loading && <p>No devices found.</p>
      )}
    </div>
  );
}
