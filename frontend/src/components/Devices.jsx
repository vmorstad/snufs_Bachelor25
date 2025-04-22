// frontend/src/components/Devices.jsx
import React, { useState } from "react";

export default function DeviceList() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [authorizedIPs, setAuthorizedIPs] = useState("");

  const handleScan = () => {
    if (!authorizedIPs.trim()) {
      return alert("Please enter authorized IPs");
    }
    setLoading(true);
    fetch(`http://localhost:8000/scan?auth_ips=${encodeURIComponent(authorizedIPs)}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) alert(data.error);
        else setDevices(data);
      })
      .finally(() => setLoading(false));
  };

  return (
    <div>
      <h2>Devices on Your Network</h2>
      <div>
        <input
          value={authorizedIPs}
          onChange={e => setAuthorizedIPs(e.target.value)}
          placeholder="e.g. 192.168.0.101,192.168.0.102"
        />
        <button onClick={handleScan}>Scan Network</button>
      </div>
      {loading && <p>Scanning…</p>}
      {!loading && devices.map((d, i) => (
        <div key={i} style={{ margin: "1em 0", padding: "1em", border: "1px solid #ccc" }}>
          <p><strong>{d.ip}</strong> ({d.name}) – {d.os}</p>
          <p><strong>Open Ports:</strong></p>
          <ul>{d.ports.map((p,j)=><li key={j}>{p}</li>)}</ul>
          <p><strong>Top Vulnerabilities:</strong></p>
          <ul>
            {d.vulnerabilities.map((v,j) => (
              <li key={j}>
                <code>{v.cve}</code> (CVSS: {v.cvss}) – {v.summary}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
