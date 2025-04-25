// frontend/src/components/Devices.jsx
import React, { useState } from "react";

export default function DeviceList() {
  const [ips, setIps] = useState("");
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState({});

  const scan = async () => {
    if (!ips.trim()) {
      return alert("Enter one or more IP addresses first");
    }
    
    setLoading(true);
    setDevices([]);
    setProgress({});

    try {
      // Start the scan
      const ipList = ips.split(",").map(ip => ip.trim()).filter(ip => ip);
      const response = await fetch(
        `http://localhost:8000/scan?auth_ips=${encodeURIComponent(ipList.join(","))}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to start scan');
      }

      // Poll for progress and results
      const pollInterval = setInterval(async () => {
        try {
          // Get progress
          const progressResp = await fetch('http://localhost:8000/scan/progress');
          if (!progressResp.ok) throw new Error('Failed to fetch progress');
          const progressData = await progressResp.json();
          setProgress(progressData);
          
          // Check if all devices are complete
          const allComplete = Object.values(progressData).every(
            p => p.status === 'completed' || p.status === 'error'
          );
          
          if (allComplete) {
            clearInterval(pollInterval);
            
            // Get final results
            const resultsResp = await fetch('http://localhost:8000/scan/results');
            if (!resultsResp.ok) throw new Error('Failed to fetch results');
            const resultsData = await resultsResp.json();
            
            // Convert results object to array
            const deviceArray = Object.values(resultsData);
            setDevices(deviceArray);
            setLoading(false);
          }
        } catch (err) {
          console.error("Polling error:", err);
          clearInterval(pollInterval);
          setLoading(false);
        }
      }, 1000);

    } catch (err) {
      console.error("Scan error:", err);
      alert("Error starting scan: " + err.message);
      setLoading(false);
    }
  };

  // Render progress information
  const renderProgress = () => {
    if (!loading || Object.keys(progress).length === 0) return null;

    return (
      <div style={{ marginBottom: 20 }}>
        <h3>Scan Progress:</h3>
        {Object.entries(progress).map(([ip, info]) => (
          <div key={ip} style={{ marginBottom: 10 }}>
            <strong>{ip}:</strong> {info.status} ({info.progress}%)
            {info.error && <span style={{ color: 'red' }}> - Error: {info.error}</span>}
          </div>
        ))}
      </div>
    );
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return '#cc0000';
      case 'HIGH': return '#ff4444';
      case 'MEDIUM': return '#ffaa00';
      case 'LOW': return '#ffcc00';
      default: return '#666666';
    }
  };

  const getCvssLabel = (score) => {
    if (score === null || score === undefined) return 'N/A';
    score = parseFloat(score);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'None';
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
        <button onClick={scan} disabled={loading}>
          {loading ? "Scanning..." : "Scan Network"}
        </button>
      </div>

      {renderProgress()}

      {!loading && Array.isArray(devices) && devices.length > 0 ? (
        devices.map((d, idx) => (
          <div
            key={d.ip || idx}
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
              <strong>OS:</strong> {d.os.name} 
              {d.os.version && ` (Version: ${d.os.version})`}
              {d.os.confidence && ` - Confidence: ${d.os.confidence}`}
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
              <strong>Vulnerabilities</strong>
            </p>
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {Array.isArray(d.vulns) && d.vulns.length > 0 ? (
                d.vulns.map((v, j) => (
                  <li key={j} style={{ 
                    marginBottom: '10px',
                    padding: '10px',
                    border: '1px solid #eee',
                    borderRadius: '4px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', marginBottom: '5px' }}>
                      <code style={{ marginRight: '10px' }}>{v.id}</code>
                      <span style={{
                        backgroundColor: getSeverityColor(v.severity),
                        color: 'white',
                        padding: '2px 6px',
                        borderRadius: '3px',
                        fontSize: '0.9em',
                        marginRight: '10px'
                      }}>
                        {v.severity || getCvssLabel(v.cvss)}
                      </span>
                      <span style={{ color: '#666' }}>
                        CVSS: {v.cvss != null ? v.cvss.toFixed(1) : 'N/A'}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.9em', color: '#333' }}>{v.summary}</div>
                    {v.vector && (
                      <div style={{ 
                        fontSize: '0.8em',
                        color: '#666',
                        fontFamily: 'monospace',
                        marginTop: '5px'
                      }}>
                        Vector: {v.vector}
                      </div>
                    )}
                  </li>
                ))
              ) : (
                <li>No vulnerabilities found. This could mean the device is secure, or its software version wasn't recognized.</li>
              )}
            </ul>
          </div>
        ))
      ) : (
        !loading && <p>No devices found. Make sure to enter valid IP addresses and try again.</p>
      )}
    </div>
  );
}
