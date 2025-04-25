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

  const getSeverityColor = (cvss) => {
    if (!cvss || cvss === 'N/A') return '#666666';
    const score = parseFloat(cvss);
    if (score >= 9.0) return '#cc0000';  // Critical - Dark Red
    if (score >= 7.0) return '#ff4444';  // High - Red
    if (score >= 4.0) return '#ff8800';  // Medium - Orange
    if (score >= 0.1) return '#ffcc00';  // Low - Yellow
    return '#666666';                    // None/Unknown - Gray
  };

  const getSeverityLabel = (cvss) => {
    if (!cvss || cvss === 'N/A') return 'Unknown';
    const score = parseFloat(cvss);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'None';
  };

  const renderVulnerability = (vuln) => {
    const cvss = vuln.cvss || 'N/A';
    const severity = vuln.severity || getSeverityLabel(cvss);
    
    return (
      <div style={{ 
        border: '1px solid #eee',
        borderRadius: '4px',
        padding: '12px',
        marginBottom: '8px'
      }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '12px',
          marginBottom: '8px' 
        }}>
          <code style={{ 
            fontSize: '1.1em',
            color: '#333'
          }}>{vuln.id}</code>
          <span style={{
            backgroundColor: getSeverityColor(cvss),
            color: 'white',
            padding: '3px 8px',
            borderRadius: '3px',
            fontSize: '0.9em',
            fontWeight: 'bold'
          }}>
            {severity}
          </span>
          <span style={{ 
            backgroundColor: '#f8f8f8',
            padding: '3px 8px',
            borderRadius: '3px',
            fontSize: '0.9em'
          }}>
            CVSS: {typeof cvss === 'number' ? cvss.toFixed(1) : cvss}
          </span>
        </div>
        <div style={{ 
          fontSize: '0.95em',
          lineHeight: '1.4',
          color: '#444'
        }}>
          {vuln.summary || 'No description available.'}
        </div>
        {vuln.vector && (
          <div style={{ 
            marginTop: '8px',
            fontSize: '0.85em',
            fontFamily: 'monospace',
            color: '#666',
            backgroundColor: '#f8f8f8',
            padding: '4px 8px',
            borderRadius: '3px'
          }}>
            {vuln.vector}
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ padding: 20, maxWidth: 1200, margin: '0 auto' }}>
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
              border: '1px solid #ddd',
              borderRadius: '8px',
              padding: '16px',
              marginBottom: '20px',
              backgroundColor: 'white',
              boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
            }}
          >
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '12px'
            }}>
              <div>
                <h3 style={{ margin: 0 }}>{d.ip}</h3>
                <div style={{ color: '#666' }}>{d.name}</div>
              </div>
              <div style={{ 
                backgroundColor: '#f8f8f8',
                padding: '8px 12px',
                borderRadius: '4px',
                fontSize: '0.9em'
              }}>
                <strong>OS:</strong> {d.os.name}
                {d.os.version && ` (${d.os.version})`}
                {d.os.confidence && 
                  <span style={{ 
                    color: '#666',
                    fontSize: '0.9em'
                  }}> - {d.os.confidence} confidence</span>
                }
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <h4 style={{ marginBottom: '8px' }}>Open Ports</h4>
              <div style={{ 
                display: 'flex', 
                flexWrap: 'wrap', 
                gap: '8px' 
              }}>
                {Array.isArray(d.ports) && d.ports.map((p, j) => (
                  <div
                    key={j}
                    style={{
                      backgroundColor: '#f8f8f8',
                      padding: '6px 10px',
                      borderRadius: '4px',
                      fontSize: '0.9em'
                    }}
                  >
                    <strong>{p.port}</strong>
                    {p.service && <em style={{ marginLeft: '6px' }}>{p.service}</em>}
                    {p.version && <span style={{ color: '#666' }}> ({p.version})</span>}
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h4 style={{ 
                marginBottom: '12px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                Vulnerabilities
                {Array.isArray(d.vulns) && d.vulns.length > 0 && (
                  <span style={{
                    backgroundColor: '#ff4444',
                    color: 'white',
                    padding: '2px 8px',
                    borderRadius: '12px',
                    fontSize: '0.8em'
                  }}>
                    {d.vulns.length}
                  </span>
                )}
              </h4>
              {Array.isArray(d.vulns) && d.vulns.length > 0 ? (
                d.vulns.map((v, j) => (
                  <div key={j}>
                    {renderVulnerability(v)}
                  </div>
                ))
              ) : (
                <div style={{ 
                  padding: '12px',
                  backgroundColor: '#f8f8f8',
                  borderRadius: '4px',
                  color: '#666',
                  fontSize: '0.9em'
                }}>
                  No vulnerabilities found. This could mean the device is secure, 
                  or its software version wasn't recognized.
                </div>
              )}
            </div>
          </div>
        ))
      ) : (
        !loading && (
          <div style={{
            padding: '20px',
            textAlign: 'center',
            color: '#666',
            backgroundColor: '#f8f8f8',
            borderRadius: '8px',
            marginTop: '20px'
          }}>
            No devices found. Make sure to enter valid IP addresses and try again.
          </div>
        )
      )}
    </div>
  );
}
