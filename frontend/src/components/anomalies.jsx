import React from 'react';
import { useDevices } from '../context/DeviceContext';
import '../styles/anomalies.css';

const Anomalies = () => {
  const { selectedDevice } = useDevices();

  const renderCVE = (anomaly) => (
    <div className={`anomaly-card ${anomaly.severity?.toLowerCase() || 'unknown'}`} key={anomaly.cve_id}>
      <div className="anomaly-header">
        <h3>{anomaly.cve_id}</h3>
        <div className={`severity-badge ${anomaly.severity?.toLowerCase() || 'unknown'}`}>{anomaly.severity}</div>
      </div>
      <div className="anomaly-content">
        <p><strong>CVSS Score:</strong> {anomaly.cvss_score}</p>
        <p><strong>Description:</strong> {anomaly.description}</p>
        <p><strong>Published:</strong> {anomaly.published ? new Date(anomaly.published).toLocaleDateString() : '-'}</p>
        <p><strong>Last Modified:</strong> {anomaly.last_modified ? new Date(anomaly.last_modified).toLocaleDateString() : '-'}</p>
        {anomaly.affected_software && (
          <p><strong>Affected Software:</strong> {anomaly.affected_software}</p>
        )}
      </div>
    </div>
  );

  const renderCPEGroup = (group) => (
    <div key={group.cpe} className="cpe-group">
      <div className="cpe-header">
        <h3>{group.cpe_title}</h3>
        <div className="cpe-id">{group.cpe}</div>
      </div>
      {group.cves && group.cves.length > 0 ? (
        group.cves.map(renderCVE)
      ) : (
        <div className="no-anomalies">No vulnerabilities found for this CPE.</div>
      )}
    </div>
  );

  return (
    <div className="anomalies-section">
      <h2>Device Vulnerabilities</h2>
      {selectedDevice ? (
        <div className="anomalies-list">
          {selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
            selectedDevice.vulnerabilities.map(renderCPEGroup)
          ) : (
            <div className="no-anomalies">
              No vulnerabilities detected for {selectedDevice.name || selectedDevice.ip}
            </div>
          )}
        </div>
      ) : (
        <div className="no-device-selected">
          Select a device to view its vulnerabilities
        </div>
      )}
    </div>
  );
};

export default Anomalies; 