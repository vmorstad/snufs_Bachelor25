import React from 'react';
import { useDevices } from '../context/DeviceContext';
import '../styles/Vulnerabilities.css';

const Vulnerabilities = () => {
  const { selectedDevice } = useDevices();

  const renderCVE = (cve) => (
    <div className={`vulnerability-card ${cve.severity?.toLowerCase() || 'unknown'}`} key={cve.cve_id}>
      <div className="vulnerability-header">
        <h3>{cve.cve_id}</h3>
        <div className={`severity-badge ${cve.severity?.toLowerCase() || 'unknown'}`}>{cve.severity}</div>
      </div>
      <div className="vulnerability-content">
        <p><strong>CVSS Score:</strong> {cve.cvss_score}</p>
        <p><strong>Description:</strong> {cve.description}</p>
        <p><strong>Published:</strong> {cve.published ? new Date(cve.published).toLocaleDateString() : '-'}</p>
        <p><strong>Last Modified:</strong> {cve.last_modified ? new Date(cve.last_modified).toLocaleDateString() : '-'}</p>
        {cve.affected_software && (
          <p><strong>Affected Software:</strong> {cve.affected_software}</p>
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
      {group.cves && group.cves.length > 0 && (
        group.cves.map(renderCVE)
      )}
    </div>
  );

  return (
    <div className="vulnerabilities-section">
      <h2>Device Vulnerabilities</h2>
      {selectedDevice ? (
        <div className="vulnerabilities-list">
          {selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
            selectedDevice.vulnerabilities.map(renderCPEGroup)
          ) : (
            <div className="no-vulnerabilities">
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

export default Vulnerabilities; 