import React from 'react';
import { useDevices } from '../context/DeviceContext';
import '../styles/Vulnerabilities.css';

const Vulnerabilities = () => {
  const { selectedDevice } = useDevices();

  const renderCVE = (cve) => (
    <article className={`vulnerability-card ${cve.severity?.toLowerCase() || 'unknown'}`} key={cve.cve_id}>
      <header className="vulnerability-header">
        <h3>{cve.cve_id}</h3>
        <span className={`severity-badge ${cve.severity?.toLowerCase() || 'unknown'}`}>{cve.severity}</span>
      </header>
      <section className="vulnerability-content">
        <p><strong>CVSS Score:</strong> {cve.cvss_score}</p>
        <p><strong>Description:</strong> {cve.description}</p>
        <p><strong>Published:</strong> {cve.published ? new Date(cve.published).toLocaleDateString() : '-'}</p>
        <p><strong>Last Modified:</strong> {cve.last_modified ? new Date(cve.last_modified).toLocaleDateString() : '-'}</p>
        {cve.affected_software && (
          <p><strong>Affected Software:</strong> {cve.affected_software}</p>
        )}
      </section>
    </article>
  );

  const renderCPEGroup = (group) => (
    <li key={group.cpe} className="cpe-group">
      <header className="cpe-header">
        <h3>{group.cpe_title}</h3>
        <span className="cpe-id">{group.cpe}</span>
      </header>
      {group.cves && group.cves.length > 0 && (
        <ul>
          {group.cves.map(renderCVE)}
        </ul>
      )}
    </li>
  );

  return (
    <section className="vulnerabilities-section">
      <h2>Device Vulnerabilities</h2>
      {selectedDevice ? (
        <ul className="vulnerabilities-list">
          {selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
            selectedDevice.vulnerabilities.map(renderCPEGroup)
          ) : (
            <li className="no-vulnerabilities">
              No vulnerabilities detected for {selectedDevice.name || selectedDevice.ip}
            </li>
          )}
        </ul>
      ) : (
        <div className="no-device-selected">
          Select a device to view its vulnerabilities
        </div>
      )}
    </section>
  );
};

export default Vulnerabilities; 