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

  // Group by source
  const renderServiceGroup = (group) => (
    <li key={group.source} className="service-group">
      <header className="service-header">
        <h3>{group.source.toUpperCase()}</h3>
      </header>
      <ul>
        {group.vulnerabilities.map(renderCVE)}
      </ul>
    </li>
  );

  return (
    <section className="vulnerabilities-section">
      <h2>Device Vulnerabilities</h2>
      {selectedDevice ? (
        <>
          {/* Vulnerabilities Section ONLY */}
          <ul className="vulnerabilities-list">
            {selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
              Object.entries(
                selectedDevice.vulnerabilities.reduce((acc, vuln) => {
                  const source = vuln.source || 'unknown';
                  if (!acc[source]) {
                    acc[source] = { source, vulnerabilities: [] };
                  }
                  acc[source].vulnerabilities.push(vuln);
                  return acc;
                }, {})
              ).map(([_, group]) => renderServiceGroup(group))
            ) : (
              <li className="no-vulnerabilities">
                No vulnerabilities detected for {selectedDevice.name || selectedDevice.ip}
              </li>
            )}
          </ul>
        </>
      ) : (
        <div className="no-device-selected">
          Select a device to view its vulnerabilities
        </div>
      )}
    </section>
  );
};

export default Vulnerabilities; 