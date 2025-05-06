import React from 'react';

const Guide = () => {
  return (
    <main className="guide-container">
      <header>
        <h1>Network Scanner Guide</h1>
      </header>

      <section className="guide-section">
        <h2>Getting Started</h2>
        <p>Follow these steps to scan your network for devices and vulnerabilities:</p>
        <ol>
          <li>Enter the IP address range you want to scan in the input field at the top</li>
          <li>Click "Scan Network" to begin the scanning process</li>
          <li>View discovered devices in the Device List section</li>
          <li>Select a device to see its vulnerabilities</li>
          <li>Check the Vulnerability Heatmap for a visual representation of security risks</li>
        </ol>
      </section>

      <section className="guide-section">
        <h2>Understanding Results</h2>
        <p>The scanner provides three main views:</p>
        <ul>
          <li><strong>Device List:</strong> Shows all discovered devices on your network</li>
          <li><strong>Device Vulnerabilities:</strong> Displays detailed vulnerability information for selected devices</li>
          <li><strong>Vulnerability Heatmap:</strong> Provides a visual overview of security risks across your network</li>
        </ul>
      </section>
      
      <section className="guide-section">
        <h2>Device List</h2>
        <div className="guide-content">
          <figure className="guide-image">
            <img src={process.env.PUBLIC_URL + '/images/device-list.png'} alt="Device List showing scanned network devices" />
          </figure>
          <div className="guide-text">
            <p>The Device List shows all devices that have been found through scanning.</p>
            <p>When you tap on a device, it expands to show more information related to that specific device — such as the operating system (OS) and any open ports.</p>
          </div>
        </div>
      </section>

      <section className="guide-section">
        <h2>Device Vulnerabilities</h2>
        <div className="guide-content">
          <figure className="guide-image">
            <img src={process.env.PUBLIC_URL + '/images/vulnerabilities.png'} alt="Device Vulnerabilities showing security risks" />
          </figure>
          <div className="guide-text">
            <p>This section gives you an overview of known security risks for the selected device.</p>
            <p>When you click on a device, you'll see a list of its vulnerabilities, including:</p>
            <ul>
              <li><strong>CPE (Common Platform Enumeration):</strong> Gives a unique identifier for an OS, or software with its version.</li>
              <li><strong>CVE (Common Vulnerabilities and Exposures):</strong> A unique ID for each known vulnerability.</li>
              <li><strong>CVSS (Common Vulnerability Scoring System):</strong> A score that rates how serious the vulnerability is.</li>
            </ul>
            <div className="severity-scale">
              <h3>CVSS Score Range (0.1 to 10.0):</h3>
              <ul>
                <li><span className="severity-badge low">Low: 0.1–3.9</span></li>
                <li><span className="severity-badge medium">Medium: 4.0–6.9</span></li>
                <li><span className="severity-badge high">High: 7.0–8.9</span></li>
                <li><span className="severity-badge critical">Critical: 9.0–10.0</span></li>
              </ul>
              <p>This helps you quickly understand the potential risk level.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="guide-section">
        <h2>Vulnerability Visualization</h2>
        <div className="guide-content">
          <figure className="guide-image">
            <img src={process.env.PUBLIC_URL + '/images/heatmap.png'} alt="Vulnerability Heatmap showing security risk distribution" />
          </figure>
          <div className="guide-text">
            <p>The Heatmap gives you a visual overview of all vulnerabilities found on the selected device.</p>
            <p>This makes it easy to spot which devices have the most or most serious issues at a glance.</p>
            <p>You can choose between either seeing a Heatmap, or a Bar chart.</p>
            <div className="heatmap-legend">
              <h3>Color Intensity Guide:</h3>
              <ul>
                <li><span className="heatmap-color critical">Critical Risk</span></li>
                <li><span className="heatmap-color high">High Risk</span></li>
                <li><span className="heatmap-color medium">Medium Risk</span></li>
                <li><span className="heatmap-color low">Low Risk</span></li>
              </ul>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
};

export default Guide; 