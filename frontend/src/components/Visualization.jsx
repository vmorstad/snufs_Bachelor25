import React, { useState } from 'react';
import Heatmap from './Heatmap';
import Barchart from './Barchart';
import '../styles/Visualization.css';

const severities = ['Unknown', 'Low', 'Medium', 'High', 'Critical'];

function getSeverityCounts(data) {
  // data: array of CPE groups, each with a cves array
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
  data.forEach(group => {
    (group.cves || []).forEach(cve => {
      const sev = (cve.severity || 'Unknown').toLowerCase();
      if (sev === 'critical') counts.Critical++;
      else if (sev === 'high') counts.High++;
      else if (sev === 'medium') counts.Medium++;
      else if (sev === 'low') counts.Low++;
      else counts.Unknown++;
    });
  });
  return severities.map(label => ({ label, value: counts[label] }));
}

const Visualization = ({ data }) => {
  const [view, setView] = useState('heatmap');
  const barData = getSeverityCounts(data);

  return (
    <div className="visualization-container">
      <div className="visualization-toggle">
        <button
          className={view === 'heatmap' ? 'active' : ''}
          onClick={() => setView('heatmap')}
        >
          Heatmap
        </button>
        <button
          className={view === 'barchart' ? 'active' : ''}
          onClick={() => setView('barchart')}
        >
          Barchart
        </button>
      </div>
      {view === 'heatmap' ? (
        <Heatmap data={data} />
      ) : (
        <Barchart data={barData} />
      )}
    </div>
  );
};

export default Visualization; 