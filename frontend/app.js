document.getElementById('scanButton').addEventListener('click', function() {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = 'Scanning...';
    
    // Adjust the URL if your back-end is hosted on a different port or domain.
    fetch('http://localhost:5000/api/scan')
      .then(response => response.json())
      .then(data => {
        let html = '<h2>Scan Results:</h2>';
        data.forEach(device => {
          html += `<h3>Device: ${device.ip}</h3>`;
          html += `<p>Open Ports: ${device.open_ports.join(', ')}</p>`;
          if (device.vulnerabilities.length > 0) {
            html += '<ul>';
            device.vulnerabilities.forEach(vuln => {
              html += `<li><strong>${vuln.id}</strong>: ${vuln.description} (Severity: ${vuln.severity})</li>`;
            });
            html += '</ul>';
          } else {
            html += '<p>No vulnerabilities found.</p>';
          }
        });
        resultsDiv.innerHTML = html;
      })
      .catch(err => {
        resultsDiv.innerHTML = 'Error: ' + err;
      });
  });
  