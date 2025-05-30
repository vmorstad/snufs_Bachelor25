import React, { useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import { useDevices } from '../context/DeviceContext';
import '../styles/Heatmap.css';

const margin = { top: 50, right: 30, bottom: 110, left: 275 };
const width = 1200;
const baseHeight = 420;
const severities = ['unknown', 'low', 'medium', 'high', 'critical'];
const severityLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  unknown: 'Unknown',
};
const colorScale = d3.scaleLinear()
  .domain([0, 1, 5, 10])
  .range(['#f9fafb', '#ffc107', '#fd7e14', '#d32f2f']);

function wrapText(text, maxLen = 10) {
  if (text.length <= maxLen) return [text];
  // Try to break at a space near the middle
  const idx = text.lastIndexOf(' ', maxLen);
  if (idx > 0) return [text.slice(0, idx), text.slice(idx + 1)];
  return [text.slice(0, maxLen), text.slice(maxLen)];
}

function truncateText(text, maxLen = 18) {
  return text.length > maxLen ? text.slice(0, maxLen - 3) + '...' : text;
}

const Heatmap = () => {
  const { selectedDevice } = useDevices();
  const svgRef = useRef();

  // Memoize service labels, label lines, rowHeights, rowYs, and matrix
  const { serviceLabels, labelLines, rowHeights, rowYs, matrix } = useMemo(() => {
    let matrix = [];
    let serviceLabels = [];
    let labelLines = [];
    let rowHeights = [];
    let rowYs = [];
    const minCellHeight = 32;
    const lineHeight = 18;
    if (selectedDevice && selectedDevice.vulnerabilities) {
      // Group vulnerabilities by source
      const groupedVulns = selectedDevice.vulnerabilities.reduce((acc, vuln) => {
        const source = vuln.source || 'unknown';
        if (!acc[source]) {
          acc[source] = [];
        }
        acc[source].push(vuln);
        return acc;
      }, {});

      serviceLabels = Object.keys(groupedVulns);
      labelLines = serviceLabels.map(label => wrapText(truncateText(label, 18), 10));
      rowHeights = labelLines.map(lines => Math.max(minCellHeight, lines.length * lineHeight + 8));
      // Calculate cumulative Y positions for each row
      rowYs = rowHeights.reduce((acc, h, i) => {
        if (i === 0) return [margin.top];
        acc.push(acc[i - 1] + rowHeights[i - 1]);
        return acc;
      }, []);
      matrix = serviceLabels.flatMap((service, rowIdx) => {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
        groupedVulns[service].forEach(vuln => {
          const sev = (vuln.severity || 'unknown').toLowerCase();
          if (counts[sev] !== undefined) counts[sev]++;
          else counts.unknown++;
        });
        return severities.map((sev, colIdx) => ({
          serviceIdx: rowIdx,
          severity: sev,
          count: counts[sev],
          service: service,
        }));
      });
    }
    return { serviceLabels, labelLines, rowHeights, rowYs, matrix };
  }, [selectedDevice]);

  // Dynamically adjust SVG height based on sum of all row heights
  const dynamicHeight = Math.max(baseHeight, margin.top + margin.bottom + (rowHeights.length > 0 ? rowHeights.reduce((a, b) => a + b, 0) : 0) + 30);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    if (!serviceLabels.length) return;

    const cellWidth = (width - margin.left - margin.right) / severities.length;

    // Draw cells
    svg.selectAll('rect')
      .data(matrix)
      .enter()
      .append('rect')
      .attr('x', d => margin.left + severities.indexOf(d.severity) * cellWidth)
      .attr('y', d => rowYs[d.serviceIdx])
      .attr('width', cellWidth - 4)
      .attr('height', d => rowHeights[d.serviceIdx] - 4)
      .attr('fill', d => colorScale(d.count))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)
      .attr('rx', 6)
      .attr('ry', 6)
      .style('cursor', d => d.count > 0 ? 'pointer' : 'default')
      .on('mouseover', function (event, d) {
        d3.select(this).attr('stroke', '#333').attr('stroke-width', 3);
      })
      .on('mouseout', function (event, d) {
        d3.select(this).attr('stroke', '#fff').attr('stroke-width', 2);
      })
      .append('title')
      .text(d => `${d.service}\n${severityLabels[d.severity]}: ${d.count} CVEs`);

    // Add count text (centered, only if count > 0)
    svg.selectAll('text.cell-count')
      .data(matrix)
      .enter()
      .append('text')
      .attr('class', 'cell-count')
      .attr('x', d => margin.left + severities.indexOf(d.severity) * cellWidth + cellWidth / 2)
      .attr('y', d => rowYs[d.serviceIdx] + rowHeights[d.serviceIdx] / 2 + 6)
      .attr('text-anchor', 'middle')
      .attr('font-size', '1.1rem')
      .attr('font-weight', 600)
      .attr('fill', d => d.count > 0 ? '#222' : '#bbb')
      .text(d => d.count > 0 ? d.count : '');

    // Y axis (Service group) with improved wrapping, truncation, and tooltip
    svg.selectAll('g.service-label-group')
      .data(labelLines)
      .enter()
      .append('g')
      .attr('class', 'service-label-group')
      .attr('transform', (d, i) => `translate(${margin.left - 12},${rowYs[i] + rowHeights[i] / 2})`)
      .each(function (d, i) {
        d3.select(this)
          .append('text')
          .attr('class', 'service-label')
          .attr('x', 0)
          .attr('y', 6)
          .attr('text-anchor', 'end')
          .attr('font-size', '1rem')
          .attr('font-weight', 500)
          .attr('fill', '#333')
          .text(serviceLabels[i]);
        d3.select(this).append('title').text(serviceLabels[i]);
      });

    // X axis (Severity)
    svg.selectAll('text.severity-label')
      .data(severities)
      .enter()
      .append('text')
      .attr('class', 'severity-label')
      .attr('x', (d, i) => margin.left + i * cellWidth + cellWidth / 2)
      .attr('y', margin.top - 18)
      .attr('text-anchor', 'middle')
      .attr('font-size', '1.1rem')
      .attr('font-weight', 600)
      .attr('fill', '#333')
      .text(d => severityLabels[d]);

    // Color legend
    const legendX = margin.left;
    const legendY = dynamicHeight - margin.bottom + 70;
    const legendWidth = 340;
    const legendHeight = 16;
    const legendScale = d3.scaleLinear().domain([0, 10]).range([0, legendWidth]);
    const legendAxis = d3.axisBottom(legendScale).ticks(5).tickFormat(d3.format('.0f'));
    // Gradient
    const defs = svg.append('defs');
    const gradient = defs.append('linearGradient')
      .attr('id', 'heatmap-gradient')
      .attr('x1', '0%').attr('y1', '0%').attr('x2', '100%').attr('y2', '0%');
    gradient.append('stop').attr('offset', '0%').attr('stop-color', '#f9fafb');
    gradient.append('stop').attr('offset', '25%').attr('stop-color', '#ffc107');
    gradient.append('stop').attr('offset', '60%').attr('stop-color', '#fd7e14');
    gradient.append('stop').attr('offset', '100%').attr('stop-color', '#d32f2f');
    svg.append('rect')
      .attr('x', legendX)
      .attr('y', legendY)
      .attr('width', legendWidth)
      .attr('height', legendHeight)
      .style('fill', 'url(#heatmap-gradient)');
    svg.append('g')
      .attr('transform', `translate(${legendX},${legendY + legendHeight})`)
      .call(legendAxis)
      .selectAll('text')
      .attr('font-size', '0.9rem');
    svg.append('text')
      .attr('x', legendX)
      .attr('y', legendY - 6)
      .attr('font-size', '0.9rem')
      .attr('fill', '#333')
      .text('Number of CVEs');
  }, [serviceLabels, labelLines, rowHeights, rowYs, matrix]);

  return (
    <section className="heatmap-section">
      <h2>Vulnerability Heatmap</h2>
      {selectedDevice ? (
        serviceLabels.length > 0 ? (
          <svg ref={svgRef} width={width} height={dynamicHeight} />
        ) : (
          <div className="no-heatmap">No vulnerabilities to visualize for this device.</div>
        )
      ) : (
        <div className="no-heatmap">Select a device to view its vulnerability heatmap.</div>
      )}
    </section>
  );
};

export default Heatmap; 