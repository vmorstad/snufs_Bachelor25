import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import '../styles/Barchart.css';

const margin = { top: 30, right: 30, bottom: 50, left: 60 };
const width = 500;
const height = 300;

const Barchart = ({ data }) => {
  const svgRef = useRef();

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // X scale
    const x = d3.scaleBand()
      .domain(data.map(d => d.label))
      .range([margin.left, width - margin.right])
      .padding(0.2);

    // Y scale
    const y = d3.scaleLinear()
      .domain([0, d3.max(data, d => d.value) || 1])
      .nice()
      .range([height - margin.bottom, margin.top]);

    // X axis
    svg.append('g')
      .attr('class', 'axis')
      .attr('transform', `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x))
      .selectAll('text')
      .attr('font-size', '1rem');

    // Y axis
    svg.append('g')
      .attr('class', 'axis')
      .attr('transform', `translate(${margin.left},0)`)
      .call(d3.axisLeft(y).ticks(5))
      .selectAll('text')
      .attr('font-size', '1rem');

    // Bars
    svg.selectAll('.bar')
      .data(data)
      .enter()
      .append('rect')
      .attr('class', 'bar')
      .attr('x', d => x(d.label))
      .attr('y', d => y(d.value))
      .attr('width', x.bandwidth())
      .attr('height', d => y(0) - y(d.value))
      .attr('fill', '#1976d2');

    // Value labels
    svg.selectAll('.bar-label')
      .data(data)
      .enter()
      .append('text')
      .attr('class', 'bar-label')
      .attr('x', d => x(d.label) + x.bandwidth() / 2)
      .attr('y', d => {
        const barTop = y(d.value);
        if (barTop < margin.top + 20) {
          return barTop + 18;
        }
        return barTop - 12;
      })
      .attr('text-anchor', 'middle')
      .attr('font-size', '1rem')
      .attr('font-weight', 600)
      .attr('fill', d => {
        const barTop = y(d.value);
        // If label is inside the bar, use white; otherwise, use black
        return barTop < margin.top + 20 ? '#fff' : '#222';
      })
      .text(d => d.value > 0 ? d.value : '');

    // Chart title
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', margin.top - 10)
      .attr('text-anchor', 'middle')
      .attr('font-size', '1.2rem')
      .attr('font-weight', 600)
      .text('Vulnerability Bar Chart');
  }, [data]);

  return (
    <svg ref={svgRef} width={width} height={height} className="barchart-svg" />
  );
};

export default Barchart; 