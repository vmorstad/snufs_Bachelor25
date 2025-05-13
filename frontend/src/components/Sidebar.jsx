import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import '../styles/Sidebar.css';

const Sidebar = () => {
  const location = useLocation();
  return (
    <div className="sidebar">
      <nav className="nav-items">
        <Link to="/" className={`nav-item${location.pathname === '/' ? ' active' : ''}`}>Home</Link>
        <Link to="/guide" className={`nav-item${location.pathname === '/guide' ? ' active' : ''}`}>Guide</Link>
      </nav>
    </div>
  );
};

export default Sidebar; 