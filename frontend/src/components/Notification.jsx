import React, { useEffect } from 'react';
import '../styles/Notification.css';

const Notification = ({ message, type = 'success', onClose }) => {
  useEffect(() => {
    // Auto-close notification after 5 seconds
    const timer = setTimeout(() => {
      onClose();
    }, 5000);

    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <div className={`notification ${type}`}>
      <div className="notification-content">
        <span className="notification-message">{message}</span>
        <button className="notification-close" onClick={onClose}>×</button>
      </div>
    </div>
  );
};

export default Notification; 