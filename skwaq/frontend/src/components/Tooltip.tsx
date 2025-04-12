import React, { useState, useRef, useEffect } from 'react';
import '../styles/Tooltip.css';

interface TooltipProps {
  children: React.ReactNode;
  content: string;
  position?: 'top' | 'right' | 'bottom' | 'left';
  maxWidth?: number;
}

/**
 * Tooltip component for displaying additional information on hover
 */
const Tooltip: React.FC<TooltipProps> = ({
  children,
  content,
  position = 'top',
  maxWidth = 250
}) => {
  const [isVisible, setIsVisible] = useState<boolean>(false);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltipPosition, setTooltipPosition] = useState({ top: 0, left: 0 });

  // Calculate tooltip position based on target and position prop
  const calculatePosition = () => {
    if (!containerRef.current || !tooltipRef.current) return;

    const containerRect = containerRef.current.getBoundingClientRect();
    const tooltipRect = tooltipRef.current.getBoundingClientRect();
    const windowWidth = window.innerWidth;
    const windowHeight = window.innerHeight;
    
    let top = 0;
    let left = 0;

    switch (position) {
      case 'top':
        top = -tooltipRect.height - 10;
        left = (containerRect.width - tooltipRect.width) / 2;
        break;
      case 'right':
        top = (containerRect.height - tooltipRect.height) / 2;
        left = containerRect.width + 10;
        break;
      case 'bottom':
        top = containerRect.height + 10;
        left = (containerRect.width - tooltipRect.width) / 2;
        break;
      case 'left':
        top = (containerRect.height - tooltipRect.height) / 2;
        left = -tooltipRect.width - 10;
        break;
    }

    // Adjust if tooltip would go off-screen
    const absoluteLeft = containerRect.left + left;
    const absoluteTop = containerRect.top + top;

    if (absoluteLeft < 0) {
      left = position === 'left' ? containerRect.width + 10 : -containerRect.left + 10;
    } else if (absoluteLeft + tooltipRect.width > windowWidth) {
      left = position === 'right' ? -tooltipRect.width - 10 : windowWidth - containerRect.left - tooltipRect.width - 10;
    }

    if (absoluteTop < 0) {
      top = position === 'top' ? containerRect.height + 10 : -containerRect.top + 10;
    } else if (absoluteTop + tooltipRect.height > windowHeight) {
      top = position === 'bottom' ? -tooltipRect.height - 10 : windowHeight - containerRect.top - tooltipRect.height - 10;
    }

    setTooltipPosition({ top, left });
  };

  // Recalculate position when tooltip becomes visible
  useEffect(() => {
    if (isVisible) {
      calculatePosition();
    }
  }, [isVisible]);

  // Update position on window resize
  useEffect(() => {
    const handleResize = () => {
      if (isVisible) {
        calculatePosition();
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isVisible]);

  return (
    <div 
      className="tooltip-container"
      ref={containerRef}
      onMouseEnter={() => setIsVisible(true)} 
      onMouseLeave={() => setIsVisible(false)}
      onFocus={() => setIsVisible(true)}
      onBlur={() => setIsVisible(false)}
    >
      {children}
      {isVisible && (
        <div 
          className={`tooltip tooltip-${position}`}
          ref={tooltipRef}
          style={{ 
            top: tooltipPosition.top, 
            left: tooltipPosition.left,
            maxWidth
          }}
        >
          <div className="tooltip-content">{content}</div>
          <div className={`tooltip-arrow tooltip-arrow-${position}`}></div>
        </div>
      )}
    </div>
  );
};

export default Tooltip;