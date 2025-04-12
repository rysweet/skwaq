import { useEffect, useCallback, useState } from 'react';
import eventService, { EventCallback } from '../services/eventService';

/**
 * Hook for subscribing to real-time events
 */
export function useRealTimeEvents(channel: string, eventType: string, callback: EventCallback) {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    // Initial connection state
    setIsConnected(eventService.isConnected(channel));
    
    // Subscribe to connection event to track connection state
    const connectionSubId = eventService.subscribe(channel, 'connection', () => {
      setIsConnected(true);
      setError(null);
    });
    
    // Subscribe to the event
    const subscriptionId = eventService.subscribe(channel, eventType, callback);
    
    // Cleanup on unmount
    return () => {
      eventService.unsubscribe(connectionSubId);
      eventService.unsubscribe(subscriptionId);
    };
  }, [channel, eventType, callback]);
  
  // Function to manually reconnect
  const reconnect = useCallback(() => {
    setError(null);
    eventService.unsubscribeAll(channel);
    
    // Resubscribe to connection event
    eventService.subscribe(channel, 'connection', () => {
      setIsConnected(true);
      setError(null);
    });
    
    // Resubscribe to the event
    eventService.subscribe(channel, eventType, callback);
  }, [channel, eventType, callback]);
  
  return {
    isConnected,
    error,
    reconnect
  };
}

/**
 * Hook for subscribing to multiple events on the same channel
 */
export function useRealTimeMultiEvents(
  channel: string, 
  subscriptions: { eventType: string; callback: EventCallback }[]
) {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    // Initial connection state
    setIsConnected(eventService.isConnected(channel));
    
    // Subscribe to connection event to track connection state
    const connectionSubId = eventService.subscribe(channel, 'connection', () => {
      setIsConnected(true);
      setError(null);
    });
    
    // Subscribe to all events
    const subscriptionIds = subscriptions.map(sub => 
      eventService.subscribe(channel, sub.eventType, sub.callback)
    );
    
    // Cleanup on unmount
    return () => {
      eventService.unsubscribe(connectionSubId);
      subscriptionIds.forEach(id => eventService.unsubscribe(id));
    };
  }, [channel, subscriptions]);
  
  // Function to manually reconnect
  const reconnect = useCallback(() => {
    setError(null);
    eventService.unsubscribeAll(channel);
    
    // Resubscribe to connection event
    eventService.subscribe(channel, 'connection', () => {
      setIsConnected(true);
      setError(null);
    });
    
    // Resubscribe to all events
    subscriptions.forEach(sub => 
      eventService.subscribe(channel, sub.eventType, sub.callback)
    );
  }, [channel, subscriptions]);
  
  return {
    isConnected,
    error,
    reconnect
  };
}