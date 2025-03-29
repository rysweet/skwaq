import apiService from './api';

export interface EventCallback {
  (eventData: any): void;
}

interface EventSubscription {
  channel: string;
  eventType: string;
  callback: EventCallback;
  id: string;
}

/**
 * Event service for handling real-time updates
 */
class EventService {
  private eventSources: { [key: string]: EventSource } = {};
  private subscriptions: EventSubscription[] = [];
  private connected: { [key: string]: boolean } = {};
  private reconnectTimeouts: { [key: string]: NodeJS.Timeout } = {};
  private baseUrl: string;
  
  constructor() {
    this.baseUrl = process.env.REACT_APP_API_URL || 'http://localhost:5001/api';
  }
  
  /**
   * Subscribe to an event channel
   */
  public subscribe(channel: string, eventType: string, callback: EventCallback): string {
    // Generate a unique subscription ID
    const subscriptionId = Math.random().toString(36).substring(2, 15);
    
    // Add subscription
    this.subscriptions.push({
      channel,
      eventType,
      callback,
      id: subscriptionId
    });
    
    // Connect to the channel if not already connected
    if (!this.eventSources[channel]) {
      this.connectToChannel(channel);
    }
    
    return subscriptionId;
  }
  
  /**
   * Unsubscribe from an event
   */
  public unsubscribe(subscriptionId: string): void {
    const index = this.subscriptions.findIndex(s => s.id === subscriptionId);
    if (index !== -1) {
      this.subscriptions.splice(index, 1);
      
      // Check if we need to disconnect from any channels
      this.cleanupUnusedConnections();
    }
  }
  
  /**
   * Unsubscribe all callbacks for a channel
   */
  public unsubscribeAll(channel: string): void {
    this.subscriptions = this.subscriptions.filter(s => s.channel !== channel);
    this.cleanupUnusedConnections();
  }
  
  /**
   * Connect to an event channel
   */
  private connectToChannel(channel: string): void {
    if (this.eventSources[channel]) {
      return;
    }
    
    try {
      // Use the correct path for SSE connections
      const url = `${this.baseUrl}/events/${channel}`;
      const token = localStorage.getItem('authToken');
      
      // Create EventSource with auth token
      // Note: EventSource doesn't support headers in the constructor in most browsers,
      // so we need to include the token in the URL as a query parameter
      const fullUrl = token ? `${url}?token=${encodeURIComponent(token)}` : url;
      const eventSource = new EventSource(fullUrl);
      
      // Store the event source
      this.eventSources[channel] = eventSource;
      
      // Handle connection events
      eventSource.addEventListener('connection', (event) => {
        const data = JSON.parse(event.data);
        console.log(`Connected to ${channel} channel:`, data);
        this.connected[channel] = true;
      });
      
      // Handle errors
      eventSource.addEventListener('error', (error) => {
        console.error(`Error in ${channel} event stream:`, error);
        this.connected[channel] = false;
        
        // Close and reconnect
        this.disconnectFromChannel(channel);
        
        // Attempt to reconnect after a delay
        this.reconnectTimeouts[channel] = setTimeout(() => {
          console.log(`Attempting to reconnect to ${channel} channel...`);
          this.connectToChannel(channel);
        }, 5000);
      });
      
      // Add listeners for all event types
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Find all matching subscriptions and call their callbacks
          this.subscriptions
            .filter(s => s.channel === channel && (s.eventType === '*' || s.eventType === data.type))
            .forEach(subscription => {
              try {
                subscription.callback(data);
              } catch (callbackError) {
                console.error(`Error in event callback for ${subscription.eventType}:`, callbackError);
              }
            });
        } catch (parseError) {
          console.error(`Error parsing event data for ${channel}:`, parseError, event.data);
        }
      };
    } catch (error) {
      console.error(`Error connecting to ${channel} channel:`, error);
    }
  }
  
  /**
   * Disconnect from an event channel
   */
  private disconnectFromChannel(channel: string): void {
    if (this.eventSources[channel]) {
      try {
        this.eventSources[channel].close();
      } catch (error) {
        console.error(`Error closing ${channel} event source:`, error);
      }
      
      delete this.eventSources[channel];
      this.connected[channel] = false;
      
      // Clear any reconnect timeout
      if (this.reconnectTimeouts[channel]) {
        clearTimeout(this.reconnectTimeouts[channel]);
        delete this.reconnectTimeouts[channel];
      }
    }
  }
  
  /**
   * Clean up unused connections
   */
  private cleanupUnusedConnections(): void {
    const usedChannels = new Set(this.subscriptions.map(s => s.channel));
    
    // Disconnect from any channels that no longer have subscriptions
    Object.keys(this.eventSources).forEach(channel => {
      if (!usedChannels.has(channel)) {
        this.disconnectFromChannel(channel);
      }
    });
  }
  
  /**
   * Disconnect from all channels
   */
  public disconnectAll(): void {
    Object.keys(this.eventSources).forEach(channel => {
      this.disconnectFromChannel(channel);
    });
    
    this.subscriptions = [];
  }
  
  /**
   * Check if a channel is connected
   */
  public isConnected(channel: string): boolean {
    return !!this.connected[channel];
  }
}

// Create a singleton instance
const eventService = new EventService();

export default eventService;