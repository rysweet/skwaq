import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

/**
 * API service for handling communication with the backend
 */
class ApiService {
  private api: AxiosInstance;
  
  constructor() {
    // Create axios instance
    this.api = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5001/api',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    // Make sure baseURL points to port 5001
    if (this.api.defaults.baseURL && !this.api.defaults.baseURL.includes('5001')) {
      console.log('Updating API base URL to use port 5001');
      this.api.defaults.baseURL = 'http://localhost:5001/api';
    }
    
    // Add request interceptor for auth header
    this.api.interceptors.request.use(
      (config) => {
        // Add auth token if it exists
        const token = this.getAuthToken();
        if (token && config.headers) {
          config.headers['Authorization'] = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
    
    // Add response interceptor for error handling
    this.api.interceptors.response.use(
      (response) => {
        console.log('API Response:', {
          url: response.config.url,
          method: response.config.method,
          status: response.status,
          data: response.data
        });
        return response;
      },
      (error) => {
        // Handle specific error codes
        console.log('API Error:', error);
        
        // Create a visible error notification in development
        const createErrorNotification = (message: string) => {
          if (process.env.NODE_ENV === 'development') {
            // Create a floating error notification
            const notification = document.createElement('div');
            notification.style.position = 'fixed';
            notification.style.bottom = '20px';
            notification.style.right = '20px';
            notification.style.backgroundColor = '#f8d7da';
            notification.style.color = '#721c24';
            notification.style.padding = '15px';
            notification.style.borderRadius = '4px';
            notification.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
            notification.style.maxWidth = '400px';
            notification.style.zIndex = '9999';
            
            const title = document.createElement('div');
            title.style.fontWeight = 'bold';
            title.style.marginBottom = '5px';
            title.textContent = 'API Error';
            
            const content = document.createElement('div');
            content.textContent = message;
            
            const closeButton = document.createElement('button');
            closeButton.textContent = '×';
            closeButton.style.position = 'absolute';
            closeButton.style.top = '5px';
            closeButton.style.right = '10px';
            closeButton.style.border = 'none';
            closeButton.style.background = 'none';
            closeButton.style.fontSize = '20px';
            closeButton.style.cursor = 'pointer';
            closeButton.style.color = '#721c24';
            closeButton.onclick = () => document.body.removeChild(notification);
            
            notification.appendChild(title);
            notification.appendChild(content);
            notification.appendChild(closeButton);
            
            document.body.appendChild(notification);
            
            // Auto-remove after 10 seconds
            setTimeout(() => {
              if (document.body.contains(notification)) {
                document.body.removeChild(notification);
              }
            }, 10000);
          }
        };
        
        if (error.response) {
          console.error('API Error Response:', {
            url: error.config?.url,
            method: error.config?.method,
            status: error.response.status,
            data: error.response.data
          });
          
          let message = '';
          
          switch (error.response.status) {
            case 401:
              // Handle unauthorized error
              message = 'Unauthorized access - Please log in again';
              console.error('Unauthorized access');
              break;
            case 403:
              // Handle forbidden error
              message = 'Forbidden access - You do not have permission for this action';
              console.error('Forbidden access');
              break;
            case 404:
              // Handle not found error
              message = `Resource not found: ${error.config?.url}`;
              console.error('Resource not found');
              break;
            default:
              // Handle other errors
              message = `API error (${error.response.status}): ${JSON.stringify(error.response.data)}`;
              console.error('API error:', error.response.data);
          }
          
          createErrorNotification(message);
        } else if (error.request) {
          // Handle network errors
          const message = `Network error: No response received from ${error.config?.url}`;
          console.error('Network error details:', {
            url: error.config?.url,
            method: error.config?.method,
            message: 'No response received'
          });
          createErrorNotification(message);
        } else {
          // Handle other errors
          const message = `API Error: ${error.message}`;
          console.error('API Error:', {
            message: error.message,
            config: error.config
          });
          createErrorNotification(message);
        }
        
        return Promise.reject(error);
      }
    );
  }
  
  /**
   * Get the authentication token from local storage
   */
  private getAuthToken(): string | null {
    return localStorage.getItem('authToken');
  }
  
  /**
   * Make a GET request to the API
   */
  public async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.api.get<T>(url, config);
    // The API can return either directly serialized data or a { data: T } wrapper
    return (response.data && response.data.hasOwnProperty('data')) 
      ? (response.data as any).data 
      : response.data;
  }
  
  /**
   * Make a POST request to the API
   */
  public async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.api.post<T>(url, data, config);
    return (response.data && response.data.hasOwnProperty('data')) 
      ? (response.data as any).data 
      : response.data;
  }
  
  /**
   * Make a PUT request to the API
   */
  public async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.api.put<T>(url, data, config);
    return (response.data && response.data.hasOwnProperty('data')) 
      ? (response.data as any).data 
      : response.data;
  }
  
  /**
   * Make a DELETE request to the API
   */
  public async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.api.delete<T>(url, config);
    return (response.data && response.data.hasOwnProperty('data')) 
      ? (response.data as any).data 
      : response.data;
  }
}

// Create a singleton instance
const apiService = new ApiService();

export default apiService;