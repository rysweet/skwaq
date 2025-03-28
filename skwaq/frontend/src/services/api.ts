import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

/**
 * API service for handling communication with the backend
 */
class ApiService {
  private api: AxiosInstance;
  
  constructor() {
    // Create axios instance
    this.api = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
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
      (response) => response,
      (error) => {
        // Handle specific error codes
        if (error.response) {
          switch (error.response.status) {
            case 401:
              // Handle unauthorized error
              console.error('Unauthorized access');
              break;
            case 403:
              // Handle forbidden error
              console.error('Forbidden access');
              break;
            case 404:
              // Handle not found error
              console.error('Resource not found');
              break;
            default:
              // Handle other errors
              console.error('API error:', error.response.data);
          }
        } else if (error.request) {
          // Handle network errors
          console.error('Network error, no response received');
        } else {
          // Handle other errors
          console.error('Error:', error.message);
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