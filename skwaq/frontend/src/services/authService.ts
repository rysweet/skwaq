import apiService from './api';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface UserInfo {
  id: string;
  username: string;
  roles: string[];
}

export interface AuthResponse {
  token: string;
  user: UserInfo;
}

/**
 * Authentication service for handling user authentication
 */
class AuthService {
  /**
   * Login with username and password
   */
  public async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const response = await apiService.post<AuthResponse>('/auth/login', credentials);
    
    // Store token in local storage
    localStorage.setItem('authToken', response.token);
    localStorage.setItem('user', JSON.stringify(response.user));
    
    return response;
  }
  
  /**
   * Logout current user
   */
  public async logout(): Promise<void> {
    try {
      await apiService.post('/auth/logout');
    } catch (error) {
      console.error('Error during logout:', error);
    } finally {
      // Always clear local storage
      localStorage.removeItem('authToken');
      localStorage.removeItem('user');
    }
  }
  
  /**
   * Refresh authentication token
   */
  public async refreshToken(): Promise<AuthResponse> {
    const response = await apiService.post<AuthResponse>('/auth/refresh');
    
    // Update token in local storage
    localStorage.setItem('authToken', response.token);
    localStorage.setItem('user', JSON.stringify(response.user));
    
    return response;
  }
  
  /**
   * Get current user information
   */
  public async getCurrentUser(): Promise<UserInfo | null> {
    try {
      const response = await apiService.get<{ user: UserInfo }>('/auth/me');
      return response.user;
    } catch (error) {
      return null;
    }
  }
  
  /**
   * Check if user is authenticated
   */
  public isAuthenticated(): boolean {
    return !!localStorage.getItem('authToken');
  }
  
  /**
   * Get current user from local storage
   */
  public getUser(): UserInfo | null {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  }
  
  /**
   * Check if user has a specific role
   */
  public hasRole(role: string): boolean {
    const user = this.getUser();
    return user ? user.roles.includes(role) : false;
  }
  
  /**
   * Get authentication token
   */
  public getToken(): string | null {
    return localStorage.getItem('authToken');
  }
}

// Create a singleton instance
const authService = new AuthService();

export default authService;