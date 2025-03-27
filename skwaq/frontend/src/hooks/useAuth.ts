import { useState, useEffect, useCallback } from 'react';
import authService, { LoginCredentials, UserInfo } from '../services/authService';

/**
 * Authentication hook for managing user authentication state
 */
export function useAuth() {
  const [user, setUser] = useState<UserInfo | null>(authService.getUser());
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(authService.isAuthenticated());
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    // Check authentication status on mount
    const checkAuth = async () => {
      if (authService.isAuthenticated()) {
        try {
          const currentUser = await authService.getCurrentUser();
          setUser(currentUser);
          setIsAuthenticated(!!currentUser);
        } catch (error) {
          // Token might be invalid, clear authentication
          handleLogout();
        }
      }
    };
    
    checkAuth();
  }, []);
  
  /**
   * Login with username and password
   */
  const login = useCallback(async (credentials: LoginCredentials) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await authService.login(credentials);
      setUser(response.user);
      setIsAuthenticated(true);
      return response;
    } catch (error: any) {
      setError(error.response?.data?.error || 'Login failed');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  /**
   * Logout current user
   */
  const handleLogout = useCallback(async () => {
    setIsLoading(true);
    
    try {
      await authService.logout();
    } finally {
      setUser(null);
      setIsAuthenticated(false);
      setIsLoading(false);
    }
  }, []);
  
  /**
   * Refresh authentication token
   */
  const refreshToken = useCallback(async () => {
    if (!isAuthenticated) return;
    
    setIsLoading(true);
    
    try {
      const response = await authService.refreshToken();
      setUser(response.user);
      return response;
    } catch (error) {
      // If refresh fails, logout
      handleLogout();
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, handleLogout]);
  
  /**
   * Check if user has a specific role
   */
  const hasRole = useCallback((role: string) => {
    return user ? user.roles.includes(role) : false;
  }, [user]);
  
  return {
    user,
    isAuthenticated,
    isLoading,
    error,
    login,
    logout: handleLogout,
    refreshToken,
    hasRole
  };
}