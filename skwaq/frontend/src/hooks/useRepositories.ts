import { useState, useEffect, useCallback } from 'react';
import repositoryService, { Repository, AnalysisOptions } from '../services/repositoryService';

/**
 * Custom hook for working with repositories
 */
const useRepositories = () => {
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  
  /**
   * Fetch repositories from the API
   */
  const fetchRepositories = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await repositoryService.getRepositories();
      setRepositories(data);
    } catch (err) {
      setError('Failed to fetch repositories');
      console.error('Error fetching repositories:', err);
    } finally {
      setLoading(false);
    }
  }, []);
  
  /**
   * Add a new repository
   */
  const addRepository = useCallback(async (url: string, options: AnalysisOptions) => {
    try {
      setError(null);
      const newRepo = await repositoryService.addRepository(url, options);
      setRepositories(prev => [...prev, newRepo]);
      return newRepo;
    } catch (err) {
      setError('Failed to add repository');
      console.error('Error adding repository:', err);
      throw err;
    }
  }, []);
  
  /**
   * Start analysis for a repository
   */
  const analyzeRepository = useCallback(async (id: string, options: AnalysisOptions) => {
    try {
      setError(null);
      const updatedRepo = await repositoryService.analyzeRepository(id, options);
      setRepositories(prev => prev.map(repo => repo.id === id ? updatedRepo : repo));
      return updatedRepo;
    } catch (err) {
      setError('Failed to start repository analysis');
      console.error('Error analyzing repository:', err);
      throw err;
    }
  }, []);
  
  /**
   * Delete a repository
   */
  const deleteRepository = useCallback(async (id: string) => {
    try {
      setError(null);
      await repositoryService.deleteRepository(id);
      setRepositories(prev => prev.filter(repo => repo.id !== id));
    } catch (err) {
      setError('Failed to delete repository');
      console.error('Error deleting repository:', err);
      throw err;
    }
  }, []);
  
  /**
   * Cancel ongoing repository analysis
   */
  const cancelAnalysis = useCallback(async (id: string) => {
    try {
      setError(null);
      await repositoryService.cancelAnalysis(id);
      // Update repository status to reflect cancellation
      setRepositories(prev => prev.map(repo => 
        repo.id === id ? { ...repo, status: 'Failed' } : repo
      ));
    } catch (err) {
      setError('Failed to cancel analysis');
      console.error('Error canceling analysis:', err);
      throw err;
    }
  }, []);
  
  // Fetch repositories on mount
  useEffect(() => {
    fetchRepositories();
  }, [fetchRepositories]);
  
  return {
    repositories,
    loading,
    error,
    fetchRepositories,
    addRepository,
    analyzeRepository,
    deleteRepository,
    cancelAnalysis
  };
};

export default useRepositories;