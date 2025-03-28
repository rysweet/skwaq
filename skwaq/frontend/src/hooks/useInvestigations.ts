import { useState, useEffect, useCallback } from 'react';
import api from '../services/api';

export interface Investigation {
  id: string;
  title: string;
  repository_id: string;
  repository_name: string;
  creation_date: string;
  status: string;
  findings_count: number;
  vulnerabilities_count: number;
  description: string;
}

export interface InvestigationDetail extends Investigation {
  workflow_id?: string;
  update_date?: string;
}

/**
 * Custom hook for handling investigation data
 */
const useInvestigations = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedInvestigation, setSelectedInvestigation] = useState<InvestigationDetail | null>(null);

  /**
   * Fetch all investigations
   */
  const fetchInvestigations = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      const results = await api.get<Investigation[]>('/api/investigations');
      setInvestigations(results);
    } catch (err) {
      console.error('Error fetching investigations:', err);
      setError('Failed to load investigations');
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Fetch a specific investigation by ID
   */
  const fetchInvestigationById = useCallback(async (id: string) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result = await api.get<InvestigationDetail>(`/api/investigations/${id}`);
      setSelectedInvestigation(result);
      return result;
    } catch (err) {
      console.error(`Error fetching investigation ${id}:`, err);
      setError('Failed to load investigation details');
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Create a new investigation
   */
  const createInvestigation = useCallback(async (investigation: Partial<Investigation>) => {
    try {
      setIsLoading(true);
      setError(null);
      
      const result = await api.post<Investigation>('/api/investigations', investigation);
      setInvestigations(prev => [...prev, result]);
      return result;
    } catch (err) {
      console.error('Error creating investigation:', err);
      setError('Failed to create investigation');
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Load all investigations on component mount
   */
  useEffect(() => {
    fetchInvestigations();
  }, [fetchInvestigations]);

  return {
    investigations,
    selectedInvestigation,
    isLoading,
    error,
    fetchInvestigations,
    fetchInvestigationById,
    createInvestigation,
    setSelectedInvestigation
  };
};

export default useInvestigations;