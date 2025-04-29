import { useState, useEffect, useCallback } from 'react';
import api from '../services/api';

export interface Finding {
  id: string;
  title: string;
  description: string;
  location?: string;
  severity?: string;
  type?: string;
  status?: string;
}

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
  findings?: Finding[];
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
      
      console.log('Fetching investigations...');
      const results = await api.get<Investigation[]>('/investigations');
      console.log('Received investigations:', results);
      setInvestigations(results || []);
    } catch (err: any) {
      console.error('Error fetching investigations:', err);
      // Log more detailed error information
      if (err.response) {
        // The request was made and the server responded with a status code outside of 2xx
        console.error('Error response data:', err.response.data);
        console.error('Error response status:', err.response.status);
        console.error('Error response headers:', err.response.headers);
        setError(`Failed to load investigations: ${err.response.status} ${err.response.statusText}`);
      } else if (err.request) {
        // The request was made but no response was received
        console.error('No response received:', err.request);
        setError('Failed to load investigations: No response from server');
      } else {
        // Something happened in setting up the request that triggered an Error
        console.error('Error message:', err.message);
        setError(`Failed to load investigations: ${err.message}`);
      }
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
      
      const result = await api.get<InvestigationDetail>(`/investigations/${id}`);
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
      
      const result = await api.post<Investigation>('/investigations', investigation);
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