import apiService from './api';

export interface Repository {
  id: string;
  name: string;
  description: string;
  status: 'Analyzing' | 'Analyzed' | 'Failed';
  vulnerabilities?: number;
  lastAnalyzed?: string;
  url: string;
}

export interface AnalysisOptions {
  deepAnalysis: boolean;
  includeDependencies: boolean;
}

/**
 * Service for handling repository-related operations
 */
class RepositoryService {
  /**
   * Get all repositories
   */
  public async getRepositories(): Promise<Repository[]> {
    return await apiService.get<Repository[]>('/repositories');
  }
  
  /**
   * Get a repository by ID
   */
  public async getRepository(id: string): Promise<Repository> {
    return await apiService.get<Repository>(`/repositories/${id}`);
  }
  
  /**
   * Add a new repository for analysis
   */
  public async addRepository(url: string, options: AnalysisOptions): Promise<Repository> {
    return await apiService.post<Repository>('/repositories', { url, options });
  }
  
  /**
   * Start analysis for a repository
   */
  public async analyzeRepository(id: string, options: AnalysisOptions): Promise<Repository> {
    return await apiService.post<Repository>(`/repositories/${id}/analyze`, options);
  }
  
  /**
   * Delete a repository
   */
  public async deleteRepository(id: string): Promise<void> {
    await apiService.delete<void>(`/repositories/${id}`);
  }
  
  /**
   * Get vulnerabilities for a repository
   */
  public async getVulnerabilities(repositoryId: string): Promise<any[]> {
    return await apiService.get<any[]>(`/repositories/${repositoryId}/vulnerabilities`);
  }
  
  /**
   * Cancel ongoing repository analysis
   */
  public async cancelAnalysis(repositoryId: string): Promise<void> {
    await apiService.post<void>(`/repositories/${repositoryId}/cancel`);
  }
}

// Create a singleton instance
const repositoryService = new RepositoryService();

export default repositoryService;