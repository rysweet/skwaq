import apiService from './api';

export interface ChatMessage {
  id: number;
  role: 'user' | 'system';
  content: string;
  timestamp?: string;
  parentId?: string;  // For threaded conversations - ID of the parent message
  threadId?: number;  // The thread this message belongs to
}

export interface ChatSession {
  id: string;
  title: string;
  messages: ChatMessage[];
  createdAt: string;
}

/**
 * Service for handling chat interactions
 */
class ChatService {
  /**
   * Get all chat conversations
   */
  public async getChatSessions(): Promise<ChatSession[]> {
    return await apiService.get<ChatSession[]>('/chat/conversations');
  }
  
  /**
   * Get a conversation by ID
   */
  public async getChatSession(id: string): Promise<ChatSession> {
    return await apiService.get<ChatSession>(`/chat/conversations/${id}`);
  }
  
  /**
   * Create a new conversation
   */
  public async createChatSession(title: string): Promise<ChatSession> {
    return await apiService.post<ChatSession>('/chat/conversations', { title });
  }
  
  /**
   * Send a message in a conversation
   */
  public async sendMessage(sessionId: string, content: string): Promise<ChatMessage> {
    return await apiService.post<ChatMessage>(`/chat/conversations/${sessionId}/messages`, { content });
  }
  
  /**
   * Delete a conversation
   */
  public async deleteChatSession(id: string): Promise<void> {
    await apiService.delete<void>(`/chat/conversations/${id}`);
  }
  
  /**
   * Get all messages for a conversation
   */
  public async getMessages(sessionId: string): Promise<ChatMessage[]> {
    return await apiService.get<ChatMessage[]>(`/chat/conversations/${sessionId}/messages`);
  }
  
  /**
   * Stream a chat response (for real-time updates)
   */
  public streamResponse(sessionId: string, content: string, onChunk: (chunk: string) => void): { cancel: () => void } {
    // Create a controller to be able to abort the fetch
    const controller = new AbortController();
    const { signal } = controller;
    
    // Start the fetch in the background
    const token = localStorage.getItem('authToken');
    fetch(`${apiService['api'].defaults.baseURL}/chat/conversations/${sessionId}/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : '',
      },
      body: JSON.stringify({ content }),
      signal,
    }).then(response => {
      // Check the response is ok and has the correct content type
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      if (!response.body) {
        throw new Error('Response body is null');
      }
      
      // Get a reader from the response body
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      
      // Read the stream
      function read(): Promise<void> {
        return reader.read().then(({ done, value }) => {
          if (done) {
            return;
          }
          
          // Decode the chunk and pass it to the callback
          const chunk = decoder.decode(value, { stream: true });
          onChunk(chunk);
          
          // Read the next chunk
          return read();
        });
      }
      
      return read();
    }).catch(error => {
      if (error.name !== 'AbortError') {
        console.error('Error streaming response:', error);
      }
    });
    
    // Return the cancel function
    return {
      cancel: () => controller.abort()
    };
  }
}

// Create a singleton instance
const chatService = new ChatService();

export default chatService;
