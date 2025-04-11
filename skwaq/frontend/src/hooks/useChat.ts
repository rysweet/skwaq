import { useState, useEffect, useCallback } from 'react';
import chatService, { ChatMessage, ChatSession } from '../services/chatService';

/**
 * Custom hook for handling chat interactions
 */
const useChat = (sessionId?: string) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSession, setActiveSession] = useState<ChatSession | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [streamingResponse, setStreamingResponse] = useState<boolean>(false);
  
  /**
   * Fetch all chat sessions
   */
  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await chatService.getChatSessions();
      setSessions(data);
    } catch (err) {
      setError('Failed to fetch chat sessions');
      console.error('Error fetching chat sessions:', err);
    } finally {
      setLoading(false);
    }
  }, []);
  
  /**
   * Fetch messages for the active session
   */
  const fetchMessages = useCallback(async (id: string) => {
    try {
      setLoading(true);
      setError(null);
      const data = await chatService.getMessages(id);
      setMessages(data);
    } catch (err) {
      setError('Failed to fetch chat messages');
      console.error('Error fetching chat messages:', err);
    } finally {
      setLoading(false);
    }
  }, []);
  
  /**
   * Send a message and get a response
   */
  const sendMessage = useCallback(async (content: string) => {
    if (!activeSession) return;
    
    try {
      setError(null);
      
      // Add user message to the list
      const userMessage: ChatMessage = {
        id: Date.now(),
        role: 'user',
        content,
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, userMessage]);
      
      // Add placeholder for system response
      const placeholderId = Date.now() + 1;
      const placeholderMessage: ChatMessage = {
        id: placeholderId,
        role: 'system',
        content: '',
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, placeholderMessage]);
      
      // Start streaming response
      setStreamingResponse(true);
      let responseContent = '';
      
      const { cancel } = chatService.streamResponse(
        activeSession.id,
        content,
        (chunk) => {
          responseContent += chunk;
          setMessages(prev => 
            prev.map(msg => 
              msg.id === placeholderId 
                ? { ...msg, content: responseContent } 
                : msg
            )
          );
        }
      );
      
      // Clean up streaming when done
      return () => {
        cancel();
        setStreamingResponse(false);
      };
    } catch (err) {
      setError('Failed to send message');
      console.error('Error sending message:', err);
      
      // Update placeholder message to show error
      setMessages(prev => 
        prev.map(msg => 
          msg.role === 'system' && msg.content === '' 
            ? { ...msg, content: 'Failed to get a response. Please try again.' } 
            : msg
        )
      );
      
      setStreamingResponse(false);
    }
  }, [activeSession]);
  
  /**
   * Create a new chat session
   */
  const createSession = useCallback(async (title: string) => {
    try {
      setLoading(true);
      setError(null);
      const newSession = await chatService.createChatSession(title);
      setSessions(prev => [...prev, newSession]);
      setActiveSession(newSession);
      setMessages([]);
      return newSession;
    } catch (err) {
      setError('Failed to create chat session');
      console.error('Error creating chat session:', err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);
  
  /**
   * Delete a chat session
   */
  const deleteSession = useCallback(async (id: string) => {
    try {
      setLoading(true);
      setError(null);
      await chatService.deleteChatSession(id);
      setSessions(prev => prev.filter(session => session.id !== id));
      
      // If the active session was deleted, clear it
      if (activeSession?.id === id) {
        setActiveSession(null);
        setMessages([]);
      }
    } catch (err) {
      setError('Failed to delete chat session');
      console.error('Error deleting chat session:', err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [activeSession]);
  
  /**
   * Set the active chat session
   */
  const setActiveSessionById = useCallback(async (id: string) => {
    try {
      setLoading(true);
      setError(null);
      const session = await chatService.getChatSession(id);
      setActiveSession(session);
      fetchMessages(id);
    } catch (err) {
      setError('Failed to fetch chat session');
      console.error('Error fetching chat session:', err);
    } finally {
      setLoading(false);
    }
  }, [fetchMessages]);
  
  // Fetch sessions and active session on mount
  useEffect(() => {
    fetchSessions();
    
    if (sessionId) {
      setActiveSessionById(sessionId);
    }
  }, [fetchSessions, sessionId, setActiveSessionById]);
  
  return {
    messages,
    sessions,
    activeSession,
    loading,
    error,
    streamingResponse,
    sendMessage,
    createSession,
    deleteSession,
    setActiveSessionById,
    fetchMessages,
    fetchSessions
  };
};

export default useChat;