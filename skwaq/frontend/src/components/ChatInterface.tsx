import React, { useState, useRef, useEffect } from 'react';
import { ChatMessage } from '../services/chatService';
import '../styles/ChatInterface.css';

interface ChatInterfaceProps {
  messages: ChatMessage[];
  onSendMessage: (message: string) => void;
  isLoading: boolean;
}

/**
 * Component for chat interactions with the system
 */
const ChatInterface: React.FC<ChatInterfaceProps> = ({
  messages,
  onSendMessage,
  isLoading
}) => {
  const [message, setMessage] = useState<string>('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim() || isLoading) return;
    
    onSendMessage(message);
    setMessage('');
  };
  
  // Format a message's content with Markdown-like syntax
  const formatMessage = (content: string) => {
    // Replace code blocks with styled pre elements
    const formattedContent = content
      .replace(/```([\s\S]*?)```/g, (_, code) => `<pre class="code-block">${code}</pre>`)
      // Replace inline code with styled code elements
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      // Replace bold text
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      // Replace italic text
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      // Replace links
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
      // Replace newlines with <br>
      .replace(/\n/g, '<br>');
    
    return {__html: formattedContent};
  };
  
  return (
    <div className="chat-interface">
      <div className="chat-messages">
        {messages.length === 0 ? (
          <div className="welcome-message">
            <h2>Welcome to the Vulnerability Assessment Copilot</h2>
            <p>Ask me anything about security vulnerabilities, code analysis, or specific security concepts.</p>
            <div className="suggested-questions">
              <p>Here are some questions to get started:</p>
              <button 
                className="suggested-question"
                onClick={() => onSendMessage('What is SQL injection and how can I prevent it?')}
              >
                What is SQL injection and how can I prevent it?
              </button>
              <button 
                className="suggested-question"
                onClick={() => onSendMessage('How can I find XSS vulnerabilities in JavaScript code?')}
              >
                How can I find XSS vulnerabilities in JavaScript code?
              </button>
              <button 
                className="suggested-question"
                onClick={() => onSendMessage('What are the OWASP Top 10 security risks?')}
              >
                What are the OWASP Top 10 security risks?
              </button>
            </div>
          </div>
        ) : (
          messages.map((msg) => (
            <div key={msg.id} className={`chat-message ${msg.role}`}>
              <div className="message-content" dangerouslySetInnerHTML={formatMessage(msg.content)}></div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>
      
      <form className="chat-input-form" onSubmit={handleSubmit}>
        <input 
          type="text" 
          className="chat-input"
          placeholder={isLoading ? "Please wait..." : "Ask a question..."}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          disabled={isLoading}
        />
        <button 
          type="submit" 
          className={`send-button ${isLoading ? 'loading' : ''}`}
          disabled={isLoading || !message.trim()}
        >
          {isLoading ? '' : 'Send'}
        </button>
      </form>
    </div>
  );
};

export default ChatInterface;