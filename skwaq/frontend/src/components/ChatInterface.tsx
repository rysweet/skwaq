import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { tomorrow } from 'react-syntax-highlighter/dist/esm/styles/prism';
import remarkGfm from 'remark-gfm';
import { ChatMessage } from '../services/chatService';
import '../styles/ChatInterface.css';

interface ChatInterfaceProps {
  messages: ChatMessage[];
  onSendMessage: (message: string, parentId?: number) => void;
  isLoading: boolean;
  darkMode?: boolean;
}

interface ThreadInfo {
  [key: string]: {
    isOpen: boolean;
    replies: number[];
  }
}

/**
 * Component for chat interactions with the system
 */
const ChatInterface: React.FC<ChatInterfaceProps> = ({
  messages,
  onSendMessage,
  isLoading,
  darkMode = false
}) => {
  const [message, setMessage] = useState<string>('');
  const [replyingTo, setReplyingTo] = useState<number | null>(null);
  const [threads, setThreads] = useState<ThreadInfo>({});
  const [showFormatting, setShowFormatting] = useState<boolean>(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  
  // Process messages into threads
  useEffect(() => {
    const newThreads: ThreadInfo = {};
    
    messages.forEach(msg => {
      if (msg.parentId) {
        const parentIdStr = msg.parentId.toString();
        if (!newThreads[parentIdStr]) {
          newThreads[parentIdStr] = { isOpen: true, replies: [] };
        }
        newThreads[parentIdStr].replies.push(msg.id);
      }
    });
    
    setThreads(newThreads);
  }, [messages]);
  
  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);
  
  // Handle textarea resize
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [message]);
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim() || isLoading) return;
    
    onSendMessage(message, replyingTo || undefined);
    setMessage('');
    setReplyingTo(null);
    
    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  };
  
  const handleInsertCode = (language: string = '') => {
    const prefix = '```' + language + '\n';
    const suffix = '\n```';
    
    // Get cursor position
    const cursorPos = textareaRef.current?.selectionStart || 0;
    const textBefore = message.substring(0, cursorPos);
    const textAfter = message.substring(cursorPos);
    
    // Insert code block
    setMessage(textBefore + prefix + suffix + textAfter);
    
    // Focus and place cursor inside the code block
    setTimeout(() => {
      if (textareaRef.current) {
        const newCursorPos = textBefore.length + prefix.length;
        textareaRef.current.focus();
        textareaRef.current.setSelectionRange(newCursorPos, newCursorPos);
      }
    }, 0);
  };
  
  const toggleThread = (parentId: number) => {
    setThreads(prev => ({
      ...prev,
      [parentId.toString()]: {
        ...prev[parentId.toString()],
        isOpen: !prev[parentId.toString()].isOpen
      }
    }));
  };
  
  const startReply = (parentId: number) => {
    setReplyingTo(parentId);
    textareaRef.current?.focus();
  };
  
  const cancelReply = () => {
    setReplyingTo(null);
  };
  
  const renderMessage = (msg: ChatMessage, isReply: boolean = false) => {
    const msgIdStr = msg.id.toString();
    const isThreadParent = threads[msgIdStr] && threads[msgIdStr].replies.length > 0;
    const replyCount = isThreadParent ? threads[msgIdStr].replies.length : 0;
    const isThreadOpen = isThreadParent && threads[msgIdStr].isOpen;
    
    return (
      <React.Fragment key={msg.id}>
        <div className={`chat-message ${msg.role} ${isReply ? 'reply' : ''} ${darkMode ? 'dark' : ''}`}>
          <div className="message-avatar">
            {msg.role === 'user' ? '👤' : '🤖'}
          </div>
          <div className="message-body">
            <div className="message-header">
              <span className="message-sender">{msg.role === 'user' ? 'You' : 'Assistant'}</span>
              <span className="message-time">{msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}</span>
            </div>
            <div className="message-content">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  code({node, inline, className, children, ...props}: any) {
                    const match = /language-(\w+)/.exec(className || '');
                    return !inline ? (
                      <SyntaxHighlighter
                        style={tomorrow}
                        language={match ? match[1] : ''}
                        PreTag="div"
                        {...props}
                      >
                        {String(children).replace(/\n$/, '')}
                      </SyntaxHighlighter>
                    ) : (
                      <code className={className} {...props}>
                        {children}
                      </code>
                    );
                  }
                }}
              >
                {msg.content}
              </ReactMarkdown>
            </div>
            <div className="message-actions">
              {!isReply && <button onClick={() => startReply(msg.id)}>Reply</button>}
              {isThreadParent && (
                <button onClick={() => toggleThread(msg.id)}>
                  {isThreadOpen ? 'Hide' : 'Show'} {replyCount} {replyCount === 1 ? 'reply' : 'replies'}
                </button>
              )}
            </div>
          </div>
        </div>
        
        {/* Render thread replies if thread is open */}
        {isThreadParent && isThreadOpen && (
          <div className="thread-replies">
            {threads[msgIdStr].replies.map(replyId => {
              const replyMsg = messages.find(m => m.id === replyId);
              if (replyMsg) {
                return renderMessage(replyMsg, true);
              }
              return null;
            })}
          </div>
        )}
      </React.Fragment>
    );
  };
  
  // Get main (non-reply) messages
  const mainMessages = messages.filter(msg => !msg.parentId);
  
  return (
    <div className={`chat-interface ${darkMode ? 'dark' : ''}`}>
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
          mainMessages.map(msg => renderMessage(msg))
        )}
        <div ref={messagesEndRef} />
      </div>
      
      <div className="chat-input-container">
        {replyingTo && (
          <div className="reply-indicator">
            <span>Replying to message</span>
            <button className="cancel-reply" onClick={cancelReply}>×</button>
          </div>
        )}
        
        <div className="formatting-toolbar">
          <button 
            type="button" 
            className="formatting-toggle"
            onClick={() => setShowFormatting(!showFormatting)}
            aria-label={showFormatting ? "Hide formatting options" : "Show formatting options"}
          >
            {showFormatting ? "Hide Formatting" : "Show Formatting"}
          </button>
          
          {showFormatting && (
            <div className="formatting-buttons">
              <button 
                type="button" 
                onClick={() => handleInsertCode()}
                title="Insert code block"
              >
                &lt;/&gt;
              </button>
              <button 
                type="button" 
                onClick={() => {
                  // Insert markdown for bold
                  const cursorPos = textareaRef.current?.selectionStart || 0;
                  const selectionEnd = textareaRef.current?.selectionEnd || cursorPos;
                  const selectedText = message.substring(cursorPos, selectionEnd);
                  const textBefore = message.substring(0, cursorPos);
                  const textAfter = message.substring(selectionEnd);
                  setMessage(textBefore + `**${selectedText}**` + textAfter);
                }}
                title="Bold"
              >
                <strong>B</strong>
              </button>
              <button 
                type="button" 
                onClick={() => {
                  // Insert markdown for italic
                  const cursorPos = textareaRef.current?.selectionStart || 0;
                  const selectionEnd = textareaRef.current?.selectionEnd || cursorPos;
                  const selectedText = message.substring(cursorPos, selectionEnd);
                  const textBefore = message.substring(0, cursorPos);
                  const textAfter = message.substring(selectionEnd);
                  setMessage(textBefore + `*${selectedText}*` + textAfter);
                }}
                title="Italic"
              >
                <em>I</em>
              </button>
              <button 
                type="button" 
                onClick={() => {
                  // Insert markdown for link
                  const cursorPos = textareaRef.current?.selectionStart || 0;
                  const textBefore = message.substring(0, cursorPos);
                  const textAfter = message.substring(cursorPos);
                  setMessage(textBefore + `[link text](https://example.com)` + textAfter);
                }}
                title="Link"
              >
                🔗
              </button>
              <button 
                type="button" 
                onClick={() => {
                  // Insert markdown for list
                  const cursorPos = textareaRef.current?.selectionStart || 0;
                  const textBefore = message.substring(0, cursorPos);
                  const textAfter = message.substring(cursorPos);
                  setMessage(textBefore + `\n- List item 1\n- List item 2\n- List item 3` + textAfter);
                }}
                title="List"
              >
                •
              </button>
            </div>
          )}
        </div>
        
        <form className="chat-input-form" onSubmit={handleSubmit}>
          <textarea
            ref={textareaRef}
            className="chat-input"
            placeholder={isLoading ? "Please wait..." : "Ask a question..."}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={isLoading}
            rows={1}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (message.trim() && !isLoading) {
                  handleSubmit(e);
                }
              }
            }}
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
    </div>
  );
};

export default ChatInterface;