import { useState, useRef, useEffect } from 'react';
import { chatWithExtension } from '../api';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
}

interface ChatPanelProps {
  scanId: string;
  extensionId: string;
  extensionName: string;
}

export default function ChatPanel({ scanId, extensionId, extensionName }: ChatPanelProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Reset messages when extension changes
  useEffect(() => {
    setMessages([]);
    setInput('');
  }, [extensionId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMsg: ChatMessage = { role: 'user', content: input.trim(), timestamp: Date.now() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const data = await chatWithExtension(scanId, extensionId, userMsg.content);
      const assistantMsg: ChatMessage = { role: 'assistant', content: data.reply, timestamp: Date.now() };
      setMessages(prev => [...prev, assistantMsg]);
    } catch {
      const errorMsg: ChatMessage = { role: 'assistant', content: 'Error communicating with AI. Please try again.', timestamp: Date.now() };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="chat-panel">
      <h3>Interrogate AI</h3>
      <p className="muted">Ask questions about {extensionName}'s security.</p>
      <div className="chat-messages" ref={scrollRef}>
        {messages.length === 0 ? (
          <div className="muted" style={{ textAlign: 'center', padding: 20 }}>
            No messages yet. Ask a question about this extension.
          </div>
        ) : (
          messages.map((msg, i) => (
            <div key={i} className={`chat-message ${msg.role}`}>
              {msg.role === 'assistant' && <strong>🤖 </strong>}
              {msg.content}
            </div>
          ))
        )}
        {loading && (
          <div className="chat-message assistant" style={{ opacity: 0.6 }}>
            <strong>🤖 </strong>Thinking...
          </div>
        )}
      </div>
      <form className="chat-input-row" onSubmit={handleSend}>
        <input
          className="chat-input"
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="e.g. Can this extension read my passwords?"
          disabled={loading}
          aria-label="Chat message"
          id="chat-input"
        />
        <button
          className="chat-send"
          type="submit"
          disabled={loading || !input.trim()}
          aria-label="Send message"
          id="chat-send-btn"
        >
          {loading ? 'Sending...' : 'Ask'}
        </button>
      </form>
    </div>
  );
}
