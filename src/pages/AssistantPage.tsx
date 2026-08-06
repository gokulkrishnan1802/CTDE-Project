import { useState, useRef, useEffect, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore, chatStore } from '../lib/storage';
import { askAI } from '../services/aiService';
import { ApiError } from '../services/api';
import type { ChatMessage, Investigation } from '../types';
import type { PageKey } from '../components/AppLayout';
import { Bot, Send, Sparkles, User as UserIcon, FolderSearch } from 'lucide-react';

interface Props {
  refreshKey: number;
  onNavigate: (p: PageKey) => void;
}

const SUGGESTED = [
  'Why is this Safe?',
  'Explain this report.',
  'Why was phishing detected?',
  'Should I trust this URL?',
  'What should I do next?',
  'Explain the SSL certificate findings.',
  'What are the APK risks?',
  'Summarize this investigation.',
];

export default function AssistantPage({ refreshKey, onNavigate }: Props) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const latestInvestigation = useMemo<Investigation | null>(() => {
    if (!user) return null;
    const all = investigationStore.getByUser(user.id);
    if (all.length === 0) return null;
    return [...all].sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  }, [user, refreshKey]);

  const chatKey = latestInvestigation?.id || 'none';

  useEffect(() => {
    if (latestInvestigation) {
      const stored = chatStore.get(latestInvestigation.id);
      setMessages(stored);
    } else {
      setMessages([]);
    }
  }, [chatKey]);

  useEffect(() => {
    if (latestInvestigation && messages.length > 0) {
      chatStore.save(latestInvestigation.id, messages);
    }
  }, [messages, latestInvestigation]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, typing]);

  const send = async (text: string) => {
    if (!text.trim() || !latestInvestigation) return;
    const userMsg: ChatMessage = {
      id: Date.now().toString(36),
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setTyping(true);

    try {
      const response = await askAI(text, latestInvestigation);
      const aiMsg: ChatMessage = {
        id: Date.now().toString(36) + 'a',
        role: 'assistant',
        content: response,
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      const aiMsg: ChatMessage = {
        id: Date.now().toString(36) + 'a',
        role: 'assistant',
        content: err instanceof ApiError ? err.message : 'Unable to reach the AI assistant backend. Please ensure the server is running.',
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, aiMsg]);
    } finally {
      setTyping(false);
    }
  };

  return (
    <div className="space-y-4 animate-fadeIn h-full flex flex-col">
      <div>
        <h2 className="text-2xl font-bold text-gray-100">AI Investigation Assistant</h2>
        <p className="text-sm text-gray-500 mt-1">Ask questions about your latest investigation</p>
      </div>

      {!latestInvestigation ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="w-16 h-16 rounded-2xl bg-gray-800/30 border border-gray-800 flex items-center justify-center mb-4">
            <Bot className="w-8 h-8 text-gray-700" />
          </div>
          <p className="text-lg font-medium text-gray-500">No active investigation selected</p>
          <p className="text-sm text-gray-700 mt-1">Complete an investigation to interact with the AI assistant</p>
          <button
            onClick={() => onNavigate('history')}
            className="mt-6 flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 text-sm font-medium rounded-lg transition-all"
          >
            <FolderSearch className="w-4 h-4" /> Start Investigation
          </button>
        </div>
      ) : (
        <>
          {/* Active investigation context */}
          <div className="flex items-center gap-2 px-4 py-2.5 bg-cyan-500/5 border border-cyan-500/20 rounded-lg text-sm">
            <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0" />
            <span className="text-gray-400">Context: </span>
            <span className="text-cyan-400 font-medium truncate">{latestInvestigation.caseName}</span>
            <span className="text-gray-600 font-mono text-xs ml-auto flex-shrink-0">Score: {latestInvestigation.trustScore}/100</span>
          </div>

          {/* Chat */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto bg-[#0f1620] border border-gray-800/60 rounded-2xl p-4 space-y-3 min-h-[300px]">
            {messages.length === 0 && (
              <div className="text-center py-8">
                <Bot className="w-10 h-10 text-gray-700 mx-auto mb-3" />
                <p className="text-sm text-gray-500">Ask me anything about this investigation</p>
              </div>
            )}
            {messages.map(msg => (
              <div key={msg.id} className={`flex gap-2.5 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${
                  msg.role === 'user' ? 'bg-cyan-500/10 border border-cyan-500/30' : 'bg-emerald-500/10 border border-emerald-500/30'
                }`}>
                  {msg.role === 'user' ? <UserIcon className="w-3.5 h-3.5 text-cyan-400" /> : <Bot className="w-3.5 h-3.5 text-emerald-400" />}
                </div>
                <div className={`max-w-[75%] px-4 py-2.5 rounded-2xl text-sm leading-relaxed ${
                  msg.role === 'user' ? 'bg-cyan-500/10 text-gray-200 rounded-tr-sm' : 'bg-[#0a0e14] border border-gray-800 text-gray-300 rounded-tl-sm'
                }`}>
                  {msg.content}
                </div>
              </div>
            ))}
            {typing && (
              <div className="flex gap-2.5">
                <div className="w-7 h-7 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-3.5 h-3.5 text-emerald-400" />
                </div>
                <div className="px-4 py-3 rounded-2xl bg-[#0a0e14] border border-gray-800 rounded-tl-sm">
                  <div className="flex gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-gray-600 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-gray-600 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-gray-600 animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Suggested questions */}
          <div className="flex flex-wrap gap-2">
            {SUGGESTED.map(q => (
              <button
                key={q}
                onClick={() => send(q)}
                className="text-xs px-3 py-1.5 bg-[#0f1620] border border-gray-800 hover:border-cyan-500/30 text-gray-400 hover:text-cyan-400 rounded-full transition-all"
              >
                {q}
              </button>
            ))}
          </div>

          {/* Input */}
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); } }}
              className="flex-1 bg-[#0f1620] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
              placeholder="Ask about this investigation..."
            />
            <button
              onClick={() => send(input)}
              disabled={!input.trim()}
              className="flex items-center gap-2 px-4 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 rounded-lg transition-all disabled:opacity-30"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </>
      )}
    </div>
  );
}
