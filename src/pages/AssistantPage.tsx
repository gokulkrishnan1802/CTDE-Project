import { useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { chatStore, investigationStore } from '../lib/storage';
import { askAI } from '../services/aiService';
import { ApiError } from '../services/api';
import type { ChatMessage, Investigation } from '../types';
import type { PageKey } from '../components/AppLayout';
import { Bot, Send, Sparkles, User as UserIcon } from 'lucide-react';

interface Props {
  refreshKey: number;
  onNavigate: (p: PageKey) => void;
}

const GENERAL_SUGGESTIONS = [
  'How can I recognize a phishing message?',
  'What does multi-factor authentication do?',
  'How do I choose a strong password?',
  'What should I do after clicking a suspicious link?',
];

const INVESTIGATION_SUGGESTIONS = [
  'Explain this result in simple terms.',
  'Why did this get its risk score?',
  'What should I do next?',
  'Which findings are uncertain or unavailable?',
];

export default function AssistantPage({ refreshKey, onNavigate }: Props) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loadedChatKey, setLoadedChatKey] = useState('');
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);
  const [useCaseContext, setUseCaseContext] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const latestInvestigation = useMemo<Investigation | null>(() => {
    if (!user) return null;
    const all = investigationStore.getByUser(user.id);
    return [...all].sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] ?? null;
  }, [user, refreshKey]);

  const activeInvestigation = useCaseContext ? latestInvestigation : null;
  const chatKey = activeInvestigation?.id ?? `general:${user?.id ?? 'guest'}`;
  const suggestions = activeInvestigation
    ? INVESTIGATION_SUGGESTIONS
    : GENERAL_SUGGESTIONS;

  useEffect(() => {
    setMessages(chatStore.get(chatKey));
    setLoadedChatKey(chatKey);
  }, [chatKey]);

  useEffect(() => {
    if (loadedChatKey === chatKey) chatStore.save(chatKey, messages);
  }, [chatKey, loadedChatKey, messages]);

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: 'smooth',
    });
  }, [messages, typing]);

  const send = async (text: string) => {
    if (!text.trim() || !user || typing) return;
    const previousMessages = messages;
    const userMsg: ChatMessage = {
      id: Date.now().toString(36),
      role: 'user',
      content: text.trim(),
      timestamp: new Date().toISOString(),
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setTyping(true);

    try {
      const response = await askAI(text, activeInvestigation, previousMessages);
      const aiMsg: ChatMessage = {
        id: `${Date.now().toString(36)}a`,
        role: 'assistant',
        content: response,
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      const aiMsg: ChatMessage = {
        id: `${Date.now().toString(36)}a`,
        role: 'assistant',
        content: err instanceof ApiError
          ? err.message
          : 'I could not reach the assistant service. Please try again shortly.',
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
        <h2 className="text-2xl font-bold text-gray-100">Cybersecurity Assistant</h2>
        <p className="text-sm text-gray-500 mt-1">
          Ask about online safety, cyber threats, or your investigation.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 px-4 py-3 bg-cyan-500/5 border border-cyan-500/20 rounded-lg text-sm">
        <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0" />
        <span className="text-gray-400">Chat mode:</span>
        <button
          type="button"
          aria-pressed={!useCaseContext}
          disabled={typing}
          onClick={() => setUseCaseContext(false)}
          className={`px-3 py-1 rounded-full border transition-all disabled:opacity-50 ${
            !useCaseContext
              ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300'
              : 'border-gray-700 text-gray-400 hover:border-cyan-500/30'
          }`}
        >
          General cybersecurity
        </button>
        <button
          type="button"
          aria-pressed={useCaseContext}
          disabled={!latestInvestigation || typing}
          onClick={() => setUseCaseContext(true)}
          title={latestInvestigation ? 'Include your latest check as context' : 'Run a check first'}
          className={`px-3 py-1 rounded-full border transition-all disabled:opacity-40 disabled:cursor-not-allowed ${
            useCaseContext
              ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300'
              : 'border-gray-700 text-gray-400 hover:border-cyan-500/30'
          }`}
        >
          Latest investigation
        </button>
        {useCaseContext && latestInvestigation && (
          <span className="text-gray-500 truncate sm:ml-auto">
            {latestInvestigation.caseName} · {latestInvestigation.trustScore}/100
          </span>
        )}
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto bg-[#0f1620] border border-gray-800/60 rounded-2xl p-4 space-y-3 min-h-[300px]"
      >
        {messages.length === 0 && (
          <div className="text-center py-8">
            <Bot className="w-10 h-10 text-gray-700 mx-auto mb-3" />
            <p className="text-sm text-gray-500">
              {activeInvestigation
                ? 'Ask me to explain this check or its recommendations.'
                : 'Ask a cybersecurity question in everyday language.'}
            </p>
          </div>
        )}
        {messages.map(msg => (
          <div key={msg.id} className={`flex gap-2.5 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${
              msg.role === 'user'
                ? 'bg-cyan-500/10 border border-cyan-500/30'
                : 'bg-emerald-500/10 border border-emerald-500/30'
            }`}>
              {msg.role === 'user'
                ? <UserIcon className="w-3.5 h-3.5 text-cyan-400" />
                : <Bot className="w-3.5 h-3.5 text-emerald-400" />}
            </div>
            <div className={`max-w-[75%] whitespace-pre-wrap px-4 py-2.5 rounded-2xl text-sm leading-relaxed ${
              msg.role === 'user'
                ? 'bg-cyan-500/10 text-gray-200 rounded-tr-sm'
                : 'bg-[#0a0e14] border border-gray-800 text-gray-300 rounded-tl-sm'
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
            <div className="px-4 py-3 rounded-2xl bg-[#0a0e14] border border-gray-800 rounded-tl-sm text-sm text-gray-500">
              Thinking…
            </div>
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {suggestions.map(q => (
          <button
            key={q}
            type="button"
            onClick={() => send(q)}
            disabled={typing}
            className="text-xs px-3 py-1.5 bg-[#0f1620] border border-gray-800 hover:border-cyan-500/30 text-gray-400 hover:text-cyan-400 rounded-full transition-all disabled:opacity-50"
          >
            {q}
          </button>
        ))}
        {!latestInvestigation && (
          <button
            type="button"
            onClick={() => onNavigate('new-investigation')}
            className="text-xs px-3 py-1.5 bg-[#0f1620] border border-gray-800 hover:border-cyan-500/30 text-gray-500 hover:text-cyan-400 rounded-full transition-all"
          >
            Run a check to ask about evidence
          </button>
        )}
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void send(input);
            }
          }}
          className="flex-1 bg-[#0f1620] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
          placeholder={activeInvestigation ? 'Ask about cybersecurity or this check…' : 'Ask a cybersecurity question…'}
          maxLength={1000}
        />
        <button
          type="button"
          onClick={() => void send(input)}
          disabled={!input.trim() || typing}
          aria-label="Send message"
          className="flex items-center gap-2 px-4 py-2.5 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 rounded-lg transition-all disabled:opacity-30"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}