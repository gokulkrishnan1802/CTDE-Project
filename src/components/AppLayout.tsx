import { useState, type ReactNode } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  ShieldCheck, LayoutDashboard, FolderSearch, FileText, Bot, Settings,
  LogOut, ChevronDown, Menu, Activity, User as UserIcon
} from 'lucide-react';

export type PageKey = 'dashboard' | 'history' | 'reports' | 'assistant' | 'settings';

interface LayoutProps {
  current: PageKey;
  onNavigate: (page: PageKey) => void;
  children: ReactNode;
}

const NAV_ITEMS: { key: PageKey; label: string; icon: typeof LayoutDashboard }[] = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { key: 'history', label: 'Investigations', icon: FolderSearch },
  { key: 'reports', label: 'Reports', icon: FileText },
  { key: 'assistant', label: 'AI Assistant', icon: Bot },
  { key: 'settings', label: 'Settings', icon: Settings },
];

export default function AppLayout({ current, onNavigate, children }: LayoutProps) {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);

  const initials = user?.fullName
    ? user.fullName.split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase()
    : '?';

  return (
    <div className="min-h-screen bg-[#0a0e14] cyber-grid flex">
      {/* Sidebar */}
      <aside className={`fixed lg:sticky top-0 left-0 h-screen w-64 bg-[#0f1620] border-r border-gray-800/60 flex flex-col z-40 transition-transform ${mobileNav ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}>
        {/* Logo */}
        <div className="px-6 py-5 border-b border-gray-800/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-sm font-bold leading-tight">
                <span className="text-cyan-400">CyberTrust</span>
                <span className="text-white"> Decision Engine</span>
              </h1>
              <p className="text-[10px] font-mono text-gray-600 mt-0.5">Digital Forensics · Powered by AI</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map(item => {
            const Icon = item.icon;
            const active = current === item.key;
            return (
              <button
                key={item.key}
                onClick={() => { onNavigate(item.key); setMobileNav(false); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group ${
                  active
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/30 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-cyan-400' : 'text-gray-600 group-hover:text-gray-400'}`} />
                {item.label}
                {active && <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />}
              </button>
            );
          })}
        </nav>

        {/* Status */}
        <div className="px-4 py-3 border-t border-gray-800/60">
          <div className="flex items-center gap-2 text-xs font-mono text-gray-600">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            SYSTEM ONLINE
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileNav && <div className="fixed inset-0 bg-black/50 z-30 lg:hidden" onClick={() => setMobileNav(false)} />}

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="sticky top-0 z-20 bg-[#0f1620]/80 backdrop-blur-xl border-b border-gray-800/60 px-4 lg:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileNav(!mobileNav)}
              className="lg:hidden p-2 rounded-lg hover:bg-gray-800/50 text-gray-400"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-[#0a0e14] border border-gray-800 rounded-lg">
              <Activity className="w-3.5 h-3.5 text-cyan-500/60" />
              <span className="text-xs font-mono text-gray-500">Threat Monitor Active</span>
            </div>
          </div>

          {/* User menu */}
          <div className="relative">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg hover:bg-gray-800/40 transition-colors"
            >
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/30 flex items-center justify-center text-xs font-bold text-cyan-400">
                {initials}
              </div>
              <div className="hidden sm:block text-left">
                <p className="text-sm font-medium text-gray-200 leading-none">{user?.fullName}</p>
                <p className="text-[10px] font-mono text-gray-600 mt-0.5">@{user?.username}</p>
              </div>
              <ChevronDown className={`w-4 h-4 text-gray-600 transition-transform ${menuOpen ? 'rotate-180' : ''}`} />
            </button>

            {menuOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
                <div className="absolute right-0 mt-2 w-56 bg-[#0f1620] border border-gray-800 rounded-xl shadow-2xl py-2 z-20 animate-fadeIn">
                  <div className="px-4 py-2 border-b border-gray-800/60">
                    <p className="text-sm font-medium text-gray-200">{user?.fullName}</p>
                    <p className="text-xs text-gray-600">{user?.email}</p>
                  </div>
                  <button
                    onClick={() => { onNavigate('settings'); setMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-400 hover:text-cyan-400 hover:bg-gray-800/40 transition-colors"
                  >
                    <UserIcon className="w-4 h-4" /> Profile
                  </button>
                  <button
                    onClick={() => { onNavigate('reports'); setMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-400 hover:text-cyan-400 hover:bg-gray-800/40 transition-colors"
                  >
                    <FileText className="w-4 h-4" /> Reports
                  </button>
                  <button
                    onClick={() => { onNavigate('settings'); setMenuOpen(false); }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-400 hover:text-cyan-400 hover:bg-gray-800/40 transition-colors"
                  >
                    <Settings className="w-4 h-4" /> Settings
                  </button>
                  <div className="border-t border-gray-800/60 my-1" />
                  <button
                    onClick={logout}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-400 hover:text-red-400 hover:bg-red-500/5 transition-colors"
                  >
                    <LogOut className="w-4 h-4" /> Logout
                  </button>
                </div>
              </>
            )}
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 p-4 lg:p-6 overflow-x-hidden">
          {children}
        </main>
      </div>
    </div>
  );
}
