import { useState, type ReactNode } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  ShieldCheck,
  LayoutDashboard,
  FolderSearch,
  FileText,
  Bot,
  Settings,
  LogOut,
  ChevronDown,
  Menu,
  Search,
  User as UserIcon,
  X,
  Activity,
  Clock3,
} from 'lucide-react';

export type PageKey =
  | 'dashboard'
  | 'history'
  | 'reports'
  | 'assistant'
  | 'settings'

  // Investigation
  | 'new-investigation'

  // Verify
  | 'verify-url'
  | 'verify-domain'
  | 'verify-email'
  | 'verify-qr'
  | 'verify-apk'

  // Digital Forensics
  | 'data-extraction'
  | 'digital-forensics'
  | 'file-analysis'
  | 'metadata'
  | 'hash-analyzer'
  | 'timeline'

  // Mobile Forensics
  | 'mobile-forensics'
  | 'mobile-evidence'
  | 'database-analysis'

  // Evidence
  | 'evidence'
  | 'evidence-viewer'
  | 'integrity'

  // Intelligence
  | 'ctde'
  | 'trust-score'
  | 'mitre'
  | 'threat-intelligence';

interface LayoutProps {
  current: PageKey;
  onNavigate: (page: PageKey) => void;
  children: ReactNode;
}

type NavItem = {
  key: PageKey;
  label: string;
  icon: typeof LayoutDashboard;
};

type NavSection = {
  title: string;
  items: NavItem[];
};

/*
 * PUBLIC USER NAVIGATION
 *
 * Technical forensic modules such as:
 * CTDE, MITRE ATT&CK, Threat Intelligence,
 * Hash Analyzer, Metadata, Timeline, etc.
 * remain available in the application but are
 * intentionally hidden from the public sidebar.
 *
 * The target user should interact with simple
 * actions rather than technical security engines.
 */
const NAV_SECTIONS: NavSection[] = [
  {
    title: 'HOME',
    items: [
      {
        key: 'dashboard',
        label: 'Dashboard',
        icon: LayoutDashboard,
      },
    ],
  },

  {
    title: 'VERIFY',
    items: [
      {
        key: 'new-investigation',
        label: 'Verify Something',
        icon: FolderSearch,
      },
    ],
  },

  {
    title: 'HISTORY',
    items: [
      {
        key: 'history',
        label: 'My Checks',
        icon: Clock3,
      },
    ],
  },

  {
    title: 'AI',
    items: [
      {
        key: 'assistant',
        label: 'Ask CyberVerify',
        icon: Bot,
      },
    ],
  },

  {
    title: 'REPORTS',
    items: [
      {
        key: 'reports',
        label: 'My Reports',
        icon: FileText,
      },
    ],
  },

  {
    title: 'ACCOUNT',
    items: [
      {
        key: 'settings',
        label: 'Settings',
        icon: Settings,
      },
    ],
  },
];

export default function AppLayout({
  current,
  onNavigate,
  children,
}: LayoutProps) {
  const { user, logout } = useAuth();

  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);

  const initials = user?.fullName
    ? user.fullName
        .split(' ')
        .map((n) => n[0])
        .slice(0, 2)
        .join('')
        .toUpperCase()
    : '?';

  const navigate = (page: PageKey) => {
    onNavigate(page);
    setMobileNav(false);
    setMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#0a0e14] cyber-grid flex">

      {/* =========================================================
          MOBILE OVERLAY
      ========================================================= */}
      {mobileNav && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden"
          onClick={() => setMobileNav(false)}
        />
      )}

      {/* =========================================================
          SIDEBAR
      ========================================================= */}
      <aside
        className={`
          fixed lg:sticky
          top-0 left-0
          h-screen
          w-72
          bg-[#0f1620]
          border-r border-gray-800/60
          flex flex-col
          z-40
          transition-transform duration-300
          ${
            mobileNav
              ? 'translate-x-0'
              : '-translate-x-full lg:translate-x-0'
          }
        `}
      >

        {/* =======================================================
            LOGO
        ======================================================= */}
        <div className="px-5 py-5 border-b border-gray-800/60">
          <div className="flex items-center gap-3">

            <div className="w-10 h-10 shrink-0 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shadow-[0_0_20px_rgba(34,211,238,0.08)]">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>

            <div className="min-w-0">
              <h1 className="text-sm font-bold leading-tight tracking-wide">
                <span className="text-cyan-400">
                  CyberVerify
                </span>

                <span className="text-white">
                  {' '}AI
                </span>
              </h1>

              <p className="text-[9px] font-mono text-gray-600 mt-1 uppercase tracking-wider">
                Digital Trust & Forensics
              </p>

              <div className="flex items-center gap-1.5 mt-1.5">
                <span className="text-[8px] font-mono text-cyan-500/60">
                  CTDE
                </span>

                <span className="w-1 h-1 rounded-full bg-gray-700" />

                <span className="text-[8px] font-mono text-gray-600">
                  v1.0
                </span>
              </div>
            </div>

            {/* ===================================================
                MOBILE CLOSE BUTTON
            =================================================== */}
            <button
              onClick={() => setMobileNav(false)}
              className="ml-auto lg:hidden p-1.5 text-gray-500 hover:text-gray-300"
              aria-label="Close navigation"
            >
              <X className="w-4 h-4" />
            </button>

          </div>
        </div>

        {/* =======================================================
            NAVIGATION
        ======================================================= */}
        <nav className="flex-1 px-3 py-4 overflow-y-auto scrollbar-thin">

          {NAV_SECTIONS.map((section) => (
            <div
              key={section.title}
              className="mb-5"
            >

              {/* Section title */}
              <div className="px-3 mb-2">
                <span className="text-[9px] font-semibold tracking-[0.18em] text-gray-600">
                  {section.title}
                </span>
              </div>

              {/* Section items */}
              <div className="space-y-0.5">

                {section.items.map((item) => {
                  const Icon = item.icon;
                  const active = current === item.key;

                  return (
                    <button
                      key={item.key}
                      onClick={() => navigate(item.key)}
                      className={`
                        relative
                        w-full
                        flex
                        items-center
                        gap-3
                        px-3
                        py-2.5
                        rounded-lg
                        text-xs
                        font-medium
                        transition-all
                        duration-200
                        group
                        ${
                          active
                            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                            : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/30 border border-transparent'
                        }
                      `}
                    >

                      {/* Active indicator */}
                      {active && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-cyan-400 rounded-r-full shadow-[0_0_8px_rgba(34,211,238,0.7)]" />
                      )}

                      {/* Icon */}
                      <Icon
                        className={`
                          w-4 h-4 shrink-0
                          transition-colors
                          ${
                            active
                              ? 'text-cyan-400'
                              : 'text-gray-600 group-hover:text-gray-400'
                          }
                        `}
                      />

                      {/* Label */}
                      <span className="truncate">
                        {item.label}
                      </span>

                      {/* Active dot */}
                      {active && (
                        <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                      )}

                    </button>
                  );
                })}

              </div>
            </div>
          ))}

        </nav>

        {/* =======================================================
            SYSTEM STATUS
        ======================================================= */}
        <div className="px-4 py-3 border-t border-gray-800/60 bg-[#0c121a]/60">

          <div className="flex items-center justify-between">

            <div className="flex items-center gap-2 text-[10px] font-mono text-gray-600">

              <span className="relative flex h-2 w-2">

                <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-50 animate-ping" />

                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />

              </span>

              SYSTEM ONLINE

            </div>

            <span className="text-[8px] font-mono text-emerald-500/60">
              SECURE
            </span>

          </div>

        </div>

      </aside>

      {/* =========================================================
          MAIN AREA
      ========================================================= */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* =======================================================
            TOP COMMAND BAR
        ======================================================= */}
        <header className="sticky top-0 z-20 bg-[#0f1620]/85 backdrop-blur-xl border-b border-gray-800/60 px-4 lg:px-6 py-3">

          <div className="flex items-center justify-between gap-4">

            {/* ===================================================
                LEFT SIDE
            =================================================== */}
            <div className="flex items-center gap-3 min-w-0">

              {/* Mobile menu button */}
              <button
                onClick={() => setMobileNav(true)}
                className="lg:hidden p-2 rounded-lg hover:bg-gray-800/50 text-gray-400"
                aria-label="Open navigation"
              >
                <Menu className="w-5 h-5" />
              </button>

              <div className="hidden sm:block">

                <p className="text-sm font-semibold text-gray-200">
                  CyberVerify AI
                </p>

                <p className="text-[9px] font-mono text-gray-600">
                  INTELLIGENT DIGITAL TRUST & FORENSICS
                </p>

              </div>

            </div>

            {/* ===================================================
                SEARCH
            =================================================== */}
            <div className="hidden md:flex flex-1 max-w-md">

              <div className="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0a0e14] border border-gray-800 hover:border-gray-700 transition-colors">

                <Search className="w-4 h-4 text-gray-600" />

                <input
                  type="text"
                  placeholder="Search your checks..."
                  className="w-full bg-transparent outline-none text-xs text-gray-300 placeholder:text-gray-700"
                />

                <span className="text-[9px] font-mono text-gray-700 border border-gray-800 rounded px-1.5 py-0.5">
                  /
                </span>

              </div>

            </div>

            {/* ===================================================
                RIGHT SIDE
            =================================================== */}
            <div className="flex items-center gap-2">

              {/* =================================================
                  SYSTEM MONITOR
              ================================================= */}
              <div className="hidden xl:flex items-center gap-2 px-3 py-2 bg-[#0a0e14] border border-gray-800 rounded-lg">

                <Activity className="w-3.5 h-3.5 text-cyan-500/60" />

                <span className="text-[10px] font-mono text-gray-500">
                  SYSTEM READY
                </span>

                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />

              </div>

              {/* =================================================
                  USER MENU
              ================================================= */}
              <div className="relative">

                <button
                  onClick={() => setMenuOpen(!menuOpen)}
                  className="flex items-center gap-2.5 px-2 py-1.5 rounded-lg hover:bg-gray-800/40 transition-colors"
                >

                  {/* Avatar */}
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/30 flex items-center justify-center text-xs font-bold text-cyan-400">
                    {initials}
                  </div>

                  {/* User information */}
                  <div className="hidden sm:block text-left">

                    <p className="text-sm font-medium text-gray-200 leading-none">
                      {user?.fullName}
                    </p>

                    <p className="text-[10px] font-mono text-gray-600 mt-0.5">
                      @{user?.username}
                    </p>

                  </div>

                  {/* Dropdown arrow */}
                  <ChevronDown
                    className={`w-4 h-4 text-gray-600 transition-transform ${
                      menuOpen ? 'rotate-180' : ''
                    }`}
                  />

                </button>

                {/* =================================================
                    USER DROPDOWN
                ================================================= */}
                {menuOpen && (
                  <>
                    {/* Click outside */}
                    <div
                      className="fixed inset-0 z-10"
                      onClick={() => setMenuOpen(false)}
                    />

                    <div className="absolute right-0 mt-2 w-60 bg-[#0f1620] border border-gray-800 rounded-xl shadow-2xl py-2 z-20 animate-fadeIn">

                      {/* User info */}
                      <div className="px-4 py-3 border-b border-gray-800/60">

                        <p className="text-sm font-medium text-gray-200">
                          {user?.fullName}
                        </p>

                        <p className="text-xs text-gray-600 mt-1">
                          {user?.email}
                        </p>

                      </div>

                      {/* Profile */}
                      <button
                        onClick={() => navigate('settings')}
                        className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-400 hover:text-cyan-400 hover:bg-gray-800/40 transition-colors"
                      >

                        <UserIcon className="w-4 h-4" />

                        Profile

                      </button>

                      {/* Reports */}
                      <button
                        onClick={() => navigate('reports')}
                        className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-400 hover:text-cyan-400 hover:bg-gray-800/40 transition-colors"
                      >

                        <FileText className="w-4 h-4" />

                        My Reports

                      </button>

                      {/* Settings */}
                      <button
                        onClick={() => navigate('settings')}
                        className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-400 hover:text-cyan-400 hover:bg-gray-800/40 transition-colors"
                      >

                        <Settings className="w-4 h-4" />

                        Settings

                      </button>

                      {/* Divider */}
                      <div className="border-t border-gray-800/60 my-1" />

                      {/* Logout */}
                      <button
                        onClick={logout}
                        className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-gray-400 hover:text-red-400 hover:bg-red-500/5 transition-colors"
                      >

                        <LogOut className="w-4 h-4" />

                        Logout

                      </button>

                    </div>
                  </>
                )}

              </div>

            </div>

          </div>

        </header>

        {/* =======================================================
            CONTENT
        ======================================================= */}
        <main className="flex-1 p-4 lg:p-6 overflow-x-hidden">
          {children}
        </main>

      </div>

    </div>
  );
}