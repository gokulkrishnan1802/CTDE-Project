import { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';

import AuthPage from './pages/AuthPage';

import AppLayout, {
  type PageKey,
} from './components/AppLayout';

import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';
import ReportsPage from './pages/ReportsPage';
import AssistantPage from './pages/AssistantPage';
import SettingsPage from './pages/SettingsPage';
import InvestigationPage from './pages/InvestigationPage';

function PlaceholderPage({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="animate-fadeIn">
      <div className="mb-6">
        <p className="text-[10px] font-mono tracking-[0.2em] text-cyan-500/60 uppercase">
          CyberVerify AI
        </p>

        <h1 className="text-2xl font-bold text-gray-100 mt-1">
          {title}
        </h1>

        <p className="text-sm text-gray-500 mt-1">
          {description}
        </p>
      </div>

      <div className="rounded-xl border border-gray-800/60 bg-[#0f1620]/70 p-10 text-center">
        <div className="w-12 h-12 mx-auto rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
        </div>

        <h2 className="text-sm font-semibold text-gray-300 mt-4">
          Module Ready
        </h2>

        <p className="text-xs text-gray-600 mt-2 max-w-md mx-auto">
          This CyberVerify AI module is part of the new forensic
          workspace. The analysis interface will be implemented next.
        </p>

        <div className="mt-5 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-900/60 border border-gray-800">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
          <span className="text-[10px] font-mono text-gray-500">
            UI MODULE INITIALIZED
          </span>
        </div>
      </div>
    </div>
  );
}

function AppContent() {
  const { user } = useAuth();

  const [page, setPage] = useState<PageKey>('dashboard');

  const [refreshKey, setRefreshKey] = useState(0);

  const [investigationMode, setInvestigationMode] =
    useState(false);

  // Reset to dashboard when user changes
  useEffect(() => {
    if (user) {
      setPage('dashboard');
      setInvestigationMode(false);
    }
  }, [user?.id]);

  if (!user) return <AuthPage />;

  const handleNavigate = (p: PageKey) => {
    setInvestigationMode(false);
    setPage(p);
  };

  const handleStartInvestigation = () => {
    setInvestigationMode(true);
    setPage('new-investigation');
  };

  const handleInvestigationComplete = () => {
    setRefreshKey((k) => k + 1);
  };

  return (
    <AppLayout
      current={page}
      onNavigate={handleNavigate}
    >
      {/* ================= INVESTIGATION ================= */}

      {investigationMode ? (
        <InvestigationPage
          onComplete={handleInvestigationComplete}
          onNavigate={handleNavigate}
        />
      ) : (
        <>
          {/* ================= EXISTING PAGES ================= */}

          {page === 'dashboard' && (
            <DashboardPage
              onNavigate={handleNavigate}
              refreshKey={refreshKey}
            />
          )}

          {page === 'history' && (
            <HistoryPage
              refreshKey={refreshKey}
              onStartNew={handleStartInvestigation}
            />
          )}

          {page === 'reports' && (
            <ReportsPage
              refreshKey={refreshKey}
            />
          )}

          {page === 'assistant' && (
            <AssistantPage
              refreshKey={refreshKey}
              onNavigate={handleNavigate}
            />
          )}

          {page === 'settings' && (
            <SettingsPage
              onNavigate={handleNavigate}
            />
          )}

          {/* ================= NEW UI MODULES ================= */}

          {page === 'new-investigation' && (
            <InvestigationPage
              onComplete={handleInvestigationComplete}
              onNavigate={handleNavigate}
            />
          )}

          {page === 'verify-url' && (
            <PlaceholderPage
              title="Website / URL Verification"
              description="Analyze URLs, redirects, certificates, reputation and digital trust indicators."
            />
          )}

          {page === 'verify-domain' && (
            <PlaceholderPage
              title="Domain Verification"
              description="Investigate domain identity, WHOIS, DNS, age and registration information."
            />
          )}

          {page === 'verify-email' && (
            <PlaceholderPage
              title="Email Verification"
              description="Analyze email headers, sender identity and authentication indicators."
            />
          )}

          {page === 'verify-qr' && (
            <PlaceholderPage
              title="QR Code Verification"
              description="Decode QR evidence and investigate the destination resource."
            />
          )}

          {page === 'verify-apk' && (
            <PlaceholderPage
              title="APK Verification"
              description="Analyze Android applications, metadata, permissions and reputation."
            />
          )}

          {page === 'data-extraction' && (
            <PlaceholderPage
              title="Data Extraction"
              description="Extract metadata, strings and forensic artifacts from digital evidence."
            />
          )}

          {page === 'digital-forensics' && (
            <PlaceholderPage
              title="Digital Forensics"
              description="Central workspace for digital evidence examination and forensic analysis."
            />
          )}

          {page === 'file-analysis' && (
            <PlaceholderPage
              title="File Analysis"
              description="Inspect files, file types, properties and forensic indicators."
            />
          )}

          {page === 'metadata' && (
            <PlaceholderPage
              title="Metadata Analysis"
              description="Inspect metadata and identify useful forensic evidence."
            />
          )}

          {page === 'hash-analyzer' && (
            <PlaceholderPage
              title="Hash Analyzer"
              description="Calculate and verify cryptographic hashes for evidence integrity."
            />
          )}

          {page === 'timeline' && (
            <PlaceholderPage
              title="Forensic Timeline"
              description="Organize evidence events into an investigation timeline."
            />
          )}

          {page === 'mobile-forensics' && (
            <PlaceholderPage
              title="Mobile Forensics"
              description="Analyze mobile applications and digital artifacts within CyberVerify AI."
            />
          )}

          {page === 'mobile-evidence' && (
            <PlaceholderPage
              title="Mobile Evidence"
              description="Manage and examine evidence extracted from mobile sources."
            />
          )}

          {page === 'database-analysis' && (
            <PlaceholderPage
              title="Database Analysis"
              description="Inspect application and mobile database artifacts."
            />
          )}

          {page === 'evidence' && (
            <PlaceholderPage
              title="Evidence Repository"
              description="Central repository for investigation evidence and forensic artifacts."
            />
          )}

          {page === 'evidence-viewer' && (
            <PlaceholderPage
              title="Evidence Viewer"
              description="View evidence, properties, metadata and analysis results."
            />
          )}

          {page === 'integrity' && (
            <PlaceholderPage
              title="Evidence Integrity"
              description="Verify evidence integrity using cryptographic hashes."
            />
          )}

          {page === 'ctde' && (
            <PlaceholderPage
              title="CTDE Decision Engine"
              description="Correlate evidence and determine digital trust and risk."
            />
          )}

          {page === 'trust-score' && (
            <PlaceholderPage
              title="Digital Trust Score"
              description="Understand the explainable trust score generated from investigation evidence."
            />
          )}

          {page === 'mitre' && (
            <PlaceholderPage
              title="MITRE ATT&CK"
              description="Map relevant findings to standardized ATT&CK techniques."
            />
          )}

          {page === 'threat-intelligence' && (
            <PlaceholderPage
              title="Threat Intelligence"
              description="Correlate investigation findings with threat intelligence sources."
            />
          )}
        </>
      )}
    </AppLayout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}