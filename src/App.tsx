import { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import AuthPage from './pages/AuthPage';
import AppLayout, { type PageKey } from './components/AppLayout';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';
import ReportsPage from './pages/ReportsPage';
import AssistantPage from './pages/AssistantPage';
import SettingsPage from './pages/SettingsPage';
import InvestigationPage from './pages/InvestigationPage';

function AppContent() {
  const { user } = useAuth();
  const [page, setPage] = useState<PageKey>('dashboard');
  const [refreshKey, setRefreshKey] = useState(0);
  const [investigationMode, setInvestigationMode] = useState(false);

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
    setPage('history');
  };

  const handleInvestigationComplete = () => {
    setRefreshKey(k => k + 1);
  };

  return (
    <AppLayout current={page} onNavigate={handleNavigate}>
      {investigationMode ? (
        <InvestigationPage
          onComplete={handleInvestigationComplete}
          onNavigate={handleNavigate}
        />
      ) : (
        <>
          {page === 'dashboard' && <DashboardPage onNavigate={handleNavigate} refreshKey={refreshKey} />}
          {page === 'history' && (
            <HistoryPage
              refreshKey={refreshKey}
              onStartNew={handleStartInvestigation}
            />
          )}
          {page === 'reports' && <ReportsPage refreshKey={refreshKey} />}
          {page === 'assistant' && <AssistantPage refreshKey={refreshKey} onNavigate={handleNavigate} />}
          {page === 'settings' && <SettingsPage onNavigate={handleNavigate} />}
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
