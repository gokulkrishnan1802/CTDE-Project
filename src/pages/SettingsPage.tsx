import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { investigationStore, chatStore } from '../lib/storage';
import type { PageKey } from '../components/AppLayout';
import {
  Settings as SettingsIcon, User as UserIcon, Lock, Download, Trash2,
  Bell, Shield, Save, AlertTriangle, Check
} from 'lucide-react';

interface Props {
  onNavigate: (p: PageKey) => void;
}

export default function SettingsPage({ onNavigate: _onNavigate }: Props) {
  const { user, deleteAccount } = useAuth();
  const [showDelete, setShowDelete] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [oldPw, setOldPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');

  // UI-only settings state
  const [notifications, setNotifications] = useState(true);
  const [autoScan, setAutoScan] = useState(false);
  const [theme, setTheme] = useState('dark');

  const handleExport = () => {
    if (!user) return;
    const data = {
      user: { fullName: user.fullName, email: user.email, username: user.username, createdAt: user.createdAt },
      investigations: investigationStore.getByUser(user.id),
      exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ctde_user_data_${user.username}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleChangePassword = (e: React.FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    if (!user) return;
    if (oldPw !== user.password) return setPwMsg({ type: 'error', text: 'Current password is incorrect.' });
    if (newPw.length < 6) return setPwMsg({ type: 'error', text: 'New password must be at least 6 characters.' });
    if (newPw !== confirmPw) return setPwMsg({ type: 'error', text: 'Passwords do not match.' });
    // UI only — would call API in production
    setPwMsg({ type: 'success', text: 'Password updated successfully. (Demo only — not saved)' });
    setOldPw(''); setNewPw(''); setConfirmPw('');
  };

  const handleDeleteAccount = () => {
    if (!user) return;
    // Clean up user's investigation chats
    investigationStore.getByUser(user.id).forEach(inv => chatStore.clear(inv.id));
    deleteAccount();
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-3xl">
      <div>
        <h2 className="text-2xl font-bold text-gray-100">Settings</h2>
        <p className="text-sm text-gray-500 mt-1">Manage your account and preferences</p>
      </div>

      {/* Profile */}
      <Section icon={UserIcon} title="Profile Information">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="Full Name" value={user?.fullName || ''} />
          <Field label="Username" value={`@${user?.username || ''}`} />
          <Field label="Email" value={user?.email || ''} />
          <Field label="Member Since" value={user ? new Date(user.createdAt).toLocaleDateString() : ''} />
        </div>
      </Section>

      {/* Change Password */}
      <Section icon={Lock} title="Change Password">
        <form onSubmit={handleChangePassword} className="space-y-3">
          {pwMsg && (
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${
              pwMsg.type === 'success' ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border border-red-500/30 text-red-400'
            }`}>
              {pwMsg.type === 'success' ? <Check className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {pwMsg.text}
            </div>
          )}
          <input type="password" value={oldPw} onChange={e => setOldPw(e.target.value)} placeholder="Current password"
            className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} placeholder="New password"
              className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
            <input type="password" value={confirmPw} onChange={e => setConfirmPw(e.target.value)} placeholder="Confirm new password"
              className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all" required />
          </div>
          <button type="submit" className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 text-sm font-medium rounded-lg transition-all">
            <Save className="w-4 h-4" /> Update Password
          </button>
        </form>
      </Section>

      {/* Preferences */}
      <Section icon={Bell} title="Preferences">
        <div className="space-y-3">
          <Toggle label="Email Notifications" desc="Receive alerts about your investigations" value={notifications} onChange={setNotifications} />
          <Toggle label="Auto-scan URLs" desc="Automatically scan URLs when pasted" value={autoScan} onChange={setAutoScan} />
          <div>
            <label className="text-sm text-gray-300">Theme</label>
            <p className="text-xs text-gray-600 mb-2">Choose your interface theme</p>
            <div className="flex gap-2">
              {['dark', 'cyber', 'midnight'].map(t => (
                <button key={t} onClick={() => setTheme(t)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-all capitalize ${theme === t ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' : 'bg-[#0a0e14] border-gray-800 text-gray-500 hover:text-gray-300'}`}>
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Section>

      {/* Data Management */}
      <Section icon={Shield} title="Data Management">
        <div className="space-y-3">
          <button onClick={handleExport}
            className="w-full flex items-center justify-between px-4 py-3 bg-[#0a0e14] border border-gray-800 hover:border-cyan-500/30 rounded-lg transition-all group">
            <div className="flex items-center gap-3">
              <Download className="w-4 h-4 text-cyan-400" />
              <div className="text-left">
                <p className="text-sm text-gray-300">Export User Data</p>
                <p className="text-xs text-gray-600">Download all your data as JSON</p>
              </div>
            </div>
            <span className="text-xs text-gray-600 group-hover:text-cyan-400 transition-colors">Download →</span>
          </button>
        </div>
      </Section>

      {/* Danger Zone */}
      <Section icon={AlertTriangle} title="Danger Zone" danger>
        <button onClick={() => setShowDelete(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 hover:border-red-500/50 text-red-400 text-sm font-medium rounded-lg transition-all">
          <Trash2 className="w-4 h-4" /> Delete Account
        </button>
        <p className="text-xs text-gray-600 mt-2">This will permanently delete your account and all associated data.</p>
      </Section>

      {/* Delete confirmation modal */}
      {showDelete && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowDelete(false)}>
          <div className="bg-[#0f1620] border border-red-500/30 rounded-2xl max-w-md w-full p-6 animate-fadeIn" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-gray-200">Delete Account?</h3>
                <p className="text-xs text-gray-600">This action cannot be undone</p>
              </div>
            </div>
            <p className="text-sm text-gray-400 mb-5">
              All your investigations, reports, and account data will be permanently removed. This cannot be recovered.
            </p>
            <div className="flex gap-2">
              <button onClick={() => setShowDelete(false)}
                className="flex-1 px-4 py-2.5 bg-[#0a0e14] border border-gray-800 hover:border-gray-700 text-gray-400 hover:text-gray-200 text-sm font-medium rounded-lg transition-all">
                Cancel
              </button>
              <button onClick={handleDeleteAccount}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 hover:border-red-500/50 text-red-400 text-sm font-medium rounded-lg transition-all">
                <Trash2 className="w-4 h-4" /> Delete Forever
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ icon: Icon, title, children, danger }: { icon: typeof SettingsIcon; title: string; children: React.ReactNode; danger?: boolean }) {
  return (
    <div className={`bg-[#0f1620] border rounded-2xl p-6 ${danger ? 'border-red-500/20' : 'border-gray-800/60'}`}>
      <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${danger ? 'text-red-400' : 'text-gray-300'}`}>
        <Icon className="w-4 h-4" /> {title}
      </h3>
      {children}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <label className="block text-xs font-mono text-gray-600 mb-1 uppercase tracking-wider">{label}</label>
      <div className="px-3 py-2 bg-[#0a0e14] border border-gray-800 rounded-lg text-sm text-gray-300">{value}</div>
    </div>
  );
}

function Toggle({ label, desc, value, onChange }: { label: string; desc: string; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-300">{label}</p>
        <p className="text-xs text-gray-600">{desc}</p>
      </div>
      <button
        onClick={() => onChange(!value)}
        className={`relative w-11 h-6 rounded-full transition-colors ${value ? 'bg-cyan-500/30' : 'bg-gray-800'}`}
      >
        <span className={`absolute top-0.5 w-5 h-5 rounded-full transition-transform ${value ? 'translate-x-5 bg-cyan-400' : 'translate-x-0.5 bg-gray-600'}`} />
      </button>
    </div>
  );
}
