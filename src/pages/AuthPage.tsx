import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import AuthLayout from '../components/AuthLayout';
import { Lock, User as UserIcon, AlertCircle, ArrowRight, KeyRound, Mail } from 'lucide-react';

type Mode = 'login' | 'register' | 'forgot';
const getUserFriendlyError = (error: any): string => {
  if (!error) {
    return 'Something went wrong. Please try again.';
  }

  // If already a normal string
  if (typeof error === 'string') {
    try {
      const parsed = JSON.parse(error);

      if (Array.isArray(parsed)) {
        return parsed
          .map((item) =>
            item?.msg?.replace(/^Value error,\s*/i, '')
          )
          .filter(Boolean)
          .join(', ');
      }

      if (parsed?.detail) {
        if (Array.isArray(parsed.detail)) {
          return parsed.detail
            .map((item: any) =>
              item?.msg?.replace(/^Value error,\s*/i, '')
            )
            .filter(Boolean)
            .join(', ');
        }

        return parsed.detail;
      }
    } catch {
      // Not JSON, just use the string
    }

    return error;
  }

  // FastAPI/Pydantic error object
  if (error?.detail) {
    if (Array.isArray(error.detail)) {
      return error.detail
        .map((item: any) =>
          item?.msg?.replace(/^Value error,\s*/i, '')
        )
        .filter(Boolean)
        .join(', ');
    }

    return error.detail;
  }

  return 'Something went wrong. Please try again.';
};
export default function AuthPage() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<Mode>('login');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  // login fields
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // register fields
  const [fullName, setFullName] = useState('');
  const [regUsername, setRegUsername] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const switchMode = (m: Mode) => {
    setMode(m);
    setError('');
    setSuccess('');
  };

  const handleLogin = async (e: React.FormEvent) => {
  e.preventDefault();

  setError('');
  setLoading(true);

  const result = await login(email, password);

  setLoading(false);

  if (!result.ok) {
    setError(getUserFriendlyError(result.error));
  }
};

const handleRegister = async (e: React.FormEvent) => {
  e.preventDefault();

  setError('');
  setSuccess('');

  if (fullName.trim().length < 2) {
    return setError('Full name must be at least 2 characters.');
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return setError('Please enter a valid email address.');
  }

  if (regUsername.trim().length < 3) {
    return setError('Username must be at least 3 characters.');
  }

  if (password.length < 8) {
    return setError('Password must be at least 8 characters.');
  }

  if (password !== confirmPassword) {
    return setError('Passwords do not match.');
  }

  setLoading(true);

  const result = await register({
    fullName: fullName.trim(),
    email: email.trim(),
    username: regUsername.trim(),
    password,
  });

  setLoading(false);

  if (!result.ok) {
    return setError(result.error || 'Registration failed');
  }

  // Registration already creates an authenticated session.
  // The user can directly enter the dashboard.
};

  const handleForgot = (e: React.FormEvent) => {
    e.preventDefault();
    setSuccess('Password reset link sent to your email (demo only).');
    setError('');
  };

  return (
    <AuthLayout>
      <div className="bg-[#0f1620]/80 backdrop-blur-xl border border-gray-800 rounded-2xl p-8 shadow-2xl animate-fadeIn">
        {/* Tabs */}
        <div className="flex gap-1 mb-6 p-1 bg-[#0a0e14] rounded-lg border border-gray-800">
          <button
            onClick={() => switchMode('login')}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition-all ${mode === 'login' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30' : 'text-gray-500 hover:text-gray-300'}`}
          >
            Login
          </button>
          <button
            onClick={() => switchMode('register')}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition-all ${mode === 'register' ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30' : 'text-gray-500 hover:text-gray-300'}`}
          >
            Register
          </button>
        </div>

        {error && (
          <div className="mb-4 flex items-start gap-2 px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400 animate-fadeIn">
          <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span className="leading-relaxed">{error}</span>
          </div>
        )}
        {success && (
          <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-sm text-emerald-400 animate-fadeIn">
            <span>{success}</span>
          </div>
        )}

        {mode === 'login' && (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">
                  Email
              </label>
              <div className="relative">
                <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                <input
                  type="text"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                  placeholder="Enter your email"
                  required
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                <input
                  type="password"
                  value={password}
                  onChange={e => {
  setPassword(e.target.value);
  setError('');
}}
                  className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                  placeholder="Enter your password"
                  required
                />
              </div>
            </div>
            <div className="flex justify-end">
              <button type="button" onClick={() => switchMode('forgot')} className="text-xs text-gray-500 hover:text-cyan-400 transition-colors">
                Forgot password?
              </button>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-medium py-2.5 rounded-lg transition-all disabled:opacity-50 group"
            >
              {loading ? 'Authenticating...' : <>Access Dashboard <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" /></>}
            </button>
            <p className="text-center text-xs text-gray-600 pt-2">
              No account? <button type="button" onClick={() => switchMode('register')} className="text-cyan-400 hover:underline">Create one</button>
            </p>
          </form>
        )}

        {mode === 'register' && (
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Full Name</label>
              <input
                type="text"
                value={fullName}
                onChange={e => setFullName(e.target.value)}
                className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                placeholder="John Doe"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                  placeholder="john@example.com"
                  required
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Username</label>
              <div className="relative">
                <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                <input
                  type="text"
                  value={regUsername}
                  onChange={e => {
                    setRegUsername(e.target.value);
                    setError('');
                  }}
                  className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                  placeholder="Choose a username"
                  required
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                  <input
                    type="password"
                    value={password}
                    onChange={e => {
                      setPassword(e.target.value);
                      setError('');
                    }}
                    className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-3 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                    placeholder="Min 6 chars"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Confirm</label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={e => {
                      setConfirmPassword(e.target.value);
                      setError('');
                    }}
                    className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-3 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                    placeholder="Repeat"
                    required
                  />
                </div>
              </div>
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 hover:border-emerald-500/50 text-emerald-400 font-medium py-2.5 rounded-lg transition-all disabled:opacity-50"
            >
              {loading ? 'Creating account...' : 'Create Account'}
            </button>
            <p className="text-center text-xs text-gray-600 pt-2">
              Already have an account? <button type="button" onClick={() => switchMode('login')} className="text-cyan-400 hover:underline">Login</button>
            </p>
          </form>
        )}

        {mode === 'forgot' && (
          <form onSubmit={handleForgot} className="space-y-4">
            <p className="text-sm text-gray-500 mb-4">Enter your email and we'll send you a reset link.</p>
            <div>
              <label className="block text-xs font-mono text-gray-500 mb-1.5 uppercase tracking-wider">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                <input
                  type="email"
                  className="w-full bg-[#0a0e14] border border-gray-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                  placeholder="your@email.com"
                  required
                />
              </div>
            </div>
            <button
              type="submit"
              className="w-full bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-500/50 text-cyan-400 font-medium py-2.5 rounded-lg transition-all"
            >
              Send Reset Link
            </button>
            <p className="text-center text-xs text-gray-600 pt-2">
              Remember your password? <button type="button" onClick={() => switchMode('login')} className="text-cyan-400 hover:underline">Login</button>
            </p>
          </form>
        )}
      </div>
    </AuthLayout>
  );
}
