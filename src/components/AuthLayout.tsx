import { type ReactNode } from 'react';
import { ShieldCheck } from 'lucide-react';

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen cyber-grid flex items-center justify-center p-4 relative overflow-hidden">
      <div className="scan-line" />
      {/* Ambient glow */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl" />

      <div className="relative z-10 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 mb-4 animate-pulse-glow">
            <ShieldCheck className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">
            <span className="text-cyan-400 text-glow-cyan">CyberTrust</span>
            <span className="text-white"> Decision Engine</span>
          </h1>
          <p className="text-sm text-gray-500 font-mono mt-1">Digital Forensics Investigation Platform</p>
          <p className="text-[10px] text-gray-600 font-mono mt-0.5">Powered by AI</p>
        </div>
        {children}
      </div>
    </div>
  );
}
