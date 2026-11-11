import React, { useState } from 'react';
import { X, Lock, KeyRound, UserCheck, Shield, Sparkles, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { useSecurity, DEMO_PASSWORDS } from '../context/SecurityContext';

interface AuthModalProps {
  onClose: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ onClose }) => {
  const { accounts, login, register, error } = useSecurity();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const handleQuickFill = (accId: string) => {
    const acc = accounts.find((a) => a.id === accId);
    if (!acc) return;
    setUsername(acc.username);
    setPassword(DEMO_PASSWORDS[accId] || '');
    setMode('login');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) return;

    try {
      setIsSubmitting(true);
      if (mode === 'register') {
        setStatusMessage('Deriving PBKDF2 vault key (100,000 iterations) & generating Curve P-256 keypairs...');
        const success = await register(username.trim(), displayName.trim() || username.trim(), password);
        if (success) {
          onClose();
        }
      } else {
        setStatusMessage('Deriving key and unlocking local private key vault...');
        const success = await login(username.trim(), password);
        if (success) {
          onClose();
        }
      }
    } finally {
      setIsSubmitting(false);
      setStatusMessage(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-md transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              {mode === 'login' ? 'Unlock Identity Vault' : 'Create Encrypted Identity'}
            </h2>
            <p className="text-xs text-slate-400">
              {mode === 'login'
                ? 'Client-side PBKDF2 zero-knowledge authentication'
                : 'Generates ECDH & ECDSA Curve P-256 keys in browser'}
            </p>
          </div>
        </div>

        {/* Quick Demo Identities Fill */}
        <div className="mb-5 p-3 bg-slate-950 rounded-lg border border-slate-800/80">
          <span className="text-[11px] font-medium text-slate-400 block mb-2">
            Quick 1-Click Demo Profiles:
          </span>
          <div className="grid grid-cols-3 gap-2">
            {accounts.filter((a) => DEMO_PASSWORDS[a.id]).map((acc) => (
              <button
                key={acc.id}
                type="button"
                onClick={() => handleQuickFill(acc.id)}
                className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-center text-xs text-slate-300 hover:text-white transition-colors"
              >
                <div className="font-semibold text-emerald-400">{acc.displayName.split(' ')[0]}</div>
                <div className="text-[10px] text-slate-500 font-mono">@{acc.username}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Tab Toggle */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg mb-4 border border-slate-800">
          <button
            type="button"
            onClick={() => setMode('login')}
            className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-colors ${
              mode === 'login' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Unlock Existing Vault
          </button>
          <button
            type="button"
            onClick={() => setMode('register')}
            className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-colors ${
              mode === 'register' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Register New Identity
          </button>
        </div>

        {/* Error message */}
        {error && (
          <div className="mb-4 p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg flex items-start gap-2 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-3.5">
          {mode === 'register' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Display Name
              </label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="e.g. David Miller"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                required
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. alice"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Master Vault Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Vault passphrase (min 6 characters)"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-3 pr-10 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              Used locally with PBKDF2 (SHA-256, 100k rounds) to encrypt private keys. Never sent to a server.
            </p>
          </div>

          {statusMessage && (
            <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded text-[11px] text-emerald-300 font-mono">
              {statusMessage}
            </div>
          )}

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-2.5 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-40 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 mt-2"
          >
            <KeyRound className="w-4 h-4" />
            <span>
              {isSubmitting
                ? 'Processing Web Crypto...'
                : mode === 'login'
                ? 'Unlock Vault & Sign In'
                : 'Generate Keys & Create Vault'}
            </span>
          </button>
        </form>
      </div>
    </div>
  );
};
