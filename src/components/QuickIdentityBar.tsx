import React from 'react';
import { UserCheck, ShieldCheck, Key, UserPlus } from 'lucide-react';
import { useSecurity, DEMO_PASSWORDS } from '../context/SecurityContext';

interface QuickIdentityBarProps {
  onOpenAuthModal: () => void;
}

export const QuickIdentityBar: React.FC<QuickIdentityBarProps> = ({ onOpenAuthModal }) => {
  const { accounts, currentUser, switchQuickUser, isLoading } = useSecurity();

  const demoAccounts = accounts.filter((a) => DEMO_PASSWORDS[a.id]);

  return (
    <div className="bg-slate-900/80 border-b border-slate-800/80 px-4 py-2.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        {/* Left: Active Identity & Cryptographic Parameters */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-slate-400">
          <div className="flex items-center gap-1.5 text-slate-200">
            <span className="text-slate-500">Active Identity:</span>
            {currentUser ? (
              <span className="font-semibold text-emerald-400 flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded-full bg-emerald-400"></span>
                {currentUser.account.displayName}{' '}
                <span className="text-slate-400 font-normal font-mono">(@{currentUser.account.username})</span>
              </span>
            ) : (
              <span className="text-amber-400 font-medium">Vault Locked (Guest)</span>
            )}
          </div>

          <span className="hidden md:inline text-slate-700">|</span>

          <div className="flex items-center gap-3 font-mono text-[11px] text-slate-400">
            <span>
              Curve: <span className="text-slate-300">P-256 (ECDH)</span>
            </span>
            <span className="text-slate-700">·</span>
            <span>
              Cipher: <span className="text-slate-300">AES-256-GCM</span>
            </span>
            <span className="text-slate-700">·</span>
            <span>
              Signature: <span className="text-slate-300">ECDSA-SHA256</span>
            </span>
          </div>
        </div>

        {/* Right: Quick Switch identities for testing E2EE */}
        <div className="flex items-center gap-2">
          <span className="text-slate-500 font-medium">Switch Identity:</span>
          <div className="flex items-center gap-1.5">
            {demoAccounts.map((account) => {
              const isActive = currentUser?.account.id === account.id;
              return (
                <button
                  key={account.id}
                  disabled={isLoading}
                  onClick={() => switchQuickUser(account.id)}
                  className={`px-2.5 py-1 rounded text-xs transition-colors font-medium ${
                    isActive
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white border border-slate-700/60'
                  }`}
                  title={`Switch active session to ${account.displayName}`}
                >
                  {account.displayName.split(' ')[0]}
                </button>
              );
            })}

            <button
              onClick={onOpenAuthModal}
              className="p-1 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors ml-1 border border-transparent hover:border-slate-700"
              title="Add New Identity / Custom Registration"
            >
              <UserPlus className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
