import React from 'react';
import { Shield, Lock, Terminal, KeyRound, BookOpen, UserCheck, LogOut, LogIn } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export type ActiveTab = 'chat' | 'wire_lab' | 'keys' | 'specs';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onOpenAuthModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onOpenAuthModal,
}) => {
  const { currentUser, logout } = useSecurity();

  return (
    <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand Wordmark (Single element) */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-base font-semibold tracking-tight text-slate-100 whitespace-nowrap">
            CipherShield <span className="text-xs font-normal text-emerald-400 font-mono ml-1">E2EE</span>
          </span>
        </div>

        {/* Zone 2: Navigation Links (Single-line text) */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium">
          <button
            onClick={() => setActiveTab('chat')}
            className={`whitespace-nowrap flex items-center gap-2 pb-1 border-b-2 transition-colors ${
              activeTab === 'chat'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Encrypted Chat</span>
          </button>

          <button
            onClick={() => setActiveTab('wire_lab')}
            className={`whitespace-nowrap flex items-center gap-2 pb-1 border-b-2 transition-colors ${
              activeTab === 'wire_lab'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Wire Lab & Tamper Simulator</span>
          </button>

          <button
            onClick={() => setActiveTab('keys')}
            className={`whitespace-nowrap flex items-center gap-2 pb-1 border-b-2 transition-colors ${
              activeTab === 'keys'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Key Ring & Safety Numbers</span>
          </button>

          <button
            onClick={() => setActiveTab('specs')}
            className={`whitespace-nowrap flex items-center gap-2 pb-1 border-b-2 transition-colors ${
              activeTab === 'specs'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Architecture & Specs</span>
          </button>
        </nav>

        {/* Zone 3: Primary Action / User Vault */}
        <div className="flex items-center gap-3 shrink-0">
          {currentUser ? (
            <div className="flex items-center gap-3">
              <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-md">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span>{currentUser.account.displayName}</span>
                <span className="text-slate-600">|</span>
                <span className="text-emerald-400/90">Vault Unlocked</span>
              </div>
              <button
                onClick={logout}
                title="Lock Vault & Log Out"
                className="p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-md transition-colors border border-transparent hover:border-rose-500/20"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuthModal}
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-emerald-400 rounded-md hover:bg-emerald-300 transition-colors whitespace-nowrap flex items-center gap-1.5"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Unlock Vault / Login</span>
            </button>
          )}
        </div>
      </div>

      {/* Mobile nav row */}
      <div className="md:hidden flex items-center justify-around border-t border-slate-800/80 px-2 py-2 text-xs bg-slate-950">
        <button
          onClick={() => setActiveTab('chat')}
          className={`px-2 py-1 rounded ${
            activeTab === 'chat' ? 'text-emerald-400 font-medium' : 'text-slate-400'
          }`}
        >
          Chat
        </button>
        <button
          onClick={() => setActiveTab('wire_lab')}
          className={`px-2 py-1 rounded ${
            activeTab === 'wire_lab' ? 'text-emerald-400 font-medium' : 'text-slate-400'
          }`}
        >
          Wire Lab
        </button>
        <button
          onClick={() => setActiveTab('keys')}
          className={`px-2 py-1 rounded ${
            activeTab === 'keys' ? 'text-emerald-400 font-medium' : 'text-slate-400'
          }`}
        >
          Keys
        </button>
        <button
          onClick={() => setActiveTab('specs')}
          className={`px-2 py-1 rounded ${
            activeTab === 'specs' ? 'text-emerald-400 font-medium' : 'text-slate-400'
          }`}
        >
          Specs
        </button>
      </div>
    </header>
  );
};
