/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { SecurityProvider, useSecurity } from './context/SecurityContext';
import { Header, ActiveTab } from './components/Header';
import { QuickIdentityBar } from './components/QuickIdentityBar';
import { ChatView } from './components/ChatView';
import { WireLab } from './components/WireLab';
import { KeyRingView } from './components/KeyRingView';
import { ArchitectureView } from './components/ArchitectureView';
import { AuthModal } from './components/AuthModal';
import { Shield } from 'lucide-react';

function AppContent() {
  const { isInitialized, isLoading } = useSecurity();
  const [activeTab, setActiveTab] = useState<ActiveTab>('chat');
  const [showAuthModal, setShowAuthModal] = useState(false);

  if (!isInitialized && isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-300">
        <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-4 animate-pulse">
          <Shield className="w-6 h-6" />
        </div>
        <div className="text-sm font-semibold text-slate-100 mb-1">
          Initializing CipherShield Web Crypto Engine
        </div>
        <p className="text-xs text-slate-500 font-mono">
          Generating Curve P-256 KeyPairs & Deriving PBKDF2 Vaults...
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenAuthModal={() => setShowAuthModal(true)}
      />

      <QuickIdentityBar onOpenAuthModal={() => setShowAuthModal(true)} />

      <main className="flex-1 flex flex-col">
        {activeTab === 'chat' && <ChatView />}
        {activeTab === 'wire_lab' && <WireLab />}
        {activeTab === 'keys' && <KeyRingView />}
        {activeTab === 'specs' && <ArchitectureView />}
      </main>

      {showAuthModal && (
        <AuthModal onClose={() => setShowAuthModal(false)} />
      )}
    </div>
  );
}

export default function App() {
  return (
    <SecurityProvider>
      <AppContent />
    </SecurityProvider>
  );
}
