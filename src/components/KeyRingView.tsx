import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Check,
  Download,
  Fingerprint,
  RefreshCw,
  Lock,
  ExternalLink,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { computeKeyFingerprint, generateSafetyNumber } from '../crypto/cryptoEngine';

export const KeyRingView: React.FC = () => {
  const { accounts, currentUser, toggleVerifySafetyNumber, isSafetyNumberVerified } = useSecurity();

  const [selectedUserAId, setSelectedUserAId] = useState<string>(
    currentUser?.account.id || accounts[0]?.id || ''
  );
  const [selectedUserBId, setSelectedUserBId] = useState<string>(
    accounts.find((a) => a.id !== (currentUser?.account.id || accounts[0]?.id))?.id || ''
  );

  const [safetyNumber, setSafetyNumber] = useState<string>('');
  const [fingerprints, setFingerprints] = useState<Record<string, { ecdh: string; ecdsa: string }>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Compute fingerprints for all registered accounts
  useEffect(() => {
    let active = true;
    async function calcAllFingerprints() {
      const results: Record<string, { ecdh: string; ecdsa: string }> = {};
      for (const acc of accounts) {
        const ecdhFp = await computeKeyFingerprint(acc.publicKeys.ecdh);
        const ecdsaFp = await computeKeyFingerprint(acc.publicKeys.ecdsa);
        results[acc.id] = { ecdh: ecdhFp, ecdsa: ecdsaFp };
      }
      if (active) setFingerprints(results);
    }
    calcAllFingerprints();
    return () => {
      active = false;
    };
  }, [accounts]);

  // Compute safety number between selected user pair
  useEffect(() => {
    let active = true;
    async function calcSafety() {
      const userA = accounts.find((a) => a.id === selectedUserAId);
      const userB = accounts.find((a) => a.id === selectedUserBId);
      if (!userA || !userB || userA.id === userB.id) {
        setSafetyNumber('');
        return;
      }

      const num = await generateSafetyNumber(
        userA.publicKeys.ecdh,
        userB.publicKeys.ecdh,
        userA.id,
        userB.id
      );
      if (active) setSafetyNumber(num);
    }
    calcSafety();
    return () => {
      active = false;
    };
  }, [selectedUserAId, selectedUserBId, accounts]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const exportDirectoryJson = () => {
    const publicDirectory = accounts.map((a) => ({
      id: a.id,
      username: a.username,
      displayName: a.displayName,
      publicKeys: a.publicKeys,
      createdAt: a.createdAt,
    }));
    const blob = new Blob([JSON.stringify(publicDirectory, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ciphershield_public_directory_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-emerald-400" />
            <span>Public Key Ring & Identity Directory</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Zero-knowledge public key exchange directory. Each identity publishes their ECDH agreement public key
            and ECDSA verification public key. Private keys remain locked in local PBKDF2 vaults.
          </p>
        </div>

        <button
          onClick={exportDirectoryJson}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 rounded-lg text-xs font-medium transition-colors flex items-center gap-2 self-start md:self-auto"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Public Key Directory (JSON)</span>
        </button>
      </div>

      {/* Safety Numbers Comparison Sandbox */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-slate-100">
              Out-of-Band Safety Number Comparator (Signal Protocol Standard)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-500">60-DIGIT NUMERIC MATRIX</span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Select any two identities to compute their mutual mathematical fingerprint. When two users compare this number over a voice call or in person, they cryptographically verify that no Man-in-the-Middle is intercepting their ECDH exchange.
        </p>

        {/* User selectors */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Party A:</label>
            <select
              value={selectedUserAId}
              onChange={(e) => setSelectedUserAId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id} disabled={a.id === selectedUserBId}>
                  {a.displayName} (@{a.username}) {a.id === currentUser?.account.id ? '(You)' : ''}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Party B:</label>
            <select
              value={selectedUserBId}
              onChange={(e) => setSelectedUserBId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id} disabled={a.id === selectedUserAId}>
                  {a.displayName} (@{a.username})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* 60-digit display */}
        {safetyNumber ? (
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-medium text-slate-300">
                Mutual Safety Number ({accounts.find((a) => a.id === selectedUserAId)?.displayName.split(' ')[0]} ↔{' '}
                {accounts.find((a) => a.id === selectedUserBId)?.displayName.split(' ')[0]}):
              </span>
              <button
                onClick={() => copyToClipboard(safetyNumber, 'safety')}
                className="flex items-center gap-1 text-slate-300 hover:text-emerald-400 transition-colors"
              >
                {copiedKey === 'safety' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'safety' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-2 text-center font-mono text-sm tracking-wider text-emerald-400 tabular-nums">
              {safetyNumber.split(' ').map((chunk, idx) => (
                <div key={idx} className="bg-slate-900 border border-slate-800 py-1.5 px-1 rounded">
                  {chunk}
                </div>
              ))}
            </div>

            <div className="pt-2 flex items-center justify-between text-[11px] text-slate-500 border-t border-slate-800/80">
              <span>Derived from sorted ECDH Curve P-256 public keys via SHA-256</span>
              {selectedUserAId === currentUser?.account.id && (
                <button
                  onClick={() => toggleVerifySafetyNumber(selectedUserBId)}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    isSafetyNumberVerified(selectedUserBId)
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {isSafetyNumberVerified(selectedUserBId) ? '✓ Verified by You' : 'Mark Verified'}
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-center text-xs text-slate-500">
            Select two distinct users to compute mutual safety numbers.
          </div>
        )}
      </div>

      {/* Directory of Published Public Keys */}
      <div className="space-y-4">
        <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <span>Registered Public Key Directory</span>
          <span className="text-xs font-normal text-slate-500">({accounts.length} identities)</span>
        </h2>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {accounts.map((acc) => {
            const isMe = acc.id === currentUser?.account.id;
            const fps = fingerprints[acc.id];

            return (
              <div
                key={acc.id}
                className={`bg-slate-900 border rounded-xl p-5 space-y-4 flex flex-col justify-between ${
                  isMe ? 'border-emerald-500/40 bg-slate-900/90' : 'border-slate-800'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-slate-200">
                        {acc.avatar}
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-100 flex items-center gap-1.5">
                          {acc.displayName}
                          {isMe && (
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 font-normal">
                              YOU
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">@{acc.username}</div>
                      </div>
                    </div>

                    <span className="text-[10px] font-mono text-slate-500">
                      Curve P-256
                    </span>
                  </div>

                  {/* Public Key Fingerprints */}
                  <div className="space-y-2 mt-4 text-[11px] font-mono">
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-sans mb-0.5">
                        <span>ECDH Agreement Fingerprint:</span>
                        <button
                          onClick={() => copyToClipboard(fps?.ecdh || '', `ecdh_${acc.id}`)}
                          className="hover:text-emerald-400 transition-colors"
                        >
                          {copiedKey === `ecdh_${acc.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                      <div className="text-emerald-400 break-all text-[10px]">{fps?.ecdh || 'Calculating...'}</div>
                    </div>

                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-sans mb-0.5">
                        <span>ECDSA Signing Fingerprint:</span>
                        <button
                          onClick={() => copyToClipboard(fps?.ecdsa || '', `ecdsa_${acc.id}`)}
                          className="hover:text-emerald-400 transition-colors"
                        >
                          {copiedKey === `ecdsa_${acc.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                      <div className="text-amber-400 break-all text-[10px]">{fps?.ecdsa || 'Calculating...'}</div>
                    </div>
                  </div>
                </div>

                {/* JWK Coordinates Preview */}
                <div className="pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-400 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 font-sans">Public Coordinates (X, Y):</span>
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(acc.publicKeys, null, 2), `jwk_${acc.id}`)}
                      className="text-emerald-400 hover:text-emerald-300 font-sans flex items-center gap-1"
                    >
                      {copiedKey === `jwk_${acc.id}` ? 'Copied' : 'Copy JWK'}
                    </button>
                  </div>
                  <div className="truncate text-slate-500">X: {acc.publicKeys.ecdh.x}</div>
                  <div className="truncate text-slate-500">Y: {acc.publicKeys.ecdh.y}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
