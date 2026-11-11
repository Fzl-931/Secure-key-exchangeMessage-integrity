import React, { useState, useEffect } from 'react';
import { X, ShieldCheck, ShieldAlert, Copy, Check, QrCode } from 'lucide-react';
import { UserAccount, SessionUser } from '../types/crypto';
import { generateSafetyNumber, computeKeyFingerprint } from '../crypto/cryptoEngine';
import { useSecurity } from '../context/SecurityContext';

interface SafetyNumberModalProps {
  contact: UserAccount;
  currentUser: SessionUser;
  onClose: () => void;
}

export const SafetyNumberModal: React.FC<SafetyNumberModalProps> = ({
  contact,
  currentUser,
  onClose,
}) => {
  const { isSafetyNumberVerified, toggleVerifySafetyNumber } = useSecurity();
  const [safetyNumber, setSafetyNumber] = useState<string>('');
  const [myFingerprint, setMyFingerprint] = useState<string>('');
  const [peerFingerprint, setPeerFingerprint] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  const isVerified = isSafetyNumberVerified(contact.id);

  useEffect(() => {
    let active = true;
    async function calc() {
      const num = await generateSafetyNumber(
        currentUser.account.publicKeys.ecdh,
        contact.publicKeys.ecdh,
        currentUser.account.id,
        contact.id
      );
      const myFp = await computeKeyFingerprint(currentUser.account.publicKeys.ecdh);
      const peerFp = await computeKeyFingerprint(contact.publicKeys.ecdh);

      if (active) {
        setSafetyNumber(num);
        setMyFingerprint(myFp);
        setPeerFingerprint(peerFp);
      }
    }
    calc();
    return () => {
      active = false;
    };
  }, [contact, currentUser]);

  const handleCopy = () => {
    navigator.clipboard.writeText(safetyNumber);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const blocks = safetyNumber.split(' ');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-md transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              isVerified
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
            }`}
          >
            {isVerified ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-100">
              Verify Safety Numbers
            </h3>
            <p className="text-xs text-slate-400">
              Cryptographic key agreement with {contact.displayName}
            </p>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed mb-4">
          Compare this 60-digit safety number with {contact.displayName} via a secure out-of-band channel
          (in person or encrypted call). If the numbers match exactly, your end-to-end encryption is mathematically
          immune to man-in-the-middle attacks.
        </p>

        {/* 60-digit numerical grid (12 blocks of 5 digits) */}
        <div className="bg-slate-950 border border-slate-800/90 rounded-lg p-4 mb-4">
          <div className="grid grid-cols-3 sm:grid-cols-4 gap-2 text-center font-mono text-sm tracking-wider text-emerald-400 tabular-nums">
            {blocks.map((block, i) => (
              <span key={i} className="py-1 px-1 bg-slate-900/60 rounded border border-slate-800">
                {block}
              </span>
            ))}
          </div>

          <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
            <span>Algorithm: SHA-256(ECDH Public Keys)</span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 text-slate-300 hover:text-emerald-400 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Number'}</span>
            </button>
          </div>
        </div>

        {/* Individual Fingerprints */}
        <div className="space-y-2 mb-6 text-xs font-mono">
          <div className="p-2.5 bg-slate-950/60 border border-slate-800/60 rounded">
            <span className="text-slate-500 block text-[10px] font-sans">Your ECDH Fingerprint (Curve P-256):</span>
            <span className="text-slate-300 break-all">{myFingerprint || 'Calculating...'}</span>
          </div>
          <div className="p-2.5 bg-slate-950/60 border border-slate-800/60 rounded">
            <span className="text-slate-500 block text-[10px] font-sans">{contact.displayName}'s ECDH Fingerprint:</span>
            <span className="text-slate-300 break-all">{peerFingerprint || 'Calculating...'}</span>
          </div>
        </div>

        {/* Verification Action */}
        <div className="flex items-center justify-between gap-4 pt-2 border-t border-slate-800">
          <span className="text-xs text-slate-400">
            Current status: {isVerified ? (
              <span className="text-emerald-400 font-medium">Verified & Trusted</span>
            ) : (
              <span className="text-amber-400 font-medium">Unverified Key</span>
            )}
          </span>

          <button
            onClick={() => toggleVerifySafetyNumber(contact.id)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors ${
              isVerified
                ? 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                : 'bg-emerald-500 text-slate-950 hover:bg-emerald-400'
            }`}
          >
            {isVerified ? 'Mark as Unverified' : 'Mark as Verified'}
          </button>
        </div>
      </div>
    </div>
  );
};
