import React from 'react';
import {
  Shield,
  Key,
  Lock,
  CheckCircle2,
  Cpu,
  Layers,
  ArrowRight,
  Database,
  Terminal,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const ArchitectureView: React.FC = () => {
  const { resetToDemoState } = useSecurity();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <span>Cryptographic Architecture & Security Specifications</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Implementation standards compliant with native W3C Web Cryptography API (SubtleCrypto).
          </p>
        </div>

        <button
          onClick={resetToDemoState}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-lg text-xs font-medium transition-colors"
        >
          Reset Demo Data & Keystores
        </button>
      </div>

      {/* 4 Core Pillars Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Pillar 1: User Authentication & Vault */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400">
            <Key className="w-4 h-4" />
            <h2 className="text-sm font-semibold text-slate-100">1. User Authentication & Vault Key Derivation</h2>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            The application operates on a <strong>Zero-Knowledge Keystore model</strong>. The user's master password never leaves the client and is never stored in plaintext anywhere.
          </p>
          <div className="space-y-1.5 text-xs text-slate-400">
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>KDF Algorithm:</strong> PBKDF2 with SHA-256 and 100,000 iterations.</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Salt:</strong> 128-bit cryptographically secure random bytes (<code className="text-slate-300">crypto.getRandomValues</code>).</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Private Key Vault:</strong> ECDH and ECDSA private keys are exported to JWK, serialized, and encrypted locally with AES-256-GCM using the derived PBKDF2 vault key.</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Authentication Verifier:</strong> Login verifies password correctness by deriving the key and comparing SHA-256(DerivedKey || Salt) without exposing the secret.</span>
            </div>
          </div>
        </div>

        {/* Pillar 2: Secure Key Exchange (ECDH) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400">
            <Cpu className="w-4 h-4" />
            <h2 className="text-sm font-semibold text-slate-100">2. Secure Key Exchange (Elliptic Curve Diffie-Hellman)</h2>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Parties negotiate symmetric conversation encryption keys over untrusted networks using Elliptic Curve Diffie-Hellman (ECDH) on NIST Curve P-256 (secp256r1).
          </p>
          <div className="space-y-1.5 text-xs text-slate-400">
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Curve:</strong> NIST P-256 (FIPS 186-4 standard, 256-bit prime field).</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Scalar Agreement:</strong> Alice computes <code className="text-emerald-300">d_Alice · Q_Bob</code>; Bob computes <code className="text-emerald-300">d_Bob · Q_Alice</code>. Both yield the exact same curve point.</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>KDF Derivation:</strong> Derived raw bits are passed through Web Crypto to generate a non-extractable 256-bit AES-GCM session key.</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Safety Numbers:</strong> 60-digit numerical fingerprints (Signal format) verify out-of-band identity to prevent Man-in-the-Middle (MITM) attacks.</span>
            </div>
          </div>
        </div>

        {/* Pillar 3: End-to-End Encryption (AES-256-GCM) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400">
            <Lock className="w-4 h-4" />
            <h2 className="text-sm font-semibold text-slate-100">3. Authenticated End-to-End Encryption (AEAD)</h2>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Plaintext messages are transformed into ciphertext on the sender's device before leaving the browser. The network transport and database only ever see opaque ciphertext packets.
          </p>
          <div className="space-y-1.5 text-xs text-slate-400">
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Mode:</strong> AES-256-GCM (Galois/Counter Mode).</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Initialization Vector (IV):</strong> Unique 96-bit (12-byte) cryptographically random nonce generated per message. Nonce reuse is strictly prohibited.</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Confidentiality:</strong> Strong 256-bit encryption strength resistant to brute-force and classical cryptanalysis.</span>
            </div>
          </div>
        </div>

        {/* Pillar 4: Message Integrity & Non-Repudiation */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400">
            <Shield className="w-4 h-4" />
            <h2 className="text-sm font-semibold text-slate-100">4. Message Integrity & Digital Signatures</h2>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Message integrity is enforced by two complementary mathematical mechanisms to defend against tampering, bit-flipping, and forgery.
          </p>
          <div className="space-y-1.5 text-xs text-slate-400">
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>AEAD Authentication Tag:</strong> AES-GCM appends a 128-bit authentication tag calculated over ciphertext and GHASH. Any single bit-flip causes decryption to abort.</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>ECDSA Digital Signatures:</strong> Sender signs packet metadata (<code className="text-slate-300">id, senderId, recipientId, timestamp, IV, ciphertext</code>) with ECDSA (SHA-256, P-256).</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono">▸</span>
              <span><strong>Non-Repudiation:</strong> Guarantees message came from the claimed sender and was not forged by an eavesdropper or rogue server.</span>
            </div>
          </div>
        </div>
      </div>

      {/* Cryptographic Pipeline Flowchart */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <span>End-to-End Cryptographic Packet Lifecycle</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-slate-500 font-sans block mb-1">STEP 1</span>
              <span className="text-slate-200 font-semibold font-sans">Sender Plaintext</span>
              <p className="text-[11px] text-slate-400 font-sans mt-1">UTF-8 encoded message buffer</p>
            </div>
            <div className="mt-3 text-emerald-400 text-[10px]">Plaintext in RAM</div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-slate-500 font-sans block mb-1">STEP 2</span>
              <span className="text-slate-200 font-semibold font-sans">ECDH Agreement</span>
              <p className="text-[11px] text-slate-400 font-sans mt-1">S = d_A · Q_B on Curve P-256</p>
            </div>
            <div className="mt-3 text-emerald-400 text-[10px]">256-bit AES-GCM Key</div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-slate-500 font-sans block mb-1">STEP 3</span>
              <span className="text-slate-200 font-semibold font-sans">AES-256-GCM</span>
              <p className="text-[11px] text-slate-400 font-sans mt-1">Encrypt + 128-bit MAC Tag</p>
            </div>
            <div className="mt-3 text-emerald-400 text-[10px]">96-bit IV + Ciphertext</div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-slate-500 font-sans block mb-1">STEP 4</span>
              <span className="text-slate-200 font-semibold font-sans">ECDSA Sign</span>
              <p className="text-[11px] text-slate-400 font-sans mt-1">Sign wire packet envelope</p>
            </div>
            <div className="mt-3 text-amber-400 text-[10px]">Digital Signature</div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col justify-between">
            <div>
              <span className="text-[10px] text-slate-500 font-sans block mb-1">STEP 5</span>
              <span className="text-slate-200 font-semibold font-sans">Recipient Verify</span>
              <p className="text-[11px] text-slate-400 font-sans mt-1">Signature check + AEAD tag</p>
            </div>
            <div className="mt-3 text-emerald-400 text-[10px]">Plaintext Decrypted</div>
          </div>
        </div>
      </div>
    </div>
  );
};
