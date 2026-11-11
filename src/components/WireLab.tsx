import React, { useState, useEffect } from 'react';
import {
  Terminal,
  ArrowRight,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Key,
  Lock,
  Unlock,
  Bug,
  RotateCcw,
  Sparkles,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { UserAccount, EncryptedMessagePacket, DecryptedMessage } from '../types/crypto';
import {
  deriveSharedSecretKey,
  inspectSharedBits,
  encryptAndSignMessage,
  verifyAndDecryptMessage,
  importPeerPublicKeys,
  computeKeyFingerprint,
  sha256Hex,
} from '../crypto/cryptoEngine';

export const WireLab: React.FC = () => {
  const { accounts, currentUser } = useSecurity();

  // Selected sender and recipient
  const [senderId, setSenderId] = useState<string>(currentUser?.account.id || accounts[0]?.id || 'usr_alice');
  const [recipientId, setRecipientId] = useState<string>(
    accounts.find((a) => a.id !== (currentUser?.account.id || accounts[0]?.id))?.id || 'usr_bob'
  );

  const [inputPlaintext, setInputPlaintext] = useState<string>(
    'Confidential operation status: Target coordinates confirmed. Execute protocol Delta.'
  );

  // Cryptographic stages state
  const [sharedSecretHex, setSharedSecretHex] = useState<string>('');
  const [sharedKeyFingerprint, setSharedKeyFingerprint] = useState<string>('');
  const [packet, setPacket] = useState<EncryptedMessagePacket | null>(null);
  const [originalPacket, setOriginalPacket] = useState<EncryptedMessagePacket | null>(null);
  const [decryptionResult, setDecryptionResult] = useState<DecryptedMessage | null>(null);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [tamperType, setTamperType] = useState<string | null>(null);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const senderAccount = accounts.find((a) => a.id === senderId) || accounts[0];
  const recipientAccount = accounts.find((a) => a.id === recipientId) || accounts[1];

  // Run encryption pipeline whenever inputs change or user clicks "Run Pipeline"
  const runPipeline = async () => {
    if (!senderAccount || !recipientAccount || senderAccount.id === recipientAccount.id) return;

    try {
      setIsProcessing(true);
      setTamperType(null);

      // Use current user's keys if sender is current user, otherwise use demo import
      // To allow testing full pipeline regardless of who is sender, we use demo password if available
      const senderPassword = senderAccount.id === 'usr_alice' ? 'alice_password_123' :
                             senderAccount.id === 'usr_bob' ? 'bob_password_123' :
                             senderAccount.id === 'usr_charlie' ? 'charlie_password_123' : '';

      const recipientPassword = recipientAccount.id === 'usr_alice' ? 'alice_password_123' :
                                recipientAccount.id === 'usr_bob' ? 'bob_password_123' :
                                recipientAccount.id === 'usr_charlie' ? 'charlie_password_123' : '';

      // Import sender private keys
      const { deriveVaultKey, decryptVault, importUserKeysFromJwks } = await import('../crypto/cryptoEngine');
      
      const senderVaultKey = await deriveVaultKey(senderPassword || 'demo_fallback', senderAccount.saltHex);
      const senderDecryptedJwks = await decryptVault(senderAccount.encryptedVault, senderVaultKey);
      const senderKeys = await importUserKeysFromJwks(senderAccount.publicKeys, senderDecryptedJwks);

      // Import recipient keys
      const recipientVaultKey = await deriveVaultKey(recipientPassword || 'demo_fallback', recipientAccount.saltHex);
      const recipientDecryptedJwks = await decryptVault(recipientAccount.encryptedVault, recipientVaultKey);
      const recipientKeys = await importUserKeysFromJwks(recipientAccount.publicKeys, recipientDecryptedJwks);

      // 1. ECDH Agreement
      const rawSharedBits = await inspectSharedBits(senderKeys.ecdhKeyPair.privateKey, recipientKeys.ecdhKeyPair.publicKey);
      const sharedHash = await sha256Hex(rawSharedBits);
      setSharedSecretHex(rawSharedBits);
      setSharedKeyFingerprint(sharedHash);

      // 2. Encrypt & Sign
      const generatedPacket = await encryptAndSignMessage({
        plaintext: inputPlaintext,
        senderId: senderAccount.id,
        recipientId: recipientAccount.id,
        senderEcdhPrivateKey: senderKeys.ecdhKeyPair.privateKey,
        senderEcdsaPrivateKey: senderKeys.ecdsaKeyPair.privateKey,
        senderEcdhPublicJwk: senderAccount.publicKeys.ecdh,
        senderEcdsaPublicJwk: senderAccount.publicKeys.ecdsa,
        recipientEcdhPublicKey: recipientKeys.ecdhKeyPair.publicKey,
      });

      setPacket(generatedPacket);
      setOriginalPacket({ ...generatedPacket });

      // 3. Recipient Decrypt
      const dec = await verifyAndDecryptMessage({
        packet: generatedPacket,
        recipientEcdhPrivateKey: recipientKeys.ecdhKeyPair.privateKey,
        recipientId: recipientAccount.id,
      });

      setDecryptionResult(dec);
    } catch (err) {
      console.error('Error running pipeline', err);
    } finally {
      setIsProcessing(false);
    }
  };

  useEffect(() => {
    runPipeline();
  }, [senderId, recipientId]);

  // Apply tampering to current packet and re-evaluate recipient decryption
  const applyTamper = async (type: 'flip_byte' | 'corrupt_sig' | 'alter_iv' | 'spoof_sender') => {
    if (!packet || !originalPacket || !recipientAccount) return;

    const modified = { ...packet };
    setTamperType(type);

    if (type === 'flip_byte') {
      // Flip one hex character in ciphertext
      const len = modified.ciphertextHex.length;
      const pos = Math.floor(len / 2);
      const current = modified.ciphertextHex[pos];
      const replacement = current === '0' ? 'f' : '0';
      modified.ciphertextHex =
        modified.ciphertextHex.substring(0, pos) + replacement + modified.ciphertextHex.substring(pos + 1);
    } else if (type === 'corrupt_sig') {
      // Corrupt signature
      const pos = modified.signatureHex.length - 4;
      const current = modified.signatureHex[pos];
      const replacement = current === 'a' ? '1' : 'a';
      modified.signatureHex =
        modified.signatureHex.substring(0, pos) + replacement + modified.signatureHex.substring(pos + 1);
    } else if (type === 'alter_iv') {
      // Flip IV
      const replacement = modified.ivHex[0] === 'a' ? 'b' : 'a';
      modified.ivHex = replacement + modified.ivHex.substring(1);
    } else if (type === 'spoof_sender') {
      modified.senderId = 'usr_mallory_attacker';
    }

    setPacket(modified);

    // Re-decrypt with recipient private key
    try {
      const recipientPassword = recipientAccount.id === 'usr_alice' ? 'alice_password_123' :
                                recipientAccount.id === 'usr_bob' ? 'bob_password_123' :
                                recipientAccount.id === 'usr_charlie' ? 'charlie_password_123' : '';

      const { deriveVaultKey, decryptVault, importUserKeysFromJwks } = await import('../crypto/cryptoEngine');
      const recipientVaultKey = await deriveVaultKey(recipientPassword || 'demo_fallback', recipientAccount.saltHex);
      const recipientDecryptedJwks = await decryptVault(recipientAccount.encryptedVault, recipientVaultKey);
      const recipientKeys = await importUserKeysFromJwks(recipientAccount.publicKeys, recipientDecryptedJwks);

      const dec = await verifyAndDecryptMessage({
        packet: modified,
        recipientEcdhPrivateKey: recipientKeys.ecdhKeyPair.privateKey,
        recipientId: recipientAccount.id,
      });

      setDecryptionResult(dec);
    } catch (err) {
      console.error('Decryption error after tamper', err);
    }
  };

  const handleRestore = async () => {
    if (!originalPacket || !recipientAccount) return;
    setPacket({ ...originalPacket });
    setTamperType(null);

    try {
      const recipientPassword = recipientAccount.id === 'usr_alice' ? 'alice_password_123' :
                                recipientAccount.id === 'usr_bob' ? 'bob_password_123' :
                                recipientAccount.id === 'usr_charlie' ? 'charlie_password_123' : '';

      const { deriveVaultKey, decryptVault, importUserKeysFromJwks } = await import('../crypto/cryptoEngine');
      const recipientVaultKey = await deriveVaultKey(recipientPassword || 'demo_fallback', recipientAccount.saltHex);
      const recipientDecryptedJwks = await decryptVault(recipientAccount.encryptedVault, recipientVaultKey);
      const recipientKeys = await importUserKeysFromJwks(recipientAccount.publicKeys, recipientDecryptedJwks);

      const dec = await verifyAndDecryptMessage({
        packet: originalPacket,
        recipientEcdhPrivateKey: recipientKeys.ecdhKeyPair.privateKey,
        recipientId: recipientAccount.id,
      });

      setDecryptionResult(dec);
    } catch (err) {
      console.error(err);
    }
  };

  const copyToClipboard = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 1800);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Top Banner & Context */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            <span>Cryptographic Wire Lab & Tamper Simulator</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Observe the real-time mathematics of ECDH key agreement, AES-256-GCM authenticated encryption,
            and digital signatures. Inject attacks on the wire to observe cryptographic defense mechanisms.
          </p>
        </div>

        <button
          onClick={runPipeline}
          disabled={isProcessing}
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2 self-start md:self-auto"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>{isProcessing ? 'Computing...' : 'Recalculate Pipeline'}</span>
        </button>
      </div>

      {/* Configuration Strip: Sender, Recipient & Plaintext */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              1. Sender Identity (Signing & Key Agreement)
            </label>
            <select
              value={senderId}
              onChange={(e) => setSenderId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id} disabled={a.id === recipientId}>
                  {a.displayName} (@{a.username})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              2. Recipient Identity (Key Agreement & Decryption)
            </label>
            <select
              value={recipientId}
              onChange={(e) => setRecipientId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id} disabled={a.id === senderId}>
                  {a.displayName} (@{a.username})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            3. Plaintext Message to Encrypt
          </label>
          <textarea
            value={inputPlaintext}
            onChange={(e) => setInputPlaintext(e.target.value)}
            rows={2}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500 resize-none font-mono"
            placeholder="Enter plaintext message..."
          />
        </div>
      </div>

      {/* 4 Pipeline Stages Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Stage 1: ECDH Key Agreement */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
              <Key className="w-4 h-4" />
              STAGE 1: ECDH Key Agreement (Curve P-256)
            </span>
            <span className="text-[11px] font-mono text-slate-500">secp256r1</span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Both parties compute the exact same scalar multiplication point on curve P-256 without ever transmitting private keys:
            <span className="font-mono text-slate-300 block mt-1 text-[11px]">
              S = d<sub>{senderAccount.displayName.split(' ')[0]}</sub> · Q<sub>{recipientAccount.displayName.split(' ')[0]}</sub> = d<sub>{recipientAccount.displayName.split(' ')[0]}</sub> · Q<sub>{senderAccount.displayName.split(' ')[0]}</sub>
            </span>
          </p>

          <div className="space-y-2 text-xs font-mono">
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <div className="flex items-center justify-between text-[10px] text-slate-500 font-sans mb-1">
                <span>Derived 256-bit Shared Secret (Hex):</span>
                <button
                  onClick={() => copyToClipboard(sharedSecretHex, 'secret')}
                  className="hover:text-emerald-400 transition-colors"
                >
                  {copiedSection === 'secret' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <div className="text-emerald-400 break-all tabular-nums text-[11px]">
                {sharedSecretHex || 'Computing...'}
              </div>
            </div>

            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] font-sans mb-0.5">SHA-256 Key Fingerprint:</span>
              <div className="text-indigo-400 break-all text-[11px]">{sharedKeyFingerprint}</div>
            </div>
          </div>
        </div>

        {/* Stage 2: AES-256-GCM Authenticated Encryption */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
              <Lock className="w-4 h-4" />
              STAGE 2: Authenticated Encryption (AEAD)
            </span>
            <span className="text-[11px] font-mono text-slate-500">AES-GCM (256-bit)</span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Galois/Counter Mode encrypts plaintext using a unique 96-bit nonce (IV) and appends a 128-bit authentication tag to ensure confidentiality and message integrity.
          </p>

          <div className="space-y-2 text-xs font-mono">
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] font-sans mb-0.5">Initialization Vector (IV / 96-bit Nonce):</span>
              <div className="text-indigo-400 break-all text-[11px]">{packet?.ivHex}</div>
            </div>

            <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] font-sans mb-0.5">Ciphertext + 128-bit GCM MAC Tag:</span>
              <div className="text-emerald-400 break-all max-h-20 overflow-y-auto text-[11px]">
                {packet?.ciphertextHex}
              </div>
            </div>
          </div>
        </div>

        {/* Stage 3: Digital Signature & Transmission */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
              <Shield className="w-4 h-4" />
              STAGE 3: ECDSA Digital Signature
            </span>
            <span className="text-[11px] font-mono text-slate-500">SHA-256 + P-256</span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Sender digitally signs the envelope with their private ECDSA key. The signature guarantees sender authenticity and non-repudiation.
          </p>

          <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs font-mono">
            <span className="text-slate-500 block text-[10px] font-sans mb-0.5">ECDSA Digital Signature (Hex):</span>
            <div className="text-amber-400 break-all max-h-20 overflow-y-auto text-[11px]">
              {packet?.signatureHex}
            </div>
          </div>
        </div>

        {/* Stage 4: Live Tamper Simulator */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
              <Bug className="w-4 h-4" />
              STAGE 4: Man-in-the-Middle (MITM) Wire Tamper Lab
            </span>
            {tamperType && (
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                ATTACK ACTIVE
              </span>
            )}
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Simulate an active attacker intercepting packets in transit. Click any attack to modify wire data before recipient verification:
          </p>

          <div className="grid grid-cols-2 gap-2 text-xs font-medium">
            <button
              onClick={() => applyTamper('flip_byte')}
              className={`p-2.5 rounded-lg border text-left transition-colors ${
                tamperType === 'flip_byte'
                  ? 'bg-rose-500/20 border-rose-500 text-rose-200'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="font-semibold text-rose-400 text-xs mb-0.5">1. Flip Ciphertext Bit</div>
              <div className="text-[10px] text-slate-400 font-sans">Triggers AES-GCM MAC tag mismatch</div>
            </button>

            <button
              onClick={() => applyTamper('corrupt_sig')}
              className={`p-2.5 rounded-lg border text-left transition-colors ${
                tamperType === 'corrupt_sig'
                  ? 'bg-rose-500/20 border-rose-500 text-rose-200'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="font-semibold text-amber-400 text-xs mb-0.5">2. Corrupt Signature</div>
              <div className="text-[10px] text-slate-400 font-sans">Triggers ECDSA verify failure</div>
            </button>

            <button
              onClick={() => applyTamper('alter_iv')}
              className={`p-2.5 rounded-lg border text-left transition-colors ${
                tamperType === 'alter_iv'
                  ? 'bg-rose-500/20 border-rose-500 text-rose-200'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="font-semibold text-indigo-400 text-xs mb-0.5">3. Modify Nonce (IV)</div>
              <div className="text-[10px] text-slate-400 font-sans">Triggers AEAD decryption failure</div>
            </button>

            <button
              onClick={() => applyTamper('spoof_sender')}
              className={`p-2.5 rounded-lg border text-left transition-colors ${
                tamperType === 'spoof_sender'
                  ? 'bg-rose-500/20 border-rose-500 text-rose-200'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="font-semibold text-purple-400 text-xs mb-0.5">4. Spoof Sender ID</div>
              <div className="text-[10px] text-slate-400 font-sans">Triggers identity check failure</div>
            </button>
          </div>

          {tamperType && (
            <button
              onClick={handleRestore}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors flex items-center justify-center gap-1.5"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Restore Pristine Wire Packet</span>
            </button>
          )}
        </div>
      </div>

      {/* Final Stage: Recipient Decryption & Verification Outcome */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            {decryptionResult?.status === 'verified' ? (
              <div className="w-6 h-6 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
              </div>
            ) : (
              <div className="w-6 h-6 rounded-full bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400">
                <XCircle className="w-4 h-4" />
              </div>
            )}
            <h3 className="text-sm font-semibold text-slate-100">
              Recipient Verification & Decryption Output ({recipientAccount.displayName})
            </h3>
          </div>

          <span
            className={`text-xs font-mono px-2.5 py-1 rounded-md font-semibold ${
              decryptionResult?.status === 'verified'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
            }`}
          >
            {decryptionResult?.status === 'verified' ? 'CRYPTO VALIDATED: 100%' : 'INTEGRITY BREACH REJECTED'}
          </span>
        </div>

        {/* Verification Checkpoints */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400 font-medium">1. ECDSA Signature:</span>
            {decryptionResult?.verificationDetails.signatureVerified ? (
              <span className="text-emerald-400 font-mono flex items-center gap-1">
                <Check className="w-3.5 h-3.5" /> Valid
              </span>
            ) : (
              <span className="text-rose-400 font-mono flex items-center gap-1">
                <XCircle className="w-3.5 h-3.5" /> Rejected
              </span>
            )}
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400 font-medium">2. AES-GCM Tag Check:</span>
            {decryptionResult?.verificationDetails.integrityVerified ? (
              <span className="text-emerald-400 font-mono flex items-center gap-1">
                <Check className="w-3.5 h-3.5" /> Authentic
              </span>
            ) : (
              <span className="text-rose-400 font-mono flex items-center gap-1">
                <XCircle className="w-3.5 h-3.5" /> Mismatch
              </span>
            )}
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
            <span className="text-slate-400 font-medium">3. Decryption Status:</span>
            <span
              className={`font-mono font-medium ${
                decryptionResult?.status === 'verified' ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              {decryptionResult?.status.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Plaintext Result Output Box */}
        <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
          <span className="text-[10px] text-slate-500 font-medium block mb-1">
            RECIPIENT DECRYPTED MESSAGE CONTENT:
          </span>
          <div
            className={`font-mono text-xs p-3 rounded border ${
              decryptionResult?.status === 'verified'
                ? 'bg-slate-900 border-emerald-500/40 text-emerald-200'
                : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
            }`}
          >
            {decryptionResult?.plaintext}
          </div>

          {decryptionResult?.verificationDetails.errorReason && (
            <p className="mt-2 text-xs text-rose-400/90 font-mono">
              Reason: {decryptionResult.verificationDetails.errorReason}
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
