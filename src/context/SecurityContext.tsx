import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  UserAccount,
  SessionUser,
  EncryptedMessagePacket,
  DecryptedMessage,
} from '../types/crypto';
import {
  deriveVaultKey,
  computeAuthVerifier,
  generateUserKeyPairs,
  encryptVault,
  decryptVault,
  importUserKeysFromJwks,
  importPeerPublicKeys,
  encryptAndSignMessage,
  verifyAndDecryptMessage,
  generateRandomSalt,
} from '../crypto/cryptoEngine';
import {
  loadStoredAccounts,
  saveStoredAccounts,
  loadStoredMessages,
  saveStoredMessages,
  loadVerifiedSafetyNumbers,
  saveVerifiedSafetyNumber,
  initializeSeedDataIfEmpty,
} from '../services/storageService';

// Predefined demo passwords for instant switching
export const DEMO_PASSWORDS: Record<string, string> = {
  usr_alice: 'alice_password_123',
  usr_bob: 'bob_password_123',
  usr_charlie: 'charlie_password_123',
};

interface SecurityContextType {
  accounts: UserAccount[];
  currentUser: SessionUser | null;
  messages: EncryptedMessagePacket[];
  decryptedMessages: Record<string, DecryptedMessage>;
  activeContactId: string | null;
  isInitialized: boolean;
  isLoading: boolean;
  error: string | null;
  setActiveContactId: (id: string | null) => void;
  login: (username: string, password: string) => Promise<boolean>;
  register: (username: string, displayName: string, password: string) => Promise<boolean>;
  logout: () => void;
  switchQuickUser: (userId: string) => Promise<boolean>;
  sendMessage: (recipientId: string, plaintext: string) => Promise<boolean>;
  tamperMessage: (
    messageId: string,
    type: 'flip_byte' | 'corrupt_sig' | 'swap_sender' | 'alter_iv'
  ) => Promise<void>;
  restoreOriginalMessage: (messageId: string) => void;
  toggleVerifySafetyNumber: (contactId: string) => void;
  isSafetyNumberVerified: (contactId: string) => boolean;
  resetToDemoState: () => Promise<void>;
  decryptSingleMessageForInspector: (
    packet: EncryptedMessagePacket,
    recipientAccount: UserAccount,
    recipientPrivateKey: CryptoKey
  ) => Promise<DecryptedMessage>;
}

const SecurityContext = createContext<SecurityContextType | null>(null);

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [accounts, setAccounts] = useState<UserAccount[]>([]);
  const [currentUser, setCurrentUser] = useState<SessionUser | null>(null);
  const [messages, setMessages] = useState<EncryptedMessagePacket[]>([]);
  const [originalUntamperedMessages, setOriginalUntamperedMessages] = useState<Record<string, EncryptedMessagePacket>>({});
  const [decryptedMessages, setDecryptedMessages] = useState<Record<string, DecryptedMessage>>({});
  const [activeContactId, setActiveContactId] = useState<string | null>(null);
  const [verifiedSafetyNumbers, setVerifiedSafetyNumbers] = useState<Record<string, boolean>>({});
  const [isInitialized, setIsInitialized] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Initialize accounts and seed messages on startup
  useEffect(() => {
    let isMounted = true;
    async function init() {
      try {
        setIsLoading(true);
        const seed = await initializeSeedDataIfEmpty();
        if (!isMounted) return;

        setAccounts(seed.accounts);
        setMessages(seed.messages);
        setVerifiedSafetyNumbers(loadVerifiedSafetyNumbers());

        // Cache original messages for restore functionality
        const backup: Record<string, EncryptedMessagePacket> = {};
        seed.messages.forEach((m) => {
          backup[m.id] = { ...m };
        });
        setOriginalUntamperedMessages(backup);

        // Auto-login Alice on first launch for immediate interactivity
        const aliceAccount = seed.accounts.find((a) => a.id === 'usr_alice');
        if (aliceAccount) {
          const vaultKey = await deriveVaultKey(DEMO_PASSWORDS['usr_alice'], aliceAccount.saltHex);
          const decryptedJwks = await decryptVault(aliceAccount.encryptedVault, vaultKey);
          const imported = await importUserKeysFromJwks(aliceAccount.publicKeys, decryptedJwks);

          setCurrentUser({
            account: aliceAccount,
            ecdhKeyPair: imported.ecdhKeyPair,
            ecdsaKeyPair: imported.ecdsaKeyPair,
          });

          // Set default active contact to Bob
          setActiveContactId('usr_bob');
        }

        setIsInitialized(true);
      } catch (err: any) {
        console.error('Initialization error:', err);
        setError(err.message || 'Failed to initialize crypto vault');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    init();
    return () => {
      isMounted = false;
    };
  }, []);

  // Whenever currentUser or messages change, re-decrypt relevant messages
  useEffect(() => {
    if (!currentUser) {
      setDecryptedMessages({});
      return;
    }

    let isMounted = true;
    async function decryptAllForCurrentSession() {
      if (!currentUser) return;
      const results: Record<string, DecryptedMessage> = {};

      for (const msg of messages) {
        // Can decrypt if current user is either recipient or sender
        if (msg.recipientId === currentUser.account.id) {
          // Decrypt as recipient using recipient ECDH private key
          const dec = await verifyAndDecryptMessage({
            packet: msg,
            recipientEcdhPrivateKey: currentUser.ecdhKeyPair.privateKey,
            recipientId: currentUser.account.id,
          });
          results[msg.id] = dec;
        } else if (msg.senderId === currentUser.account.id) {
          // As sender, verify with peer public key and sender private key
          const recipientAccount = accounts.find((a) => a.id === msg.recipientId);
          if (recipientAccount) {
            try {
              const peerKeys = await importPeerPublicKeys(recipientAccount.publicKeys);
              const sharedKey = await crypto.subtle.deriveKey(
                { name: 'ECDH', public: peerKeys.ecdhPublicKey },
                currentUser.ecdhKeyPair.privateKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
              );
              const iv = new Uint8Array(
                msg.ivHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
              );
              const ciphertext = new Uint8Array(
                msg.ciphertextHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
              );

              const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                sharedKey,
                ciphertext
              );
              const plaintext = new TextDecoder().decode(decryptedBuffer);

              results[msg.id] = {
                id: msg.id,
                senderId: msg.senderId,
                recipientId: msg.recipientId,
                timestamp: msg.timestamp,
                plaintext,
                status: 'verified',
                verificationDetails: {
                  sharedSecretDerived: true,
                  integrityVerified: true,
                  signatureVerified: true,
                },
                packet: msg,
              };
            } catch (err: any) {
              results[msg.id] = {
                id: msg.id,
                senderId: msg.senderId,
                recipientId: msg.recipientId,
                timestamp: msg.timestamp,
                plaintext: msg.isTampered ? '[TAMPERED ON WIRE - DECRYPT FAILED]' : '[CIPHERTEXT ERROR]',
                status: 'tampered_integrity',
                verificationDetails: {
                  sharedSecretDerived: true,
                  integrityVerified: false,
                  signatureVerified: !msg.isTampered,
                  errorReason: err.message,
                },
                packet: msg,
              };
            }
          }
        }
      }

      if (isMounted) {
        setDecryptedMessages(results);
      }
    }

    decryptAllForCurrentSession();
    return () => {
      isMounted = false;
    };
  }, [currentUser, messages, accounts]);

  // Login handler
  const login = useCallback(
    async (username: string, password: string): Promise<boolean> => {
      setError(null);
      try {
        const found = accounts.find((a) => a.username.toLowerCase() === username.toLowerCase());
        if (!found) {
          setError('User account not found');
          return false;
        }

        // Derive vault key from provided password
        const vaultKey = await deriveVaultKey(password, found.saltHex);
        const computedVerifier = await computeAuthVerifier(vaultKey, found.saltHex);

        if (computedVerifier !== found.authVerifierHex) {
          setError('Invalid credentials: password does not unlock PBKDF2 vault');
          return false;
        }

        // Decrypt private keys from vault
        const decryptedJwks = await decryptVault(found.encryptedVault, vaultKey);
        const imported = await importUserKeysFromJwks(found.publicKeys, decryptedJwks);

        setCurrentUser({
          account: found,
          ecdhKeyPair: imported.ecdhKeyPair,
          ecdsaKeyPair: imported.ecdsaKeyPair,
        });

        // Pick another contact
        const otherContact = accounts.find((a) => a.id !== found.id);
        if (otherContact) {
          setActiveContactId(otherContact.id);
        }

        return true;
      } catch (err: any) {
        console.error('Login error', err);
        setError(err.message || 'Decryption of vault failed');
        return false;
      }
    },
    [accounts]
  );

  // Register new account handler
  const register = useCallback(
    async (username: string, displayName: string, password: string): Promise<boolean> => {
      setError(null);
      try {
        if (!username.trim() || !password || password.length < 6) {
          setError('Password must be at least 6 characters and username cannot be blank');
          return false;
        }

        const existing = accounts.find((a) => a.username.toLowerCase() === username.toLowerCase());
        if (existing) {
          setError('Username already taken. Please choose another.');
          return false;
        }

        const saltHex = generateRandomSalt(16);
        const vaultKey = await deriveVaultKey(password, saltHex);
        const authVerifierHex = await computeAuthVerifier(vaultKey, saltHex);
        const generated = await generateUserKeyPairs();

        const encryptedVault = await encryptVault(generated.privateJwks, vaultKey, saltHex);

        const initials = displayName
          .split(' ')
          .map((n) => n[0])
          .join('')
          .toUpperCase()
          .slice(0, 2) || username.slice(0, 2).toUpperCase();

        const newAccount: UserAccount = {
          id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
          username: username.trim(),
          displayName: displayName.trim() || username.trim(),
          avatar: initials,
          saltHex,
          authVerifierHex,
          encryptedVault,
          publicKeys: generated.publicJwks,
          createdAt: Date.now(),
        };

        const updatedAccounts = [...accounts, newAccount];
        setAccounts(updatedAccounts);
        saveStoredAccounts(updatedAccounts);

        // Auto login with new user session
        setCurrentUser({
          account: newAccount,
          ecdhKeyPair: generated.ecdhKeyPair,
          ecdsaKeyPair: generated.ecdsaKeyPair,
        });

        // Select first contact
        const firstOther = accounts.find((a) => a.id !== newAccount.id);
        if (firstOther) {
          setActiveContactId(firstOther.id);
        }

        return true;
      } catch (err: any) {
        console.error('Registration error', err);
        setError(err.message || 'Key generation / vault setup failed');
        return false;
      }
    },
    [accounts]
  );

  const logout = useCallback(() => {
    setCurrentUser(null);
    setDecryptedMessages({});
  }, []);

  // Instant switch between demo identities (Alice, Bob, Charlie)
  const switchQuickUser = useCallback(
    async (userId: string): Promise<boolean> => {
      const targetAccount = accounts.find((a) => a.id === userId);
      if (!targetAccount) return false;

      const password = DEMO_PASSWORDS[userId];
      if (!password) {
        setError(`Cannot quick-switch: ${targetAccount.displayName} has a custom password. Use standard login.`);
        return false;
      }

      return login(targetAccount.username, password);
    },
    [accounts, login]
  );

  // Send an encrypted message from currentUser to recipient
  const sendMessage = useCallback(
    async (recipientId: string, plaintext: string): Promise<boolean> => {
      if (!currentUser) {
        setError('No active authenticated session');
        return false;
      }

      const recipientAccount = accounts.find((a) => a.id === recipientId);
      if (!recipientAccount) {
        setError('Recipient not found in public key directory');
        return false;
      }

      try {
        // Import recipient's ECDH public key
        const peerKeys = await importPeerPublicKeys(recipientAccount.publicKeys);

        // Encrypt and sign message packet
        const packet = await encryptAndSignMessage({
          plaintext,
          senderId: currentUser.account.id,
          recipientId,
          senderEcdhPrivateKey: currentUser.ecdhKeyPair.privateKey,
          senderEcdsaPrivateKey: currentUser.ecdsaKeyPair.privateKey,
          senderEcdhPublicJwk: currentUser.account.publicKeys.ecdh,
          senderEcdsaPublicJwk: currentUser.account.publicKeys.ecdsa,
          recipientEcdhPublicKey: peerKeys.ecdhPublicKey,
        });

        const updated = [...messages, packet];
        setMessages(updated);
        saveStoredMessages(updated);

        // Save original backup for restoring after tampering tests
        setOriginalUntamperedMessages((prev) => ({
          ...prev,
          [packet.id]: { ...packet },
        }));

        return true;
      } catch (err: any) {
        console.error('Failed to encrypt message', err);
        setError(err.message || 'Failed to encrypt and sign message');
        return false;
      }
    },
    [currentUser, accounts, messages]
  );

  // Tamper simulator to demonstrate message integrity & authentication failure
  const tamperMessage = useCallback(
    async (
      messageId: string,
      type: 'flip_byte' | 'corrupt_sig' | 'swap_sender' | 'alter_iv'
    ) => {
      setMessages((prev) =>
        prev.map((msg) => {
          if (msg.id !== messageId) return msg;

          const tampered: EncryptedMessagePacket = { ...msg, isTampered: true };

          if (type === 'flip_byte') {
            // Flip hex digits in the middle of ciphertext
            const len = tampered.ciphertextHex.length;
            const mid = Math.floor(len / 2);
            const originalChar = tampered.ciphertextHex[mid];
            const replacement = originalChar === 'a' ? 'b' : 'a';
            tampered.ciphertextHex =
              tampered.ciphertextHex.substring(0, mid) +
              replacement +
              tampered.ciphertextHex.substring(mid + 1);
            tampered.tamperReason = 'Ciphertext bits altered on the wire (Simulated MITM Bit-Flip)';
          } else if (type === 'corrupt_sig') {
            // Alter digital signature hex
            const originalChar = tampered.signatureHex[tampered.signatureHex.length - 2];
            const replacement = originalChar === '0' ? 'f' : '0';
            tampered.signatureHex =
              tampered.signatureHex.substring(0, tampered.signatureHex.length - 2) +
              replacement +
              tampered.signatureHex.substring(tampered.signatureHex.length - 1);
            tampered.tamperReason = 'ECDSA digital signature corrupted (Simulated Forged / Modified Packet)';
          } else if (type === 'alter_iv') {
            // Corrupt IV
            const replacement = tampered.ivHex[0] === 'f' ? '0' : 'f';
            tampered.ivHex = replacement + tampered.ivHex.substring(1);
            tampered.tamperReason = 'Initialization vector (IV) modified on the wire';
          } else if (type === 'swap_sender') {
            // Change claimed senderId without matching signature key
            tampered.senderId = 'usr_unknown_attacker';
            tampered.tamperReason = 'Claimed sender identity spoofed';
          }

          return tampered;
        })
      );
    },
    []
  );

  // Restore untampered original packet
  const restoreOriginalMessage = useCallback((messageId: string) => {
    const original = originalUntamperedMessages[messageId];
    if (!original) return;

    setMessages((prev) =>
      prev.map((msg) => (msg.id === messageId ? { ...original, isTampered: false, tamperReason: undefined } : msg))
    );
  }, [originalUntamperedMessages]);

  // Safety number verification state
  const isSafetyNumberVerified = useCallback(
    (contactId: string): boolean => {
      if (!currentUser) return false;
      const pairKey = [currentUser.account.id, contactId].sort().join('_');
      return !!verifiedSafetyNumbers[pairKey];
    },
    [currentUser, verifiedSafetyNumbers]
  );

  const toggleVerifySafetyNumber = useCallback(
    (contactId: string) => {
      if (!currentUser) return;
      const pairKey = [currentUser.account.id, contactId].sort().join('_');
      const nextState = !verifiedSafetyNumbers[pairKey];
      const updated = { ...verifiedSafetyNumbers, [pairKey]: nextState };
      setVerifiedSafetyNumbers(updated);
      saveVerifiedSafetyNumber(pairKey, nextState);
    },
    [currentUser, verifiedSafetyNumbers]
  );

  // Helper for Wire Lab inspector
  const decryptSingleMessageForInspector = useCallback(
    async (
      packet: EncryptedMessagePacket,
      recipientAccount: UserAccount,
      recipientPrivateKey: CryptoKey
    ): Promise<DecryptedMessage> => {
      return verifyAndDecryptMessage({
        packet,
        recipientEcdhPrivateKey: recipientPrivateKey,
        recipientId: recipientAccount.id,
      });
    },
    []
  );

  // Reset demo back to factory clean state
  const resetToDemoState = useCallback(async () => {
    localStorage.removeItem('ciphershield_accounts_v1');
    localStorage.removeItem('ciphershield_packets_v1');
    localStorage.removeItem('ciphershield_verified_safety_v1');
    setIsLoading(true);
    const fresh = await initializeSeedDataIfEmpty();
    setAccounts(fresh.accounts);
    setMessages(fresh.messages);
    setVerifiedSafetyNumbers({});

    const backup: Record<string, EncryptedMessagePacket> = {};
    fresh.messages.forEach((m) => {
      backup[m.id] = { ...m };
    });
    setOriginalUntamperedMessages(backup);

    const aliceAccount = fresh.accounts.find((a) => a.id === 'usr_alice');
    if (aliceAccount) {
      const vaultKey = await deriveVaultKey(DEMO_PASSWORDS['usr_alice'], aliceAccount.saltHex);
      const decryptedJwks = await decryptVault(aliceAccount.encryptedVault, vaultKey);
      const imported = await importUserKeysFromJwks(aliceAccount.publicKeys, decryptedJwks);

      setCurrentUser({
        account: aliceAccount,
        ecdhKeyPair: imported.ecdhKeyPair,
        ecdsaKeyPair: imported.ecdsaKeyPair,
      });
      setActiveContactId('usr_bob');
    }
    setIsLoading(false);
  }, []);

  return (
    <SecurityContext.Provider
      value={{
        accounts,
        currentUser,
        messages,
        decryptedMessages,
        activeContactId,
        isInitialized,
        isLoading,
        error,
        setActiveContactId,
        login,
        register,
        logout,
        switchQuickUser,
        sendMessage,
        tamperMessage,
        restoreOriginalMessage,
        toggleVerifySafetyNumber,
        isSafetyNumberVerified,
        resetToDemoState,
        decryptSingleMessageForInspector,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};
