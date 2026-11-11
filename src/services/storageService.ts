import { UserAccount, EncryptedMessagePacket } from '../types/crypto';
import {
  generateRandomSalt,
  deriveVaultKey,
  computeAuthVerifier,
  generateUserKeyPairs,
  encryptVault,
  encryptAndSignMessage,
  importUserKeysFromJwks,
} from '../crypto/cryptoEngine';

const USERS_STORAGE_KEY = 'ciphershield_accounts_v1';
const MESSAGES_STORAGE_KEY = 'ciphershield_packets_v1';
const VERIFIED_SAFETY_NUMBERS_KEY = 'ciphershield_verified_safety_v1';

export interface StorageData {
  accounts: UserAccount[];
  messages: EncryptedMessagePacket[];
}

export function loadStoredAccounts(): UserAccount[] {
  try {
    const raw = localStorage.getItem(USERS_STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load accounts', err);
    return [];
  }
}

export function saveStoredAccounts(accounts: UserAccount[]): void {
  try {
    localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(accounts));
  } catch (err) {
    console.error('Failed to save accounts', err);
  }
}

export function loadStoredMessages(): EncryptedMessagePacket[] {
  try {
    const raw = localStorage.getItem(MESSAGES_STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load messages', err);
    return [];
  }
}

export function saveStoredMessages(messages: EncryptedMessagePacket[]): void {
  try {
    localStorage.setItem(MESSAGES_STORAGE_KEY, JSON.stringify(messages));
  } catch (err) {
    console.error('Failed to save messages', err);
  }
}

export function loadVerifiedSafetyNumbers(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(VERIFIED_SAFETY_NUMBERS_KEY);
    if (!raw) return {};
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

export function saveVerifiedSafetyNumber(pairKey: string, isVerified: boolean): void {
  try {
    const current = loadVerifiedSafetyNumbers();
    current[pairKey] = isVerified;
    localStorage.setItem(VERIFIED_SAFETY_NUMBERS_KEY, JSON.stringify(current));
  } catch (err) {
    console.error('Failed to save verified safety number', err);
  }
}

// Seed initial demo data asynchronously if storage is empty
export async function initializeSeedDataIfEmpty(): Promise<{
  accounts: UserAccount[];
  messages: EncryptedMessagePacket[];
}> {
  const existingAccounts = loadStoredAccounts();
  const existingMessages = loadStoredMessages();

  if (existingAccounts.length >= 2 && existingMessages.length > 0) {
    return {
      accounts: existingAccounts,
      messages: existingMessages,
    };
  }

  // Generate seed demo users
  const demoUsersConfig = [
    {
      id: 'usr_alice',
      username: 'alice',
      displayName: 'Alice Smith',
      avatar: 'AS',
      password: 'alice_password_123',
    },
    {
      id: 'usr_bob',
      username: 'bob',
      displayName: 'Bob Vance',
      avatar: 'BV',
      password: 'bob_password_123',
    },
    {
      id: 'usr_charlie',
      username: 'charlie',
      displayName: 'Charlie Davis',
      avatar: 'CD',
      password: 'charlie_password_123',
    },
  ];

  const createdAccounts: UserAccount[] = [];
  const createdKeys: Record<string, any> = {};

  for (const cfg of demoUsersConfig) {
    const saltHex = generateRandomSalt(16);
    const vaultKey = await deriveVaultKey(cfg.password, saltHex);
    const authVerifierHex = await computeAuthVerifier(vaultKey, saltHex);
    const generated = await generateUserKeyPairs();

    const encryptedVault = await encryptVault(generated.privateJwks, vaultKey, saltHex);

    const account: UserAccount = {
      id: cfg.id,
      username: cfg.username,
      displayName: cfg.displayName,
      avatar: cfg.avatar,
      saltHex,
      authVerifierHex,
      encryptedVault,
      publicKeys: generated.publicJwks,
      createdAt: Date.now() - 3600000,
    };

    createdAccounts.push(account);
    createdKeys[cfg.id] = {
      account,
      generated,
    };
  }

  // Pre-seed real encrypted & digitally signed messages between Alice and Bob
  const aliceData = createdKeys['usr_alice'];
  const bobData = createdKeys['usr_bob'];

  const aliceKeys = await importUserKeysFromJwks(aliceData.account.publicKeys, aliceData.generated.privateJwks);
  const bobKeys = await importUserKeysFromJwks(bobData.account.publicKeys, bobData.generated.privateJwks);

  const seedPackets: EncryptedMessagePacket[] = [];

  // Message 1: Alice -> Bob
  const msg1 = await encryptAndSignMessage({
    plaintext: "Hey Bob! I've established our ECDH P-256 session. Can you verify our safety number?",
    senderId: 'usr_alice',
    recipientId: 'usr_bob',
    senderEcdhPrivateKey: aliceKeys.ecdhKeyPair.privateKey,
    senderEcdsaPrivateKey: aliceKeys.ecdsaKeyPair.privateKey,
    senderEcdhPublicJwk: aliceData.account.publicKeys.ecdh,
    senderEcdsaPublicJwk: aliceData.account.publicKeys.ecdsa,
    recipientEcdhPublicKey: bobKeys.ecdhKeyPair.publicKey,
  });
  msg1.timestamp = Date.now() - 120000;
  seedPackets.push(msg1);

  // Message 2: Bob -> Alice
  const msg2 = await encryptAndSignMessage({
    plaintext: "Received loud and clear! Safety number matches. All packets are encrypted via AES-256-GCM with ECDSA signatures.",
    senderId: 'usr_bob',
    recipientId: 'usr_alice',
    senderEcdhPrivateKey: bobKeys.ecdhKeyPair.privateKey,
    senderEcdsaPrivateKey: bobKeys.ecdsaKeyPair.privateKey,
    senderEcdhPublicJwk: bobData.account.publicKeys.ecdh,
    senderEcdsaPublicJwk: bobData.account.publicKeys.ecdsa,
    recipientEcdhPublicKey: aliceKeys.ecdhKeyPair.publicKey,
  });
  msg2.timestamp = Date.now() - 80000;
  seedPackets.push(msg2);

  // Message 3: Alice -> Bob
  const msg3 = await encryptAndSignMessage({
    plaintext: "Awesome. Try inspecting the raw ciphertext packet or testing the tamper simulator in the Wire Lab tab to see GCM integrity checks in action!",
    senderId: 'usr_alice',
    recipientId: 'usr_bob',
    senderEcdhPrivateKey: aliceKeys.ecdhKeyPair.privateKey,
    senderEcdsaPrivateKey: aliceKeys.ecdsaKeyPair.privateKey,
    senderEcdhPublicJwk: aliceData.account.publicKeys.ecdh,
    senderEcdsaPublicJwk: aliceData.account.publicKeys.ecdsa,
    recipientEcdhPublicKey: bobKeys.ecdhKeyPair.publicKey,
  });
  msg3.timestamp = Date.now() - 30000;
  seedPackets.push(msg3);

  saveStoredAccounts(createdAccounts);
  saveStoredMessages(seedPackets);

  return {
    accounts: createdAccounts,
    messages: seedPackets,
  };
}
