export interface StoredPublicKeys {
  ecdh: JsonWebKey;
  ecdsa: JsonWebKey;
}

export interface EncryptedVault {
  salt: string;       // Hex salt used for PBKDF2
  iv: string;         // Hex IV for AES-GCM vault encryption
  ciphertext: string; // Hex ciphertext containing JSON string of private JWKs
  authTag?: string;
}

export interface UserAccount {
  id: string;
  username: string;
  displayName: string;
  avatar: string;
  saltHex: string;
  authVerifierHex: string; // Hash for login verification without storing password
  encryptedVault: EncryptedVault;
  publicKeys: StoredPublicKeys;
  createdAt: number;
}

export interface SessionUser {
  account: UserAccount;
  ecdhKeyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
  ecdsaKeyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
}

export interface EncryptedMessagePacket {
  id: string;
  senderId: string;
  recipientId: string;
  timestamp: number;
  ivHex: string;              // 12-byte initialization vector in hex
  ciphertextHex: string;      // AES-GCM ciphertext in hex (includes GCM auth tag in standard Web Crypto output)
  signatureHex: string;       // ECDSA P-256 signature over (senderId + recipientId + timestamp + ivHex + ciphertextHex)
  senderEcdsaPublicKeyJwk: JsonWebKey;
  senderEcdhPublicKeyJwk: JsonWebKey;
  isTampered?: boolean;
  tamperReason?: string;
}

export interface DecryptedMessage {
  id: string;
  senderId: string;
  recipientId: string;
  timestamp: number;
  plaintext: string;
  status: 'verified' | 'tampered_integrity' | 'tampered_signature' | 'failed_decrypt';
  verificationDetails: {
    sharedSecretDerived: boolean;
    integrityVerified: boolean;
    signatureVerified: boolean;
    errorReason?: string;
  };
  packet: EncryptedMessagePacket;
}

export interface KeyExchangeInfo {
  aliceId: string;
  bobId: string;
  curve: string;
  fingerprintA: string;
  fingerprintB: string;
  safetyNumber: string; // 60 digits formatted in blocks of 5
  sharedSecretHash: string; // SHA-256 preview of derived shared key
}
