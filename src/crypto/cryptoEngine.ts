import { EncryptedMessagePacket, DecryptedMessage, KeyExchangeInfo, StoredPublicKeys } from '../types/crypto';

// --- Utility Helpers for Hex & Buffer Conversion ---

export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToUint8Array(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(Math.floor(cleanHex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function uint8ArrayToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export async function sha256Hex(data: string | Uint8Array | BufferSource): Promise<string> {
  const bytes = typeof data === 'string' ? stringToUint8Array(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
  return bufferToHex(hash);
}

// Generate cryptographically secure random salt
export function generateRandomSalt(length = 16): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return bufferToHex(array);
}

// --- PBKDF2 Password Key Derivation & Vault Encryption ---

// Derives an AES-GCM 256-bit vault key from password and salt
export async function deriveVaultKey(password: string, saltHex: string): Promise<CryptoKey> {
  const salt = hexToUint8Array(saltHex);
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    stringToUint8Array(password) as unknown as BufferSource,
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    true, // extractable for verifier computation
    ['encrypt', 'decrypt']
  );
}

// Compute an authentication verifier from derived key and salt (Zero-Knowledge authentication)
export async function computeAuthVerifier(vaultKey: CryptoKey, saltHex: string): Promise<string> {
  const rawKey = await crypto.subtle.exportKey('raw', vaultKey);
  const combined = new Uint8Array(rawKey.byteLength + saltHex.length);
  combined.set(new Uint8Array(rawKey), 0);
  combined.set(stringToUint8Array(saltHex), rawKey.byteLength);
  return sha256Hex(combined);
}

// Encrypt user's private key store into an encrypted vault
export async function encryptVault(
  privateKeys: { ecdh: JsonWebKey; ecdsa: JsonWebKey },
  vaultKey: CryptoKey,
  saltHex: string
): Promise<{ salt: string; iv: string; ciphertext: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = stringToUint8Array(JSON.stringify(privateKeys));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    vaultKey,
    plaintextBytes as unknown as BufferSource
  );

  return {
    salt: saltHex,
    iv: bufferToHex(iv),
    ciphertext: bufferToHex(ciphertextBuffer),
  };
}

// Decrypt user's private key vault using derived vault key
export async function decryptVault(
  encryptedVault: { iv: string; ciphertext: string },
  vaultKey: CryptoKey
): Promise<{ ecdh: JsonWebKey; ecdsa: JsonWebKey }> {
  const iv = hexToUint8Array(encryptedVault.iv);
  const ciphertext = hexToUint8Array(encryptedVault.ciphertext);

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    vaultKey,
    ciphertext as unknown as BufferSource
  );

  const jsonString = uint8ArrayToString(new Uint8Array(decryptedBuffer));
  return JSON.parse(jsonString);
}

// --- Key Generation & Import/Export ---

// Generate both ECDH (for key exchange) and ECDSA (for signing) keypairs
export async function generateUserKeyPairs(): Promise<{
  ecdhKeyPair: CryptoKeyPair;
  ecdsaKeyPair: CryptoKeyPair;
  publicJwks: StoredPublicKeys;
  privateJwks: { ecdh: JsonWebKey; ecdsa: JsonWebKey };
}> {
  // 1. ECDH KeyPair (Curve P-256)
  const ecdhKeyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  // 2. ECDSA KeyPair (Curve P-256, SHA-256)
  const ecdsaKeyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  // Export to JWK
  const [ecdhPublicJwk, ecdhPrivateJwk, ecdsaPublicJwk, ecdsaPrivateJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey),
    crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey),
    crypto.subtle.exportKey('jwk', ecdsaKeyPair.publicKey),
    crypto.subtle.exportKey('jwk', ecdsaKeyPair.privateKey),
  ]);

  return {
    ecdhKeyPair,
    ecdsaKeyPair,
    publicJwks: {
      ecdh: ecdhPublicJwk,
      ecdsa: ecdsaPublicJwk,
    },
    privateJwks: {
      ecdh: ecdhPrivateJwk,
      ecdsa: ecdsaPrivateJwk,
    },
  };
}

// Import Public and Private JWKs back to CryptoKeys
export async function importUserKeysFromJwks(
  publicJwks: StoredPublicKeys,
  privateJwks: { ecdh: JsonWebKey; ecdsa: JsonWebKey }
): Promise<{
  ecdhKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  ecdsaKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
}> {
  const ecdhPublicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwks.ecdh,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  const ecdhPrivateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwks.ecdh,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const ecdsaPublicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwks.ecdsa,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  const ecdsaPrivateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwks.ecdsa,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );

  return {
    ecdhKeyPair: { publicKey: ecdhPublicKey, privateKey: ecdhPrivateKey },
    ecdsaKeyPair: { publicKey: ecdsaPublicKey, privateKey: ecdsaPrivateKey },
  };
}

export async function importPeerPublicKeys(publicJwks: StoredPublicKeys): Promise<{
  ecdhPublicKey: CryptoKey;
  ecdsaPublicKey: CryptoKey;
}> {
  const ecdhPublicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwks.ecdh,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  const ecdsaPublicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwks.ecdsa,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  return { ecdhPublicKey, ecdsaPublicKey };
}

// --- ECDH Key Agreement (Diffie-Hellman) ---

// Derives a 256-bit AES-GCM shared key from private key and peer's public key
export async function deriveSharedSecretKey(
  ownPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: peerPublicKey,
    },
    ownPrivateKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false, // Non-extractable for memory safety
    ['encrypt', 'decrypt']
  );
}

// Compute raw shared bits preview (for cryptographic inspection purposes)
export async function inspectSharedBits(
  ownPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<string> {
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: peerPublicKey,
    },
    ownPrivateKey,
    256
  );
  return bufferToHex(bits);
}

// --- Safety Numbers & Key Fingerprints ---

// Compute public key fingerprint (SHA-256 of coordinates x, y)
export async function computeKeyFingerprint(jwk: JsonWebKey): Promise<string> {
  const canonical = `${jwk.crv || 'P-256'}:${jwk.x}:${jwk.y}`;
  const hash = await sha256Hex(canonical);
  // Format as readable hex pairs separated by colons
  return hash.substring(0, 32).match(/.{1,2}/g)?.join(':') || hash.substring(0, 32);
}

// Generate Signal-style 60-digit safety numbers from two public keys
export async function generateSafetyNumber(
  userAJwk: JsonWebKey,
  userBJwk: JsonWebKey,
  userAId: string,
  userBId: string
): Promise<string> {
  // Sort deterministically by ID so both users calculate the exact same safety number
  const [firstKey, secondKey] = userAId < userBId 
    ? [userAJwk, userBJwk] 
    : [userBJwk, userAJwk];

  const payload = `${firstKey.x}:${firstKey.y}:${secondKey.x}:${secondKey.y}`;
  const hashBuffer = await crypto.subtle.digest('SHA-256', stringToUint8Array(payload) as unknown as BufferSource);
  const bytes = new Uint8Array(hashBuffer);

  // Generate 60 numeric digits by hashing iterations (12 groups of 5 digits)
  let numericString = '';
  for (let i = 0; i < 12; i++) {
    // Take 4 bytes to form a 32-bit unsigned integer, then modulo 100000 to get a 5-digit block
    const offset = (i * 2) % (bytes.length - 4);
    const val = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const fiveDigits = Math.abs(val % 100000).toString().padStart(5, '0');
    numericString += (i > 0 ? ' ' : '') + fiveDigits;
  }

  return numericString;
}

// --- End-to-End Encryption (AES-256-GCM) & Digital Signatures (ECDSA) ---

export interface EncryptMessageParams {
  plaintext: string;
  senderId: string;
  recipientId: string;
  senderEcdhPrivateKey: CryptoKey;
  senderEcdsaPrivateKey: CryptoKey;
  senderEcdhPublicJwk: JsonWebKey;
  senderEcdsaPublicJwk: JsonWebKey;
  recipientEcdhPublicKey: CryptoKey;
}

// Creates an authenticated, encrypted, and digitally signed message packet
export async function encryptAndSignMessage(
  params: EncryptMessageParams
): Promise<EncryptedMessagePacket> {
  const {
    plaintext,
    senderId,
    recipientId,
    senderEcdhPrivateKey,
    senderEcdsaPrivateKey,
    senderEcdhPublicJwk,
    senderEcdsaPublicJwk,
    recipientEcdhPublicKey,
  } = params;

  // 1. Derive shared secret key via ECDH (Curve P-256)
  const sharedKey = await deriveSharedSecretKey(senderEcdhPrivateKey, recipientEcdhPublicKey);

  // 2. Generate cryptographically strong random 96-bit (12-byte) initialization vector (IV)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ivHex = bufferToHex(iv);

  // 3. Encrypt plaintext with AES-256-GCM (produces ciphertext + 128-bit authentication tag)
  const plaintextBytes = stringToUint8Array(plaintext);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    sharedKey,
    plaintextBytes as unknown as BufferSource
  );
  const ciphertextHex = bufferToHex(ciphertextBuffer);

  const timestamp = Date.now();
  const id = `msg_${timestamp}_${Math.random().toString(36).substring(2, 8)}`;

  // 4. Create the digital signature envelope over packet data to guarantee authenticity & non-repudiation
  const signaturePayload = `${id}:${senderId}:${recipientId}:${timestamp}:${ivHex}:${ciphertextHex}`;
  const signatureBuffer = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    senderEcdsaPrivateKey,
    stringToUint8Array(signaturePayload) as unknown as BufferSource
  );
  const signatureHex = bufferToHex(signatureBuffer);

  return {
    id,
    senderId,
    recipientId,
    timestamp,
    ivHex,
    ciphertextHex,
    signatureHex,
    senderEcdsaPublicKeyJwk: senderEcdsaPublicJwk,
    senderEcdhPublicKeyJwk: senderEcdhPublicJwk,
  };
}

// --- Decryption & Message Integrity Verification ---

export interface DecryptMessageParams {
  packet: EncryptedMessagePacket;
  recipientEcdhPrivateKey: CryptoKey;
  recipientId: string;
}

// Verifies digital signature, verifies AES-GCM authentication tag, and decrypts plaintext
export async function verifyAndDecryptMessage(
  params: DecryptMessageParams
): Promise<DecryptedMessage> {
  const { packet, recipientEcdhPrivateKey } = params;

  // Step 1: Verify ECDSA Digital Signature (Authenticity & Non-Repudiation)
  let signatureVerified = false;
  try {
    const senderEcdsaPublicKey = await crypto.subtle.importKey(
      'jwk',
      packet.senderEcdsaPublicKeyJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );

    const signaturePayload = `${packet.id}:${packet.senderId}:${packet.recipientId}:${packet.timestamp}:${packet.ivHex}:${packet.ciphertextHex}`;
    const signatureBytes = hexToUint8Array(packet.signatureHex);

    signatureVerified = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      senderEcdsaPublicKey,
      signatureBytes as unknown as BufferSource,
      stringToUint8Array(signaturePayload) as unknown as BufferSource
    );
  } catch (err) {
    signatureVerified = false;
  }

  if (!signatureVerified) {
    return {
      id: packet.id,
      senderId: packet.senderId,
      recipientId: packet.recipientId,
      timestamp: packet.timestamp,
      plaintext: '[SIGNATURE VERIFICATION FAILED - FORGERY OR CORRUPTION DETECTED]',
      status: 'tampered_signature',
      verificationDetails: {
        sharedSecretDerived: false,
        integrityVerified: false,
        signatureVerified: false,
        errorReason: 'ECDSA digital signature did not match sender public key and payload hash.',
      },
      packet,
    };
  }

  // Step 2: Derive Shared Secret Key using recipient's private key + sender's public key
  let sharedKey: CryptoKey;
  try {
    const senderEcdhPublicKey = await crypto.subtle.importKey(
      'jwk',
      packet.senderEcdhPublicKeyJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    sharedKey = await deriveSharedSecretKey(recipientEcdhPrivateKey, senderEcdhPublicKey);
  } catch (err) {
    return {
      id: packet.id,
      senderId: packet.senderId,
      recipientId: packet.recipientId,
      timestamp: packet.timestamp,
      plaintext: '[KEY AGREEMENT FAILED - INVALID PEER ECDH PUBLIC KEY]',
      status: 'failed_decrypt',
      verificationDetails: {
        sharedSecretDerived: false,
        integrityVerified: false,
        signatureVerified: true,
        errorReason: 'Could not perform ECDH curve scalar multiplication.',
      },
      packet,
    };
  }

  // Step 3: Decrypt with AES-256-GCM and verify MAC Authentication Tag
  try {
    const iv = hexToUint8Array(packet.ivHex);
    const ciphertext = hexToUint8Array(packet.ciphertextHex);

    // SubtleCrypto decrypt validates the 128-bit authentication tag included in ciphertext
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      sharedKey,
      ciphertext as unknown as BufferSource
    );

    const plaintext = uint8ArrayToString(new Uint8Array(decryptedBuffer));

    return {
      id: packet.id,
      senderId: packet.senderId,
      recipientId: packet.recipientId,
      timestamp: packet.timestamp,
      plaintext,
      status: 'verified',
      verificationDetails: {
        sharedSecretDerived: true,
        integrityVerified: true,
        signatureVerified: true,
      },
      packet,
    };
  } catch (err) {
    // Web Crypto throws OperationError if authentication tag does not match
    return {
      id: packet.id,
      senderId: packet.senderId,
      recipientId: packet.recipientId,
      timestamp: packet.timestamp,
      plaintext: '[INTEGRITY CHECK FAILED - CIPHERTEXT OR TAG ALTERED IN TRANSIT]',
      status: 'tampered_integrity',
      verificationDetails: {
        sharedSecretDerived: true,
        integrityVerified: false,
        signatureVerified: true,
        errorReason: 'AES-GCM authentication tag mismatch: ciphertext bits were modified on the wire.',
      },
      packet,
    };
  }
}
