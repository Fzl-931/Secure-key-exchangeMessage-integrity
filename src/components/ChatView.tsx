import React, { useState, useRef, useEffect } from 'react';
import {
  Send,
  Lock,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  RotateCcw,
  Bug,
  Search,
  Key,
  Shield,
  FileCode,
  CheckCheck,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { EncryptedMessagePacket, DecryptedMessage, UserAccount } from '../types/crypto';
import { SafetyNumberModal } from './SafetyNumberModal';

export const ChatView: React.FC = () => {
  const {
    accounts,
    currentUser,
    messages,
    decryptedMessages,
    activeContactId,
    setActiveContactId,
    sendMessage,
    tamperMessage,
    restoreOriginalMessage,
    isSafetyNumberVerified,
  } = useSecurity();

  const [inputText, setInputText] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedPackets, setExpandedPackets] = useState<Record<string, boolean>>({});
  const [showSafetyModal, setShowSafetyModal] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Available contacts (all accounts except current logged in user)
  const contacts = accounts.filter((a) => a.id !== currentUser?.account.id);
  const filteredContacts = contacts.filter((c) =>
    c.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.username.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const activeContact = accounts.find((a) => a.id === activeContactId) || contacts[0];

  // Auto-select first contact if activeContactId is null
  useEffect(() => {
    if (!activeContactId && contacts.length > 0) {
      setActiveContactId(contacts[0].id);
    }
  }, [activeContactId, contacts, setActiveContactId]);

  // Messages between current user and active contact
  const conversationMessages = messages.filter((m) => {
    if (!currentUser || !activeContact) return false;
    const isSent = m.senderId === currentUser.account.id && m.recipientId === activeContact.id;
    const isReceived = m.senderId === activeContact.id && m.recipientId === currentUser.account.id;
    return isSent || isReceived;
  });

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [conversationMessages.length]);

  const handleSend = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!inputText.trim() || isSending || !activeContact) return;

    try {
      setIsSending(true);
      await sendMessage(activeContact.id, inputText.trim());
      setInputText('');
    } finally {
      setIsSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const togglePacketExpand = (msgId: string) => {
    setExpandedPackets((prev) => ({
      ...prev,
      [msgId]: !prev[msgId],
    }));
  };

  if (!currentUser) {
    return (
      <div className="flex-1 flex items-center justify-center p-8 text-center bg-slate-950">
        <div className="max-w-md p-6 bg-slate-900 border border-slate-800 rounded-xl">
          <Lock className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-slate-100 mb-2">Vault is Locked</h2>
          <p className="text-xs text-slate-400 mb-4">
            Unlock your identity vault using your password or switch to a demo profile to start end-to-end encrypted messaging.
          </p>
        </div>
      </div>
    );
  }

  const isContactVerified = activeContact ? isSafetyNumberVerified(activeContact.id) : false;

  return (
    <div className="flex-1 flex overflow-hidden h-[calc(100vh-105px)] bg-slate-950">
      {/* Left Column: Contacts Directory */}
      <aside className="w-80 shrink-0 border-r border-slate-800 flex flex-col bg-slate-950/60">
        {/* Search header */}
        <div className="p-3 border-b border-slate-800">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search contacts..."
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        {/* Contacts list */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/40">
          {filteredContacts.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">
              No contacts found
            </div>
          ) : (
            filteredContacts.map((contact) => {
              const isActive = activeContact?.id === contact.id;
              const isVerified = isSafetyNumberVerified(contact.id);
              // Get last message in conversation
              const contactMsgs = messages.filter(
                (m) =>
                  (m.senderId === contact.id && m.recipientId === currentUser.account.id) ||
                  (m.senderId === currentUser.account.id && m.recipientId === contact.id)
              );
              const lastMsg = contactMsgs[contactMsgs.length - 1];
              const decryptedLast = lastMsg ? decryptedMessages[lastMsg.id] : null;

              return (
                <button
                  key={contact.id}
                  onClick={() => setActiveContactId(contact.id)}
                  className={`w-full text-left p-3.5 transition-colors flex items-start gap-3 ${
                    isActive ? 'bg-slate-900/90 border-l-2 border-emerald-500' : 'hover:bg-slate-900/40'
                  }`}
                >
                  <div className="relative">
                    <div className="w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-medium text-xs text-slate-300">
                      {contact.avatar}
                    </div>
                    {isVerified && (
                      <span className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-emerald-400">
                        <ShieldCheck className="w-2.5 h-2.5" />
                      </span>
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-xs font-semibold text-slate-200 truncate">
                        {contact.displayName}
                      </span>
                      {lastMsg && (
                        <span className="text-[10px] text-slate-500 tabular-nums">
                          {new Date(lastMsg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      )}
                    </div>

                    <div className="text-[11px] text-slate-400 truncate flex items-center gap-1">
                      {lastMsg?.isTampered ? (
                        <span className="text-rose-400 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          Tampered Packet
                        </span>
                      ) : decryptedLast ? (
                        <span>{decryptedLast.plaintext}</span>
                      ) : (
                        <span className="italic text-slate-500">Key exchange ready</span>
                      )}
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Directory Footer Info */}
        <div className="p-3 border-t border-slate-800/80 text-[11px] text-slate-500 flex items-center justify-between">
          <span>ECDH Directory: {accounts.length} Identities</span>
          <span className="font-mono text-[10px] text-emerald-400/80">SECP256R1</span>
        </div>
      </aside>

      {/* Center Column: Active Conversation */}
      <main className="flex-1 flex flex-col bg-slate-950 min-w-0">
        {activeContact ? (
          <>
            {/* Conversation Header */}
            <header className="px-5 py-3 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-200 text-xs font-semibold">
                  {activeContact.avatar}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold text-slate-100 truncate">
                      {activeContact.displayName}
                    </h2>
                    <span className="text-xs font-mono text-slate-500">@{activeContact.username}</span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-slate-400">
                    <span className="flex items-center gap-1 text-emerald-400">
                      <Lock className="w-2.5 h-2.5" />
                      E2EE Active
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono text-slate-400">AES-256-GCM</span>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono text-slate-400">Curve P-256</span>
                  </div>
                </div>
              </div>

              {/* Safety Number Button */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowSafetyModal(true)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors border ${
                    isContactVerified
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
                  }`}
                  title="Verify Safety Number with peer"
                >
                  {isContactVerified ? (
                    <>
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Verified Safety Number</span>
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Verify Safety Number</span>
                    </>
                  )}
                </button>
              </div>
            </header>

            {/* Conversation Stream */}
            <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
              {/* E2EE Info Callout */}
              <div className="max-w-xl mx-auto p-3 bg-slate-900/60 border border-slate-800/80 rounded-lg text-center text-xs text-slate-400">
                <div className="flex items-center justify-center gap-1.5 text-emerald-400 font-medium mb-1">
                  <Lock className="w-3.5 h-3.5" />
                  <span>End-to-End Encrypted Session</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Messages and calls are secured with Elliptic Curve Diffie-Hellman key exchange and authenticated with AES-256-GCM.
                  Nobody outside of this chat, not even the server, can read or tamper with them.
                </p>
              </div>

              {conversationMessages.length === 0 ? (
                <div className="text-center py-12 text-slate-500 text-xs">
                  No encrypted messages yet. Type a message below to perform an ECDH key exchange and send encrypted ciphertext.
                </div>
              ) : (
                conversationMessages.map((msg) => {
                  const isSentByMe = msg.senderId === currentUser.account.id;
                  const decrypted = decryptedMessages[msg.id];
                  const isExpanded = !!expandedPackets[msg.id];
                  const isTampered = msg.isTampered;

                  return (
                    <div
                      key={msg.id}
                      className={`flex flex-col ${isSentByMe ? 'items-end' : 'items-start'} max-w-2xl ${
                        isSentByMe ? 'ml-auto' : 'mr-auto'
                      }`}
                    >
                      {/* Sender label and timestamp */}
                      <div className="flex items-center gap-2 mb-1 text-[11px] text-slate-500 px-1">
                        <span>{isSentByMe ? 'You' : activeContact.displayName}</span>
                        <span>·</span>
                        <span className="tabular-nums">
                          {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>

                      {/* Message Bubble */}
                      <div
                        className={`rounded-2xl p-4 text-xs transition-all w-full max-w-xl ${
                          isTampered
                            ? 'bg-rose-950/40 border border-rose-500/40 text-rose-200'
                            : isSentByMe
                            ? 'bg-slate-900 border border-slate-800 text-slate-100'
                            : 'bg-slate-900/90 border border-slate-800 text-slate-100'
                        }`}
                      >
                        {/* Plaintext / Decryption Result */}
                        {isTampered ? (
                          <div className="space-y-2 mb-3">
                            <div className="flex items-center gap-2 text-rose-400 font-semibold text-xs">
                              <AlertTriangle className="w-4 h-4 shrink-0" />
                              <span>Integrity Check Failed: {msg.tamperReason || 'Packet Tampered'}</span>
                            </div>
                            <p className="font-mono text-[11px] text-rose-300 bg-rose-950/60 p-2.5 rounded border border-rose-800/40">
                              {decrypted?.plaintext || 'Web Crypto AES-GCM tag verification rejected this packet.'}
                            </p>
                            <p className="text-[11px] text-rose-400/80">
                              The recipient's browser aborted decryption because ciphertext bits or digital signatures do not match.
                            </p>
                          </div>
                        ) : (
                          <p className="text-sm text-slate-100 whitespace-pre-wrap leading-relaxed mb-2 font-normal">
                            {decrypted ? decrypted.plaintext : 'Decrypting with ECDH shared key...'}
                          </p>
                        )}

                        {/* Security Verification Footer */}
                        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[10px]">
                          <div className="flex items-center gap-2">
                            {isTampered ? (
                              <span className="text-rose-400 flex items-center gap-1 font-mono">
                                <AlertTriangle className="w-3 h-3" />
                                TAMPER DETECTED
                              </span>
                            ) : (
                              <span className="text-emerald-400 flex items-center gap-1 font-mono">
                                <CheckCheck className="w-3 h-3" />
                                VERIFIED E2EE (AES-GCM + ECDSA)
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            {/* Toggle Raw Wire Packet */}
                            <button
                              onClick={() => togglePacketExpand(msg.id)}
                              className="text-slate-400 hover:text-slate-200 flex items-center gap-1 transition-colors"
                            >
                              <FileCode className="w-3 h-3" />
                              <span>{isExpanded ? 'Hide Wire Packet' : 'Inspect Wire Packet'}</span>
                              {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            </button>
                          </div>
                        </div>

                        {/* Raw Wire Packet Inspector Drawer */}
                        {isExpanded && (
                          <div className="mt-3 pt-3 border-t border-slate-800 text-[11px] font-mono space-y-2 bg-slate-950/70 p-3 rounded-lg border border-slate-800/60">
                            <div className="flex items-center justify-between text-slate-400 font-sans text-[10px]">
                              <span className="font-semibold text-slate-300">RAW CIPHERTEXT PACKET ON WIRE</span>
                              <span className="text-emerald-400">96-bit Nonce + 256-bit Ciphertext + 128-bit MAC</span>
                            </div>

                            <div>
                              <span className="text-slate-500 block text-[10px] font-sans">Initialization Vector (IV / Nonce):</span>
                              <div className="text-indigo-400 break-all select-all">{msg.ivHex}</div>
                            </div>

                            <div>
                              <span className="text-slate-500 block text-[10px] font-sans">AES-256-GCM Ciphertext + Auth Tag:</span>
                              <div className="text-emerald-400 break-all select-all max-h-24 overflow-y-auto">
                                {msg.ciphertextHex}
                              </div>
                            </div>

                            <div>
                              <span className="text-slate-500 block text-[10px] font-sans">ECDSA Digital Signature (SHA-256):</span>
                              <div className="text-amber-400 break-all select-all max-h-16 overflow-y-auto">
                                {msg.signatureHex}
                              </div>
                            </div>

                            {/* Direct Tamper Lab Controls */}
                            <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center gap-1.5 font-sans">
                              <span className="text-[10px] text-slate-400 font-medium mr-1 flex items-center gap-1">
                                <Bug className="w-3 h-3 text-amber-400" />
                                Simulate Attack:
                              </span>

                              {isTampered ? (
                                <button
                                  onClick={() => restoreOriginalMessage(msg.id)}
                                  className="px-2 py-1 bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 rounded text-[10px] font-medium transition-colors flex items-center gap-1"
                                >
                                  <RotateCcw className="w-3 h-3" />
                                  Restore Original Packet
                                </button>
                              ) : (
                                <>
                                  <button
                                    onClick={() => tamperMessage(msg.id, 'flip_byte')}
                                    className="px-2 py-1 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20 border border-rose-500/30 rounded text-[10px] transition-colors"
                                    title="Flip random byte in ciphertext (causes GCM tag check failure)"
                                  >
                                    Flip Ciphertext Bit
                                  </button>
                                  <button
                                    onClick={() => tamperMessage(msg.id, 'corrupt_sig')}
                                    className="px-2 py-1 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 border border-amber-500/30 rounded text-[10px] transition-colors"
                                    title="Corrupt ECDSA signature (causes signature rejection)"
                                  >
                                    Corrupt Signature
                                  </button>
                                  <button
                                    onClick={() => tamperMessage(msg.id, 'alter_iv')}
                                    className="px-2 py-1 bg-slate-800 text-slate-300 hover:bg-slate-700 rounded text-[10px] transition-colors"
                                    title="Alter IV"
                                  >
                                    Alter IV
                                  </button>
                                </>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Message Composer */}
            <footer className="p-4 border-t border-slate-800 bg-slate-950/90">
              <form onSubmit={handleSend} className="max-w-4xl mx-auto flex items-end gap-3">
                <div className="flex-1 relative bg-slate-900 border border-slate-800 rounded-xl focus-within:border-emerald-500 transition-colors">
                  <textarea
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder={`Message ${activeContact.displayName} securely... (Shift+Enter for newline)`}
                    rows={2}
                    className="w-full bg-transparent p-3 text-xs text-slate-100 placeholder-slate-500 focus:outline-none resize-none font-sans"
                  />
                  <div className="px-3 pb-2 flex items-center justify-between text-[10px] text-slate-500">
                    <span className="flex items-center gap-1 text-emerald-400/80">
                      <Lock className="w-2.5 h-2.5" />
                      Encrypted client-side via AES-256-GCM before transport
                    </span>
                    <span className="tabular-nums font-mono">{inputText.length} chars</span>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={!inputText.trim() || isSending}
                  className="px-5 py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 disabled:opacity-40 disabled:hover:bg-emerald-500 text-slate-950 font-semibold text-xs flex items-center gap-2 transition-colors shrink-0 shadow-sm"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{isSending ? 'Encrypting...' : 'Send'}</span>
                </button>
              </form>
            </footer>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center p-8 text-slate-500 text-xs">
            Select a contact to begin an encrypted conversation.
          </div>
        )}
      </main>

      {/* Safety Number Inspection Modal */}
      {showSafetyModal && activeContact && (
        <SafetyNumberModal
          contact={activeContact}
          currentUser={currentUser}
          onClose={() => setShowSafetyModal(false)}
        />
      )}
    </div>
  );
};
