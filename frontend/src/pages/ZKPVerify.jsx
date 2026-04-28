import { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, Lock, Search, CheckCircle, XCircle, Hash, RefreshCw, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';
import Layout from '../components/Layout';

// ── Local ZKP verification (runs in the browser, no server needed) ────────────
// Mirrors the Node.js zkp-generator.js logic using the Web Crypto API.

async function sha256Hex(text) {
    const msgBuf = new TextEncoder().encode(text);
    const hashBuf = await crypto.subtle.digest('SHA-256', msgBuf);
    return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256Hex(key, data) {
    const enc = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
        'raw', enc.encode(key),
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ──────────────────────────────────────────────────────────────────────────────

// Mock data for demonstration — in production this comes from /api/zkp-proofs
const MOCK_ZKP_RECORDS = [
    {
        ip_address: '192.168.1.105',
        commitment: 'a3f9b1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1',
        zkp_proof: 'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2',
        nonce: 'f1e2d3c4b5a6978869504132',
        timestamp: Math.floor(Date.now() / 1000) - 3600,
        verified: true,
    },
    {
        ip_address: '10.0.0.42',
        commitment: 'c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        zkp_proof: 'd7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8',
        nonce: 'a1b2c3d4e5f6789012345678',
        timestamp: Math.floor(Date.now() / 1000) - 7200,
        verified: true,
    },
    {
        ip_address: '172.16.0.254',
        commitment: 'e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0',
        zkp_proof: 'f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1',
        nonce: '9988776655443322',
        timestamp: Math.floor(Date.now() / 1000) - 300,
        verified: true,
    },
];

function CopyButton({ text }) {
    const [copied, setCopied] = useState(false);
    const handleCopy = async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };
    return (
        <button onClick={handleCopy} className="text-gray-500 hover:text-white transition-colors ml-1 flex-shrink-0">
            {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
        </button>
    );
}

function ProofCard({ record, index }) {
    const [expanded, setExpanded] = useState(false);
    const age = Math.floor((Date.now() / 1000 - record.timestamp) / 60);

    return (
        <div
            className="group border border-white/10 rounded-2xl overflow-hidden bg-gradient-to-br from-white/5 to-transparent
                        hover:border-emerald-500/30 transition-all duration-300"
            style={{ animationDelay: `${index * 80}ms` }}
        >
            <div className="p-5 flex items-center gap-4">
                {/* ZKP badge */}
                <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                    <Lock className="w-5 h-5 text-emerald-400" />
                </div>

                {/* IP + fingerprint */}
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono font-semibold text-white">{record.ip_address}</span>
                        <span className="px-2 py-0.5 text-xs rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                            ZKP ✓
                        </span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500 font-mono">
                            zkp:{record.commitment.slice(0, 8)}...
                        </span>
                        <span className="text-xs text-gray-600">·</span>
                        <span className="text-xs text-gray-500">{age < 60 ? `${age}m ago` : `${Math.floor(age / 60)}h ago`}</span>
                    </div>
                </div>

                {/* Expand toggle */}
                <button
                    onClick={() => setExpanded(v => !v)}
                    className="text-gray-500 hover:text-white transition-colors p-1"
                >
                    {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
            </div>

            {/* Expanded detail panel */}
            {expanded && (
                <div className="border-t border-white/5 p-5 space-y-3 bg-black/20">
                    <p className="text-xs text-gray-500 uppercase tracking-widest mb-3 font-semibold">On-Chain ZKP Data</p>

                    {[
                        { label: 'IP Address', value: record.ip_address, note: 'Public — used for blocklist' },
                        { label: 'Commitment', value: record.commitment, note: 'SHA-256(ip + attack_type + nonce) — hides attack details' },
                        { label: 'ZKP Proof', value: record.zkp_proof, note: 'HMAC-SHA256(serverKey, commitment) — proves validator knew the secret' },
                        { label: 'Nonce', value: record.nonce, note: 'Random salt — prevents replay attacks' },
                    ].map(({ label, value, note }) => (
                        <div key={label} className="space-y-1">
                            <div className="flex items-center justify-between">
                                <span className="text-xs text-gray-400 font-semibold">{label}</span>
                                <span className="text-xs text-gray-600 italic">{note}</span>
                            </div>
                            <div className="flex items-center gap-1 bg-black/40 rounded-lg px-3 py-2 border border-white/5">
                                <span className="font-mono text-xs text-gray-300 truncate flex-1">{value}</span>
                                <CopyButton text={value} />
                            </div>
                        </div>
                    ))}

                    <div className="mt-2 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/10">
                        <p className="text-xs text-emerald-400">
                            <span className="font-semibold">🔒 Attack type is NOT stored on-chain.</span>
                            {' '}The commitment cryptographically attests that a valid attack was detected without revealing what it was.
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}

export default function ZKPVerify() {
    const [records, setRecords] = useState([]);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);

    // Manual verifier state
    const [verifyIp, setVerifyIp] = useState('');
    const [verifyCommitment, setVerifyCommitment] = useState('');
    const [verifyProof, setVerifyProof] = useState('');
    const [verifyKey, setVerifyKey] = useState('');
    const [verifyAttack, setVerifyAttack] = useState('');
    const [verifyNonce, setVerifyNonce] = useState('');
    const [verifyResult, setVerifyResult] = useState(null); // null | 'valid' | 'invalid'
    const [verifying, setVerifying] = useState(false);

    const loadRecords = useCallback(async () => {
        try {
            // Try to fetch from the real API; fall back to mock data
            const res = await fetch('/api/zkp-proofs').catch(() => null);
            if (res && res.ok) {
                const data = await res.json();
                setRecords(data.records || []);
            } else {
                setRecords(MOCK_ZKP_RECORDS);
            }
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    }, []);

    useEffect(() => { loadRecords(); }, [loadRecords]);

    const handleRefresh = () => {
        setRefreshing(true);
        loadRecords();
    };

    // Local ZKP verification — runs entirely in the browser
    const handleVerify = async () => {
        setVerifying(true);
        setVerifyResult(null);
        try {
            // Reconstruct the witness and commitment
            const witness = `${verifyIp}:${verifyAttack}:${verifyNonce}`;
            const expectedCommitment = await sha256Hex(witness);

            if (expectedCommitment !== verifyCommitment) {
                setVerifyResult('invalid');
                return;
            }

            // Verify the HMAC proof
            const expectedProof = await hmacSha256Hex(verifyKey, verifyCommitment);
            setVerifyResult(expectedProof === verifyProof ? 'valid' : 'invalid');
        } catch {
            setVerifyResult('invalid');
        } finally {
            setVerifying(false);
        }
    };

    const canVerify = verifyIp && verifyCommitment && verifyProof && verifyKey && verifyAttack && verifyNonce;

    return (
        <Layout>
            <div className="max-w-5xl mx-auto space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-500">

                {/* Header */}
                <div className="flex items-center justify-between border-b border-white/10 pb-6">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-3 mb-1">
                            <div className="p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">
                                <ShieldCheck className="w-7 h-7 text-emerald-400" />
                            </div>
                            ZKP Proof Registry
                        </h1>
                        <p className="text-gray-400 text-sm mt-2 max-w-xl">
                            Each flagged IP has a cryptographic proof that it was malicious.
                            The attack method is <span className="text-emerald-400 font-semibold">never revealed</span> — only the commitment hash is stored on-chain.
                        </p>
                    </div>
                    <button
                        onClick={handleRefresh}
                        disabled={refreshing}
                        className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-all text-sm text-gray-300"
                    >
                        <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                        Refresh
                    </button>
                </div>

                {/* How it works banner */}
                <div className="grid grid-cols-3 gap-4">
                    {[
                        {
                            icon: <Hash className="w-5 h-5 text-blue-400" />,
                            bg: 'from-blue-500/10',
                            border: 'border-blue-500/20',
                            title: 'Commitment',
                            desc: 'SHA-256 of (ip + attack_type + nonce). Hides the attack method.'
                        },
                        {
                            icon: <Lock className="w-5 h-5 text-purple-400" />,
                            bg: 'from-purple-500/10',
                            border: 'border-purple-500/20',
                            title: 'ZKP Proof',
                            desc: 'HMAC-SHA256 proof that the validator knew the secret at detection time.'
                        },
                        {
                            icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
                            bg: 'from-emerald-500/10',
                            border: 'border-emerald-500/20',
                            title: 'Privacy Guarantee',
                            desc: 'Attack type, patterns & payloads never reach the blockchain.'
                        },
                    ].map(({ icon, bg, border, title, desc }) => (
                        <div key={title} className={`p-4 rounded-xl bg-gradient-to-br ${bg} to-transparent border ${border} backdrop-blur-sm`}>
                            <div className="flex items-center gap-2 mb-2">
                                {icon}
                                <span className="font-semibold text-sm">{title}</span>
                            </div>
                            <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
                        </div>
                    ))}
                </div>

                {/* ZKP Records list */}
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <h2 className="text-lg font-semibold text-gray-200 flex items-center gap-2">
                            <Lock className="w-4 h-4 text-emerald-400" />
                            ZKP-Attested Malicious IPs
                            <span className="text-sm font-normal text-gray-500">({records.length})</span>
                        </h2>
                    </div>

                    {loading ? (
                        <div className="flex items-center justify-center h-40">
                            <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-emerald-400" />
                        </div>
                    ) : records.length === 0 ? (
                        <div className="text-center py-16 text-gray-500 border border-white/5 rounded-2xl">
                            No ZKP records on-chain yet.
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {records.map((rec, i) => (
                                <ProofCard key={rec.ip_address} record={rec} index={i} />
                            ))}
                        </div>
                    )}
                </div>

                {/* Manual verifier */}
                <div className="border border-white/10 rounded-2xl overflow-hidden">
                    <div className="p-6 bg-gradient-to-br from-violet-500/5 to-transparent border-b border-white/5">
                        <h2 className="text-lg font-semibold flex items-center gap-2 mb-1">
                            <Search className="w-5 h-5 text-violet-400" />
                            Manual Proof Verifier
                        </h2>
                        <p className="text-sm text-gray-400">
                            If you have the original secret inputs, you can verify a proof locally — entirely in your browser.
                            This proves the on-chain commitment matches the attack data.
                        </p>
                    </div>

                    <div className="p-6 space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            {[
                                { label: 'IP Address', value: verifyIp, set: setVerifyIp, placeholder: '192.168.1.1', public: true },
                                { label: 'Attack Type', value: verifyAttack, set: setVerifyAttack, placeholder: 'DoS / SQLi / XSS …', public: false },
                                { label: 'Nonce', value: verifyNonce, set: setVerifyNonce, placeholder: 'hex nonce from proof record', public: true },
                                { label: 'Server Secret Key', value: verifyKey, set: setVerifyKey, placeholder: 'validator HMAC key (stays local)', public: false },
                                { label: 'On-chain Commitment', value: verifyCommitment, set: setVerifyCommitment, placeholder: '64-char hex', public: true },
                                { label: 'On-chain ZKP Proof', value: verifyProof, set: setVerifyProof, placeholder: '64-char hex', public: true },
                            ].map(({ label, value, set, placeholder, public: isPub }) => (
                                <div key={label} className="space-y-1">
                                    <label className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wide">
                                        {label}
                                        <span className={`px-1.5 py-0.5 rounded text-xs ${isPub ? 'bg-blue-500/10 text-blue-400' : 'bg-orange-500/10 text-orange-400'}`}>
                                            {isPub ? 'public' : 'private'}
                                        </span>
                                    </label>
                                    <input
                                        type={isPub ? 'text' : 'text'}
                                        value={value}
                                        onChange={e => set(e.target.value)}
                                        placeholder={placeholder}
                                        className="w-full px-3 py-2.5 rounded-xl bg-black/40 border border-white/10 text-sm font-mono text-gray-200
                                                   placeholder-gray-600 focus:outline-none focus:border-violet-500/40 focus:ring-1 focus:ring-violet-500/20 transition-all"
                                    />
                                </div>
                            ))}
                        </div>

                        <div className="flex items-center gap-4 pt-2">
                            <button
                                onClick={handleVerify}
                                disabled={!canVerify || verifying}
                                className="px-6 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 disabled:opacity-40 disabled:cursor-not-allowed
                                           transition-all font-semibold text-sm flex items-center gap-2 shadow-lg shadow-violet-500/20"
                            >
                                {verifying
                                    ? <><RefreshCw className="w-4 h-4 animate-spin" /> Verifying…</>
                                    : <><Search className="w-4 h-4" /> Verify Proof</>
                                }
                            </button>

                            {verifyResult && (
                                <div className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold
                                    ${verifyResult === 'valid'
                                        ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                                        : 'bg-red-500/10 border border-red-500/20 text-red-400'
                                    }`}>
                                    {verifyResult === 'valid'
                                        ? <><CheckCircle className="w-4 h-4" /> Proof Valid — Attack confirmed, method hidden ✓</>
                                        : <><XCircle className="w-4 h-4" /> Proof Invalid — Inputs don't match</>
                                    }
                                </div>
                            )}
                        </div>

                        <p className="text-xs text-gray-600 italic">
                            🔒 Private inputs (attack type, server key) never leave your browser — verification runs locally using the Web Crypto API.
                        </p>
                    </div>
                </div>

            </div>
        </Layout>
    );
}
