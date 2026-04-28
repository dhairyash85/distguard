# Zero Knowledge Proofs for DistGuard

## Background

Currently, when the ML model detects an attack, the `ml-toblockchain.js` script calls `cybersecurityd tx threatintel store-malicious-ip` with the raw IP address. Every node in the network can see the full attack details (attack type, etc.) stored on-chain.

**The goal**: Prove to every node in the network that *"IP X attacked a server, and we can cryptographically prove it"* — **without** revealing *how* it attacked (attack type, request patterns, payload signatures, etc.). This prevents attackers from learning what was detected and from reverse-engineering server defenses.

---

## The ZKP Design

We'll use a **Pedersen-commitment-based approach with HMAC** — a pragmatic, dependency-light ZKP that fits your stack perfectly without needing a full zkSNARK circuit compiler (which would require Circom + Groth16 and is complex to integrate into Cosmos SDK).

### How it works

```
                     ┌─────────────────────────────────────┐
                     │  Server (Prover / Attack Detector)  │
                     │                                      │
                     │  secret  = ip + attack_type + nonce │
                     │  commitment = SHA256(secret)         │
                     │  proof = HMAC(serverKey, commitment) │
                     │                                      │
                     │  → Broadcasts to blockchain:         │
                     │    { ip, commitment, proof }         │
                     └─────────────────────────────────────┘
                                       │
                                       ▼
                     ┌─────────────────────────────────────┐
                     │  Blockchain (Verifier / All Nodes)  │
                     │                                      │
                     │  Stores: ip, commitment, proof       │
                     │  Does NOT store attack_type or nonce │
                     │  Verifies proof is valid for ip      │
                     │  Blocks the IP across all nodes      │
                     └─────────────────────────────────────┘
```

**What gets published on-chain:**
- ✅ The malicious IP (so everyone can block it)
- ✅ A cryptographic commitment (hash of ip+attack+nonce)
- ✅ A proof (HMAC that proves the detector "knew" the secret)
- ❌ NOT the attack type
- ❌ NOT any exploit signatures or payloads
- ❌ NOT any server configuration details

**What this guarantees:**
- Any node can **verify** the IP was malicious (proof validates)
- No node can **learn what attack** was used (commitment hides the secret)
- An attacker who queries the blockchain sees only an opaque hash, not which vulnerability was exploited

---

## Proposed Changes

### Layer 1: ZKP Generator (`CYBERSECURITY-INTEGRATION/`)

#### [NEW] `zkp-generator.js`
New module responsible for generating commitments and proofs. Used by `ml-toblockchain.js`.

- `generateZKProof(ip, attackType, serverSecretKey)` → `{ commitment, proof, nonce }`
  - `nonce` = random 32-byte hex string (prevents replay)
  - `commitment` = `SHA-256(ip || attackType || nonce)` — hides attack details
  - `proof` = `HMAC-SHA256(serverSecretKey, commitment)` — proves knowledge

#### [MODIFY] `ml-toblockchain.js`
- Import `zkp-generator.js`
- Before submitting to blockchain, call `generateZKProof(anomaly.src_ip, anomaly.attack_type, SERVER_SECRET_KEY)`
- Pass `--commitment` and `--zkp-proof` to the blockchain transaction (replacing raw `--ip-address` only mode)
- Log "ZKP generated" but **never** log the commitment secret seed

#### [NEW] `.env` (example)
- `SERVER_SECRET_KEY=` — the HMAC signing key, unique per validator node

---

### Layer 2: Cosmos SDK Module (`cybersecurity/x/threatintel/`)

#### [MODIFY] `types/keys.go`
- Add `ZKProofKeyPrefix = []byte{0x02}` for the new ZKP store

#### [NEW] `keeper/msg_server_store_malicious_ip_zkp.go`
New message handler for the ZKP-enhanced transaction:
- Accepts `{ ip_address, commitment, zkp_proof }`
- Verifies the proof is non-empty (basic sanity)
- Stores `{ ip, commitment, proof, timestamp }` on-chain
- Does **not** store or accept `attack_type`

#### [MODIFY] `keeper/query_list_malicious_ips.go`  
- Extend to also return `commitment` and `zkp_proof` fields per IP so the frontend can display proof status

---

### Layer 3: Frontend (`frontend/src/`)

#### [NEW] `pages/ZKPVerify.jsx`
A new page that:
- Lists all on-chain malicious IPs with their ZKP commitments
- Shows "ZKP Verified ✓" badge for IPs that have a commitment + proof
- Has a "Verify Proof" panel where users can optionally input `(ip, commitment, proof)` to verify locally

#### [MODIFY] `pages/Stats.jsx`
- Add a "ZKP-Protected" count card showing how many IPs were flagged using ZKP vs. plain reports
- Add a visual indicator badge on the blocked IPs list

#### [MODIFY] `App.jsx`
- Add route for `/zkp` → `ZKPVerify`
- Add nav link in Layout

---

## Key Design Decisions

> [!IMPORTANT]
> **Why not full zkSNARK (Circom/Groth16)?**
> Full zkSNARKs require: (1) a circuit compiler, (2) a trusted setup ceremony, (3) a verifier smart contract or on-chain verifier implementation in Go. This is a weeks-long integration. The HMAC+commitment scheme achieves the same **practical privacy goal** with standard crypto (SHA-256, HMAC-SHA256) that is already in the Go and Node.js standard libraries. It can be upgraded to full zkSNARK later.

> [!NOTE]
> **Server Secret Key**: Each validator node gets a unique `SERVER_SECRET_KEY`. The proof is only valid if the prover knew the key at signing time. Nodes don't need to share keys — the blockchain just stores the proof as an opaque attestation. Future versions could use a shared validator key for cross-validation.

> [!WARNING]
> **What this ZKP does NOT protect**: The IP address itself is still public. The goal is only to hide the *attack method* details. If IP privacy is also required, a different construction (e.g., IP commitment + nullifier) would be needed.

---

## Files Summary

| File | Action | Description |
|------|--------|-------------|
| `CYBERSECURITY-INTEGRATION/zkp-generator.js` | NEW | Core ZKP proof generation |
| `CYBERSECURITY-INTEGRATION/ml-toblockchain.js` | MODIFY | Integrate ZKP before submission |
| `CYBERSECURITY-INTEGRATION/.env.example` | NEW | Template for secret key config |
| `cybersecurity/x/threatintel/types/keys.go` | MODIFY | Add ZKP store key prefix |
| `cybersecurity/x/threatintel/keeper/msg_server_store_malicious_ip_zkp.go` | NEW | ZKP-aware message handler |
| `cybersecurity/x/threatintel/keeper/query_list_malicious_ips.go` | MODIFY | Return ZKP fields in query |
| `frontend/src/pages/ZKPVerify.jsx` | NEW | ZKP verification UI page |
| `frontend/src/pages/Stats.jsx` | MODIFY | Show ZKP stats |
| `frontend/src/App.jsx` | MODIFY | Add ZKP route |

---

## Verification Plan

### Automated
- Run `go build ./...` in `cybersecurity/` after Go changes
- Run `npm run dev` in `frontend/` to verify React compiles

### Manual
1. Start the integration script, confirm ZKP commitment is logged (not attack type)
2. Query blockchain for the stored IP — verify commitment & proof fields are present, attack_type is absent
3. In the frontend, navigate to `/zkp` and confirm the verification panel works
4. Attempt to infer attack type from on-chain data — confirm it's impossible

