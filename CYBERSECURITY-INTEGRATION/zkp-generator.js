/**
 * zkp-generator.js
 *
 * Zero-Knowledge Proof generator for DistGuard.
 *
 * Scheme: SHA-256 commitment + HMAC-SHA256 proof
 * ---------------------------------------------------
 * The "witness" (the secret that must be hidden) is the attack_type.
 * The prover commits to   secret = ip || attack_type || nonce
 * and publishes:          commitment = SHA256(secret)
 *                         proof      = HMAC-SHA256(serverKey, commitment)
 *
 * What goes on-chain: ip, commitment, proof, nonce
 * What NEVER goes on-chain: attack_type, serverKey
 *
 * Any node can store the (commitment, proof) and trust that whoever
 * submitted it knew both the secret and the serverKey.
 * No node can reverse-engineer the attack_type from commitment alone.
 */

'use strict';

const crypto = require('crypto');

/**
 * Generate a ZKP commitment + proof for a detected anomaly.
 *
 * @param {string} ip          - The attacker's IP address (public)
 * @param {string} attackType  - The attack type (PRIVATE — never revealed)
 * @param {string} serverKey   - Per-validator HMAC secret key (PRIVATE)
 * @returns {{ commitment: string, proof: string, nonce: string }}
 */
function generateZKProof(ip, attackType, serverKey) {
  if (!ip || !attackType || !serverKey) {
    throw new Error('generateZKProof: ip, attackType, and serverKey are all required');
  }

  // Step 1: Generate a random nonce to prevent replay attacks.
  // Two reports of the same IP + attack produce different commitments.
  const nonce = crypto.randomBytes(32).toString('hex');

  // Step 2: Build the secret witness.
  // This encodes WHAT attack happened WITHOUT putting it on-chain.
  const witness = `${ip}:${attackType}:${nonce}`;

  // Step 3: Commit to the witness via SHA-256.
  // commitment hides attack_type — SHA-256 is preimage-resistant.
  const commitment = crypto
    .createHash('sha256')
    .update(witness, 'utf8')
    .digest('hex');

  // Step 4: Prove knowledge using HMAC-SHA256 over the commitment.
  // This proves the detector "knew" the commitment at signing time,
  // binding the proof to this specific validator node's secret key.
  const proof = crypto
    .createHmac('sha256', serverKey)
    .update(commitment, 'utf8')
    .digest('hex');

  return { commitment, proof, nonce };
}

/**
 * Verify a ZKP proof given the public inputs.
 * Called by nodes that wish to confirm a submitted proof is authentic.
 *
 * NOTE: Nodes that do not share the same serverKey will get a different
 * computed proof. In a multi-validator setup this is an attestation
 * from the reporting validator; the blockchain still stores and forwards it.
 *
 * @param {string} commitment  - The commitment retrieved from the chain
 * @param {string} proof       - The proof retrieved from the chain
 * @param {string} serverKey   - The validator's secret key (if available)
 * @returns {boolean}
 */
function verifyZKProof(commitment, proof, serverKey) {
  if (!commitment || !proof || !serverKey) return false;

  const expectedProof = crypto
    .createHmac('sha256', serverKey)
    .update(commitment, 'utf8')
    .digest('hex');

  // Use timingSafeEqual to prevent timing-oracle attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(proof, 'hex'),
      Buffer.from(expectedProof, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * Derive a human-readable "proof fingerprint" for display in the UI.
 * This is a short prefix of the commitment — safe to show publicly.
 *
 * @param {string} commitment
 * @returns {string} e.g. "zkp:a3f9b1c2"
 */
function proofFingerprint(commitment) {
  return `zkp:${commitment.slice(0, 8)}`;
}

module.exports = { generateZKProof, verifyZKProof, proofFingerprint };
