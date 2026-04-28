const axios = require('axios');
const { spawn, exec } = require('child_process');
const { generateZKProof, proofFingerprint } = require('./zkp-generator');
require('dotenv').config();

const ML_API = process.env.ML_API || 'http://localhost:5000';
const VALIDATOR_ADDRESS = process.env.VALIDATOR_ADDRESS || 'cosmos1pyhc08t8eytyna8ldzdvyq8sgd53607k0y3syp';
const CHAIN_ID = 'cybersecurity';
const NODE_HOME = process.env.NODE_HOME || '/home/dheerizz/.cybersecurity-testnet/node0';
const SERVER_SECRET_KEY = process.env.SERVER_SECRET_KEY;
let lastProcessedTimestamp = null;

// Warn loudly at startup if the secret key is missing
if (!SERVER_SECRET_KEY) {
  console.warn('⚠️  WARNING: SERVER_SECRET_KEY is not set in .env');
  console.warn('   ZKP proofs will NOT be generated for submissions.');
  console.warn('   Copy .env.example to .env and set SERVER_SECRET_KEY.');
}

// Function to get the latest account sequence from the blockchain
function getLatestSequence(address) {
  return new Promise((resolve, reject) => {
    exec(`cybersecurityd query auth account ${address} --home ${NODE_HOME} --output json`, (error, stdout, stderr) => {
      if (error) {
        return reject(new Error(`Error fetching account details: ${stderr}`));
      }
      try {
        const accountData = JSON.parse(stdout);

        // CORRECTED LOGIC: Check the nested path and default to 0 if sequence is missing.
        if (accountData && accountData.account && accountData.account.value && accountData.account.value.sequence) {
          resolve(parseInt(accountData.account.value.sequence, 10));
        } else {
          // If the sequence field does not exist, it's the first transaction, so the sequence is 0.
          console.log("Sequence number not found, defaulting to 0 for the first transaction.");
          resolve(0);
        }

      } catch (e) {
        reject(new Error(`Failed to parse account data. Error: ${e.message}`));
      }
    });
  });
}

async function submitToBlockchain(anomaly) {
  try {
    console.log(`[${new Date().toISOString()}] Submitting anomaly to blockchain...`);
    console.log(`  Source IP: ${anomaly.src_ip}`);
    // NOTE: attack_type is intentionally NOT logged here to avoid leaking
    // security-sensitive information to log files.

    // 1. Get the LATEST sequence number dynamically
    const currentSequence = await getLatestSequence(VALIDATOR_ADDRESS);
    console.log(`  Using sequence number: ${currentSequence}`);

    // 2. Generate Zero-Knowledge Proof
    //    The ZKP commits to (ip + attack_type + nonce) but only
    //    publishes the commitment hash and HMAC proof on-chain.
    //    The attack_type NEVER leaves this process.
    let zkpData = null;
    if (SERVER_SECRET_KEY) {
      const { commitment, proof, nonce } = generateZKProof(
        anomaly.src_ip,
        anomaly.attack_type,
        SERVER_SECRET_KEY
      );
      const fingerprint = proofFingerprint(commitment);
      console.log(`  🔐 ZKP generated: ${fingerprint} (nonce: ${nonce.slice(0, 8)}...)`);
      zkpData = { commitment, proof, nonce };
    } else {
      console.log('  ⚠️  Submitting without ZKP (SERVER_SECRET_KEY not configured)');
    }

    // 3. Spawn the transaction command
    const args = [
      'tx', 'threatintel', 'store-malicious-ip',
      '--ip-address', anomaly.src_ip,
      '--from', 'validator',
      '--keyring-backend', 'test',
      '--chain-id', CHAIN_ID,
      '--home', NODE_HOME,
      '--sequence', currentSequence.toString(),
      '--gas', 'auto',
      '--gas-adjustment', '1.5',
      '--yes',
    ];

    // Pass ZKP payload via the --note (memo) flag.
    // The on-chain handler reads tx.Memo and stores the commitment + proof
    // in the ZKProofKeyPrefix namespace, WITHOUT storing the attack_type.
    if (zkpData) {
      const zkpMemo = JSON.stringify({
        commitment: zkpData.commitment,
        zkp_proof: zkpData.proof,
        nonce: zkpData.nonce,
      });
      args.push('--note', zkpMemo);
    }

    const cmd = spawn('cybersecurityd', args);

    let errorOutput = '';
    cmd.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    cmd.on('close', (code) => {
      if (code === 0) {
        const zkpStatus = zkpData ? ' (ZKP-protected)' : '';
        console.log(`✓ Successfully submitted anomaly to blockchain${zkpStatus}.`);
      } else {
        console.log(`✗ Failed to submit transaction (exit code: ${code})`);
        console.error('Blockchain Error:', errorOutput);
      }
    });

  } catch (error) {
    console.error('Error submitting to blockchain:', error.message);
  }
}

async function checkAnomalies() {
  try {
    const response = await axios.get(`${ML_API}/recent-anomalies?limit=1`);
    if (response.data.anomalies.length > 0) {
      const anomaly = response.data.anomalies[0];

      // 3. Check if the anomaly is new and NOT benign
      if (anomaly.timestamp !== lastProcessedTimestamp && anomaly.anomaly_detected === true) {
        console.log(`\n🚨 New malicious activity detected:`);
        console.log(`   Timestamp: ${anomaly.timestamp}`);
        // NOTE: attack_type is intentionally omitted from logs to protect security intel.
        console.log(`   [attack type hidden — ZKP will attest to it on-chain]`);

        lastProcessedTimestamp = anomaly.timestamp; // Mark as processed
        await submitToBlockchain(anomaly);
      }
    }
  } catch (error) {
    // Suppress connection errors for cleaner logs
    if (error.code !== 'ECONNREFUSED') {
      console.error('Error checking anomalies:', error.message);
    }
  }
}

console.log('Starting ML-to-Blockchain integration (ZKP-enabled)...');
if (SERVER_SECRET_KEY) {
  console.log('🔐 Zero-Knowledge Proofs: ENABLED');
} else {
  console.log('⚠️  Zero-Knowledge Proofs: DISABLED (set SERVER_SECRET_KEY in .env)');
}
setInterval(checkAnomalies, 10000);
