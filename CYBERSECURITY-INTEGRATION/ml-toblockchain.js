const axios = require('axios');
const { spawn, exec } = require('child_process');
require('dotenv').config();

const ML_API = process.env.ML_API || 'http://localhost:5000';
const VALIDATOR_ADDRESS = process.env.VALIDATOR_ADDRESS || 'cosmos199xtarytzzw3qm0vaz8pkz7ure4w9k94qp53e4';
const CHAIN_ID = 'cybersecurity';
let lastProcessedTimestamp = null;

// Function to get the latest account sequence from the blockchain
function getLatestSequence(address) {
  return new Promise((resolve, reject) => {
    exec(`cybersecurityd query auth account ${address} --output json`, (error, stdout, stderr) => {
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
    console.log(`  Attack Type: ${anomaly.attack_type}`);

    // 1. Get the LATEST sequence number dynamically
    const currentSequence = await getLatestSequence(VALIDATOR_ADDRESS);
    console.log(`  Using sequence number: ${currentSequence}`);

    // 2. Spawn the command
    const cmd = spawn('cybersecurityd', [
      'tx', 'threatintel', 'store-malicious-ip',
      '--ip-address', anomaly.src_ip,
      '--from', 'validator',
      '--keyring-backend', 'test',
      '--chain-id', CHAIN_ID,
      '--sequence', currentSequence.toString(),
      '--gas', 'auto', // Let the chain estimate gas
      '--gas-adjustment', '1.5',
      '--yes'
    ]);

    let errorOutput = '';
    cmd.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    cmd.on('close', (code) => {
      if (code === 0) {
        console.log(`✓ Successfully submitted anomaly to blockchain.`);
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
      if (anomaly.timestamp !== lastProcessedTimestamp && anomaly.attack_type !== 'Benign') {
        console.log(`\n🚨 New malicious activity detected:`);
        console.log(`   Timestamp: ${anomaly.timestamp}`);
        console.log(`   Type: ${anomaly.attack_type}`);

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

console.log('Starting ML-to-Blockchain integration...');
setInterval(checkAnomalies, 10000);
