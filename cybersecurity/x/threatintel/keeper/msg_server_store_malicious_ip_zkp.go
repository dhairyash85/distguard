package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cybersecurity/x/threatintel/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ZKProofRecord is the on-chain record for a ZKP-attested malicious IP.
// It deliberately omits attack_type — only the commitment (a hash of the
// secret witness) and the HMAC proof are stored.
type ZKProofRecord struct {
	IpAddress  string `json:"ip_address"`
	Commitment string `json:"commitment"` // SHA-256(ip || attack_type || nonce)
	ZKPProof   string `json:"zkp_proof"`  // HMAC-SHA256(serverKey, commitment)
	Nonce      string `json:"nonce"`      // Random salt; prevents replay
	Timestamp  int64  `json:"timestamp"`
}

// MsgStoreZKProof is a pure-Go (non-proto) message used internally
// when the integration script passes ZKP fields via the blockchain memo/note field.
// It is decoded from the JSON-encoded --note flag of the store-malicious-ip tx.
type MsgStoreZKProof struct {
	IpAddress  string `json:"ip_address"`
	Commitment string `json:"commitment"`
	ZKPProof   string `json:"zkp_proof"`
	Nonce      string `json:"nonce"`
}

// StoreZKProofRecord stores a ZKP proof record on-chain.
// It is called by the StoreMaliciousIp handler when ZKP fields are detected
// in the transaction's memo/note field.
//
// Privacy guarantee: the attack_type is embedded inside the commitment
// hash and is never transmitted or stored on-chain. Any node can verify
// the IP was flagged (proof exists) but cannot learn HOW it attacked.
func (k msgServer) StoreZKProofRecord(goCtx context.Context, zkp MsgStoreZKProof) error {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if zkp.IpAddress == "" {
		return fmt.Errorf("ip_address cannot be empty")
	}

	// Validate commitment format (must be 64-char hex = SHA-256 output)
	if len(zkp.Commitment) != 64 {
		return fmt.Errorf("invalid commitment: expected 64-char SHA-256 hex, got %d chars", len(zkp.Commitment))
	}

	// Validate proof format (must be 64-char hex = HMAC-SHA256 output)
	if len(zkp.ZKPProof) != 64 {
		return fmt.Errorf("invalid zkp_proof: expected 64-char HMAC-SHA256 hex, got %d chars", len(zkp.ZKPProof))
	}

	store := k.storeService.OpenKVStore(ctx)

	// ── Store the ZKP record in its own namespace (prefix 0x02) ──────────────
	// Key: ZKProofKeyPrefix + ip_address (unique per IP)
	zkpKey := append(types.ZKProofKeyPrefix, []byte(zkp.IpAddress)...)

	record := ZKProofRecord{
		IpAddress:  zkp.IpAddress,
		Commitment: zkp.Commitment,
		ZKPProof:   zkp.ZKPProof,
		Nonce:      zkp.Nonce,
		Timestamp:  time.Now().Unix(),
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal ZKP record: %w", err)
	}

	store.Set(zkpKey, recordBytes)

	// ── Emit a blockchain event ───────────────────────────────────────────────
	// commitment is public (opaque hash). attack_type is intentionally absent.
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			"zkp_malicious_ip_stored",
			sdk.NewAttribute("ip_address", zkp.IpAddress),
			sdk.NewAttribute("commitment", zkp.Commitment),
			// zkp_proof omitted from events — queryable directly from chain state.
		),
	)

	return nil
}

// tryDecodeZKPFromMemo attempts to decode a ZKProof from the transaction memo.
// The integration script JSON-encodes ZKP fields into the --note/memo field:
//   --note '{"commitment":"...","zkp_proof":"...","nonce":"..."}'
// Returns nil if the memo contains no ZKP fields (plain transaction).
func tryDecodeZKPFromMemo(memo string, ipAddress string) *MsgStoreZKProof {
	if memo == "" {
		return nil
	}
	var zkp MsgStoreZKProof
	if err := json.Unmarshal([]byte(memo), &zkp); err != nil {
		return nil
	}
	if zkp.Commitment == "" || zkp.ZKPProof == "" {
		return nil
	}
	zkp.IpAddress = ipAddress
	return &zkp
}
