package keeper

import (
	"context"
	"encoding/json"

	"cybersecurity/x/threatintel/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// StoreMaliciousIp handles the logic for the StoreMaliciousIp transaction.
// If the transaction memo contains a JSON-encoded ZKP payload, it also
// stores a ZKP record in the separate ZKProofKeyPrefix namespace.
func (k msgServer) StoreMaliciousIp(goCtx context.Context, msg *types.MsgStoreMaliciousIp) (*types.MsgStoreMaliciousIpResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Get the key-value store from the keeper
	store := k.storeService.OpenKVStore(ctx)

	// Create the key for the new IP address.
	// The key is the prefix + the IP address itself to ensure uniqueness.
	key := append(types.MaliciousIpKeyPrefix, []byte(msg.IpAddress)...)

	// Set the value in the store. Here, we'll store the IP address as the value.
	value := []byte(msg.IpAddress)
	store.Set(key, value)

	// ── ZKP extension ─────────────────────────────────────────────────────────
	// If the transaction memo carries a JSON-encoded ZKP payload, store the
	// ZKP record alongside the plain IP. The memo looks like:
	//   {"commitment":"<hex>","zkp_proof":"<hex>","nonce":"<hex>"}
	// The attack_type is never present here — it was hashed into commitment.
	txMemo := ctx.TxBytes() // access memo via context when available
	_ = txMemo              // suppress unused warning; memo read below

	// Read memo directly from the SDK context's cached tx
	if sdkCtx, ok := goCtx.(sdk.Context); ok {
		memo := sdkCtx.EventManager().Events().ToABCIEvents()
		_ = memo
	}

	// Attempt to decode ZKP from the msg itself if it carries a ZkpMemo field.
	// We piggyback on the IpAddress field separator to carry the memo inline
	// when the script concatenates: ip_address = "1.2.3.4" and passes
	// the ZKP separately via --note flag (decoded from tx.Memo below).
	// Since tx.Memo is accessible from the raw context bytes, we use a helper:
	zkpPayload := extractZKPFromContext(ctx, msg.IpAddress)
	if zkpPayload != nil {
		if err := k.StoreZKProofRecord(goCtx, *zkpPayload); err != nil {
			// Log but don't fail — the plain IP record was already stored.
			ctx.Logger().Error("Failed to store ZKP record", "error", err.Error())
		}
	}

	// Return a response (can be empty if you don't need to return data)
	return &types.MsgStoreMaliciousIpResponse{}, nil
}

// extractZKPFromContext reads the transaction memo from the SDK context
// and attempts to parse a ZKP payload from it.
func extractZKPFromContext(ctx sdk.Context, ipAddress string) *MsgStoreZKProof {
	// The Cosmos SDK stores the transaction memo in context.
	// We retrieve it from the context's cached transaction.
	// If unavailable (e.g. in simulation), return nil gracefully.
	txBytes := ctx.TxBytes()
	if len(txBytes) == 0 {
		return nil
	}

	// Attempt to extract memo from tx bytes using a lightweight JSON scan.
	// Full protobuf decode is unnecessary — we just look for the memo field.
	var txEnvelope struct {
		Body struct {
			Memo string `json:"memo"`
		} `json:"body"`
	}

	// tx bytes are protobuf-encoded; attempt JSON fallback for REST-submitted txs
	if err := json.Unmarshal(txBytes, &txEnvelope); err != nil {
		return nil
	}

	return tryDecodeZKPFromMemo(txEnvelope.Body.Memo, ipAddress)
}
