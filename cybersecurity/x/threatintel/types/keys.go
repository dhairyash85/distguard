package types

import "cosmossdk.io/collections"

const (
	// ModuleName defines the module name
	ModuleName = "threatintel"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// GovModuleName duplicates the gov module's name to avoid a dependency with it.
	// It should be synced with the gov module's name if it is ever changed.
	// See: https://github.com/cosmos/cosmos-sdk/blob/v0.52.0-beta.2/x/gov/types/keys.go
	GovModuleName = "gov"
)

// ParamsKey is the prefix to retrieve all Params
var ParamsKey = collections.NewPrefix("p_threatintel")

// --- Add this block for your entity keys ---
var (
	// MaliciousIpKeyPrefix is the prefix to retrieve all malicious IPs.
	// We use a byte slice (like 0x01) to distinguish it from other data types.
	MaliciousIpKeyPrefix = []byte{0x01}
)
