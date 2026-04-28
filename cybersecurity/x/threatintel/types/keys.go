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

// --- Key prefixes for on-chain data ---
var (
	// MaliciousIpKeyPrefix is the prefix for plain malicious IP records.
	// Byte 0x01 separates it from other data types in the store.
	MaliciousIpKeyPrefix = []byte{0x01}

	// ZKProofKeyPrefix is the prefix for ZKP-attested malicious IP records.
	// Stores { commitment, proof, nonce } alongside the IP address.
	// Byte 0x02 ensures no collision with MaliciousIpKeyPrefix.
	ZKProofKeyPrefix = []byte{0x02}
)
