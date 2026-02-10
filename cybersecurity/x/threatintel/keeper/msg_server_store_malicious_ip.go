package keeper

import (
	"context"

	"cybersecurity/x/threatintel/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// StoreMaliciousIp handles the logic for the StoreMaliciousIp transaction.
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

	// Return a response (can be empty if you don't need to return data)
	return &types.MsgStoreMaliciousIpResponse{}, nil
}
