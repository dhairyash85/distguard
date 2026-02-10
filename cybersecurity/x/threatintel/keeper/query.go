package keeper

import (
	"context"

	"cybersecurity/x/threatintel/types"

	storetypes "cosmossdk.io/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ types.QueryServer = queryServer{}

// NewQueryServerImpl returns an implementation of the QueryServer interface
// for the provided Keeper.
func NewQueryServerImpl(k Keeper) types.QueryServer {
	return queryServer{k}
}

type queryServer struct {
	k Keeper
}


// ListMaliciousIps implements the Query/ListMaliciousIps gRPC method.
func (k queryServer) ListMaliciousIps(goCtx context.Context, req *types.QueryListMaliciousIpsRequest) (*types.QueryListMaliciousIpsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	store := k.k.storeService.OpenKVStore(ctx)
	var ips []string

	// Use the store's native iterator method, which is guaranteed to be compatible.
	iterator, err := store.Iterator(types.MaliciousIpKeyPrefix, storetypes.PrefixEndBytes(types.MaliciousIpKeyPrefix))
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		ip := string(iterator.Value())
		ips = append(ips, ip)
	}

	return &types.QueryListMaliciousIpsResponse{Ips: ips}, nil
}
