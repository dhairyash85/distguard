package keeper

import (
	"context"
	"cybersecurity/x/threatintel/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) ListMaliciousIps(goCtx context.Context, req *types.QueryListMaliciousIpsRequest) (*types.QueryListMaliciousIpsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	store := k.storeService.OpenKVStore(goCtx)
	
	var ips []string
	
	// Iterate through all keys starting with "malicious_ip:"
	prefix := []byte("malicious_ip:")
	iterator, err := store.Iterator(prefix, append(prefix, 0xff))
		if err != nil {
    		return nil, err
			}
	defer iterator.Close()
	
	for ; iterator.Valid(); iterator.Next() {
		ip := string(iterator.Value())
		ips = append(ips, ip)
	}

	return &types.QueryListMaliciousIpsResponse{
		Ips: ips,
	}, nil
}
