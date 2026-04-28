package keeper

import (
	"context"
	"encoding/json"

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

	// ── Scan plain malicious IP records (prefix 0x01) ─────────────────────────
	ipPrefix := types.MaliciousIpKeyPrefix
	iterator, err := store.Iterator(ipPrefix, append(ipPrefix, 0xff))
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		ip := string(iterator.Value())
		ips = append(ips, ip)
	}

	// ── Scan ZKP records (prefix 0x02) — add IPs not already in the list ────
	// ZKP records are keyed by IP address so each IP appears at most once.
	zkpPrefix := types.ZKProofKeyPrefix
	zkpIter, err := store.Iterator(zkpPrefix, append(zkpPrefix, 0xff))
	if err != nil {
		return nil, err
	}
	defer zkpIter.Close()

	ipSet := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ipSet[ip] = struct{}{}
	}

	for ; zkpIter.Valid(); zkpIter.Next() {
		var record ZKProofRecord
		if err := json.Unmarshal(zkpIter.Value(), &record); err != nil {
			continue // skip malformed records
		}
		if _, exists := ipSet[record.IpAddress]; !exists {
			ips = append(ips, record.IpAddress)
			ipSet[record.IpAddress] = struct{}{}
		}
	}

	return &types.QueryListMaliciousIpsResponse{
		Ips: ips,
	}, nil
}
