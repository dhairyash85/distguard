package keeper

import (
	"context"

	"cybersecurity/x/threatintel/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (q queryServer) ListThreatReports(ctx context.Context, req *types.QueryListThreatReportsRequest) (*types.QueryListThreatReportsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	// TODO: Process the query

	return &types.QueryListThreatReportsResponse{}, nil
}
