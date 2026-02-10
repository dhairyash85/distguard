package keeper

import (
	"context"

	"cybersecurity/x/threatintel/types"

	errorsmod "cosmossdk.io/errors"
)

func (k msgServer) SubmitThreatReport(ctx context.Context, msg *types.MsgSubmitThreatReport) (*types.MsgSubmitThreatReportResponse, error) {
	if _, err := k.addressCodec.StringToBytes(msg.Creator); err != nil {
		return nil, errorsmod.Wrap(err, "invalid authority address")
	}

	// TODO: Handle the message

	return &types.MsgSubmitThreatReportResponse{}, nil
}
