package keeper

import (
	"context"

	"cybersecurity/x/threatintel/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	// Set the parameters for the module
	if err := k.Params.Set(ctx, genState.Params); err != nil {
		return err
	}

	return nil
}

// ExportGenesis returns the module's exported genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		return nil, err
	}

	genesis := types.DefaultGenesis()
	genesis.Params = params

	return genesis, nil
}
