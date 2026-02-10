package simulation

import (
	"math/rand"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"

	"cybersecurity/x/threatintel/keeper"
	"cybersecurity/x/threatintel/types"
)

func SimulateMsgStoreMaliciousIp(
	ak types.AuthKeeper,
	bk types.BankKeeper,
	k keeper.Keeper,
	txGen client.TxConfig,
) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string,
	) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		simAccount, _ := simtypes.RandomAcc(r, accs)
		msg := &types.MsgStoreMaliciousIp{
			Creator: simAccount.Address.String(),
		}

		// TODO: Handle the StoreMaliciousIp simulation

		return simtypes.NoOpMsg(types.ModuleName, sdk.MsgTypeURL(msg), "StoreMaliciousIp simulation not implemented"), nil, nil
	}
}
