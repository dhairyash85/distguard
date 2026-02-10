package threatintel

import (
	"math/rand"

	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	threatintelsimulation "cybersecurity/x/threatintel/simulation"
	"cybersecurity/x/threatintel/types"
)

// GenerateGenesisState creates a randomized GenState of the module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	accs := make([]string, len(simState.Accounts))
	for i, acc := range simState.Accounts {
		accs[i] = acc.Address.String()
	}
	threatintelGenesis := types.GenesisState{
		Params: types.DefaultParams(),
	}
	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(&threatintelGenesis)
}

// RegisterStoreDecoder registers a decoder.
func (am AppModule) RegisterStoreDecoder(_ simtypes.StoreDecoderRegistry) {}

// WeightedOperations returns the all the gov module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	operations := make([]simtypes.WeightedOperation, 0)
	const (
		opWeightMsgSubmitThreatReport          = "op_weight_msg_threatintel"
		defaultWeightMsgSubmitThreatReport int = 100
	)

	var weightMsgSubmitThreatReport int
	simState.AppParams.GetOrGenerate(opWeightMsgSubmitThreatReport, &weightMsgSubmitThreatReport, nil,
		func(_ *rand.Rand) {
			weightMsgSubmitThreatReport = defaultWeightMsgSubmitThreatReport
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgSubmitThreatReport,
		threatintelsimulation.SimulateMsgSubmitThreatReport(am.authKeeper, am.bankKeeper, am.keeper, simState.TxConfig),
	))
	const (
		opWeightMsgStoreMaliciousIp          = "op_weight_msg_threatintel"
		defaultWeightMsgStoreMaliciousIp int = 100
	)

	var weightMsgStoreMaliciousIp int
	simState.AppParams.GetOrGenerate(opWeightMsgStoreMaliciousIp, &weightMsgStoreMaliciousIp, nil,
		func(_ *rand.Rand) {
			weightMsgStoreMaliciousIp = defaultWeightMsgStoreMaliciousIp
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgStoreMaliciousIp,
		threatintelsimulation.SimulateMsgStoreMaliciousIp(am.authKeeper, am.bankKeeper, am.keeper, simState.TxConfig),
	))

	return operations
}

// ProposalMsgs returns msgs used for governance proposals for simulations.
func (am AppModule) ProposalMsgs(simState module.SimulationState) []simtypes.WeightedProposalMsg {
	return []simtypes.WeightedProposalMsg{}
}
