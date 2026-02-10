package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	// "github.com/cosmos/cosmos-sdk/client/flags"

	"cybersecurity/x/threatintel/types"
)

// GetQueryCmd returns the cli query commands for this module
func GetQueryCmd(queryRoute string) *cobra.Command {
	// Group threatintel queries under a subcommand
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      fmt.Sprintf("Querying commands for the %s module", types.ModuleName),
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	// Add the command to query module parameters
	cmd.AddCommand(CmdQueryParams())

	// Add the command to list malicious IPs
	cmdListMaliciousIps := &cobra.Command{
		Use:   "list-malicious-ips",
		Short: "Query a list of all malicious IPs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)

			params := &types.QueryListMaliciousIpsRequest{}

			res, err := queryClient.ListMaliciousIps(cmd.Context(), params)
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}
	cmd.AddCommand(cmdListMaliciousIps)

	// this line is used by starport scaffolding # 1

	return cmd
}
