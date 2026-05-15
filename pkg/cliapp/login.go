package cliapp

import (
	"github.com/spf13/cobra"
)

func loginCommand(rt runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the configured IdP",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := rt.profileResolver(cmd)
			if err != nil {
				return err
			}
			return rt.loginRunner(cmd.Context(), profile, cmd.OutOrStdout())
		},
	}
}
