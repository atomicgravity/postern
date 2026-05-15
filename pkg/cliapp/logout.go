package cliapp

import (
	"fmt"

	"github.com/spf13/cobra"
)

func logoutCommand(rt runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear cached credentials for a profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileName := commandProfileName(cmd, rt.lookupEnv)
			if err := rt.deleteToken(profileName); err != nil {
				return fmt.Errorf("logout profile %q: %w", profileName, err)
			}

			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Logged out of profile %q\n", profileName)
			return err
		},
	}
}
