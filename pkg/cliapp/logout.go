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

			// Resolve the profile to learn its token-store backend, but tolerate
			// failure: logout must still clear credentials when the config is
			// missing, incomplete, or names a profile that no longer exists (an
			// orphaned slot after a rename). On failure fall back to the bare
			// name, which selects the env-configured or default backend.
			resolved, err := rt.profileResolver(cmd)
			if err != nil {
				resolved = ResolvedProfile{Name: profileName}
			}

			if err := rt.deleteToken(resolved); err != nil {
				return fmt.Errorf("logout profile %q: %w", profileName, err)
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Logged out of profile %q\n", profileName)
			return err
		},
	}
}
