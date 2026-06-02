package cliapp

import (
	"fmt"
	"slices"

	"github.com/atomicgravity/postern/internal/oauthlogin"
	"github.com/spf13/cobra"
)

const (
	loginNoBrowserFlag    = "no-browser"
	loginCallbackPortFlag = "callback-port"
)

func loginCommand(rt runtime) *cobra.Command {
	var (
		noBrowser    bool
		callbackPort int
	)

	command := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the configured IdP",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateCallbackPort(callbackPort); err != nil {
				return err
			}

			profile, err := rt.profileResolver(cmd)
			if err != nil {
				return err
			}

			return rt.loginRunner(cmd.Context(), profile, cmd.OutOrStdout(), loginOptions{
				NoBrowser:    noBrowser,
				CallbackPort: callbackPort,
			})
		},
	}

	command.Flags().BoolVar(&noBrowser, loginNoBrowserFlag, false,
		"don't open a browser; print the authorization URL and the loopback port to forward back (for headless / remote hosts)")
	command.Flags().IntVar(&callbackPort, loginCallbackPortFlag, 0,
		"pin the loopback callback port to a single registered port; 0 tries the full set in order")

	return command
}

// validateCallbackPort rejects a pinned --callback-port that isn't one of
// the registered loopback ports. Binding an unregistered port would build
// a redirect URI the IdP's allowlist rejects, so failing here gives a
// clearer error than the IdP's redirect_uri_mismatch.
func validateCallbackPort(port int) error {
	if port == 0 {
		return nil
	}

	allowed := oauthlogin.AllowedCallbackPorts()
	if slices.Contains(allowed, port) {
		return nil
	}

	return fmt.Errorf("--%s %d is not a registered callback port (allowed: %d-%d)",
		loginCallbackPortFlag, port, allowed[0], allowed[len(allowed)-1])
}
