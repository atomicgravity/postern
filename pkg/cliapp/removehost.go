package cliapp

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

func removeHostCommand(rt runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "remove-host <device-id>",
		Short: "Remove a device's stanza from the Postern-managed ssh-config",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemoveHost(cmd, rt, args[0])
		},
	}
}

// runRemoveHost deletes the Postern-managed stanza for deviceID. Engineer
// content outside the BEGIN/END markers is preserved verbatim by the
// writer; a missing stanza is a no-op (idempotent) with a friendly note.
func runRemoveHost(cmd *cobra.Command, rt runtime, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if err := validateMintDeviceID(deviceID); err != nil {
		return err
	}

	writer, err := rt.openSSHConfWriter()
	if err != nil {
		return err
	}

	before, err := writer.List()
	if err != nil {
		return fmt.Errorf("read %s: %w", writer.Path(), err)
	}

	if err := writer.Remove(deviceID); err != nil {
		return fmt.Errorf("update %s: %w", writer.Path(), err)
	}

	out := cmd.OutOrStdout()
	if slices.Contains(before, deviceID) {
		fmt.Fprintf(out, "Removed %s from %s.\n", deviceID, writer.Path())
	} else {
		fmt.Fprintf(out, "No stanza for %s in %s; nothing to remove.\n", deviceID, writer.Path())
	}
	return nil
}
