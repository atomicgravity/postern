package cliapp

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/spf13/cobra"
)

const (
	cacheDryRunFlag = "dry-run"
)

func cacheCommand(rt runtime) *cobra.Command {
	command := &cobra.Command{
		Use:   "cache",
		Short: "Inspect and prune the on-disk SSH cert cache",
	}
	command.AddCommand(cacheListCommand(rt))
	command.AddCommand(cachePruneCommand(rt))
	return command
}

func cacheListCommand(rt runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List cached cert entries for the current profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCacheList(cmd, rt, time.Now())
		},
	}
}

func cachePruneCommand(rt runtime) *cobra.Command {
	var dryRun bool

	command := &cobra.Command{
		Use:   "prune",
		Short: "Remove expired cert entries for the current profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCachePrune(cmd, rt, time.Now(), dryRun)
		},
	}
	command.Flags().BoolVar(&dryRun, cacheDryRunFlag, false, "list what would be pruned without acting")
	return command
}

// runCacheList renders cached entries as a human-readable table. Scripting
// callers parse cert files directly.
func runCacheList(cmd *cobra.Command, rt runtime, now time.Time) error {
	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	store, err := rt.openCertStore(profile.Name)
	if err != nil {
		return err
	}

	entries, err := store.ListEntries()
	if err != nil {
		return fmt.Errorf("list cache entries: %w", err)
	}

	return writeCacheList(cmd.OutOrStdout(), entries, now)
}

func writeCacheList(out io.Writer, entries []certcache.Entry, now time.Time) error {
	if len(entries) == 0 {
		_, err := fmt.Fprintln(out, "No cached certs.")
		return err
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "DEVICE\tVALID UNTIL\tTIME LEFT\tSERIAL\tKEY ID\tPRINCIPALS\tCERT PATH"); err != nil {
		return err
	}
	for _, entry := range entries {
		validUntil := entry.ValidBefore.UTC().Format(time.RFC3339)
		timeLeft := remainingDisplay(entry.ValidBefore, now)
		principals := strings.Join(entry.Principals, ",")
		if principals == "" {
			principals = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			entry.Device, validUntil, timeLeft, entry.SerialNumber, entry.KeyID, principals, entry.CertPath); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// remainingDisplay formats the TIME LEFT column; expired entries render as
// "EXPIRED" rather than negative durations.
func remainingDisplay(validBefore, now time.Time) string {
	if !validBefore.After(now) {
		return "EXPIRED"
	}
	return validBefore.Sub(now).Round(time.Second).String()
}

// runCachePrune removes expired cert files for the current profile;
// --dry-run reuses the same filter so output matches what prune would do.
func runCachePrune(cmd *cobra.Command, rt runtime, now time.Time, dryRun bool) error {
	profile, err := rt.profileResolver(cmd)
	if err != nil {
		return err
	}

	store, err := rt.openCertStore(profile.Name)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if dryRun {
		entries, err := store.ListEntries()
		if err != nil {
			return fmt.Errorf("list cache entries: %w", err)
		}
		expired := filterExpired(entries, now)
		if len(expired) == 0 {
			_, err := fmt.Fprintln(out, "No expired entries to prune.")
			return err
		}
		fmt.Fprintln(out, "Would remove:")
		for _, device := range expired {
			fmt.Fprintf(out, "  %s\n", device)
		}
		return nil
	}

	pruned, err := store.PruneExpired(now)
	if err != nil {
		return fmt.Errorf("prune expired entries: %w", err)
	}
	if len(pruned) == 0 {
		_, err := fmt.Fprintln(out, "No expired entries to prune.")
		return err
	}
	fmt.Fprintln(out, "Removed:")
	for _, device := range pruned {
		fmt.Fprintf(out, "  %s\n", device)
	}
	return nil
}

// filterExpired returns expired device ids. Mirrors Store.PruneExpired's
// filter so --dry-run can't diverge from a real prune.
func filterExpired(entries []certcache.Entry, now time.Time) []string {
	var expired []string
	for _, entry := range entries {
		if entry.ValidBefore.After(now) {
			continue
		}
		expired = append(expired, entry.Device)
	}
	return expired
}
