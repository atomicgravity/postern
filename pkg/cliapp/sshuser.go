package cliapp

import (
	"strings"

	"github.com/atomicgravity/postern/internal/sshconf"
)

// resolveUser is the user-resolution chokepoint shared by add-host, ssh,
// scp, and tunnel. Returns (user, explicit). Tiers, highest first:
//
//  1. --user flag
//  2. User directive of the persistent <device> stanza in ssh.conf
//  3. profile.DefaultSSHUser (the `default_ssh_user:` YAML key)
//  4. DefaultSSHUser ("engineer") fallback — implicit
//
// ssh / scp use the explicit bool to decide whether to emit -l / -o User=;
// the implicit-only case is left as no-signal so a `Host *` wildcard User
// directive in ~/.ssh/config keeps applying. Add-host and tunnel always
// want a concrete value and discard the bool.
//
// Depends on Profile.WithDefaults NOT injecting DefaultSSHUser — otherwise
// tier 3 and tier 4 are indistinguishable. resolveUser owns the entire
// fallback chain.
func resolveUser(writer *sshconf.Writer, device, flagUser string, profile ResolvedProfile) (string, bool) {
	if u := strings.TrimSpace(flagUser); u != "" {
		return u, true
	}
	if writer != nil {
		if u, found, err := writer.LookupUser(device); err == nil && found {
			return u, true
		}
	}
	if configured := strings.TrimSpace(profile.Profile.DefaultSSHUser); configured != "" {
		return configured, true
	}
	return DefaultSSHUser, false
}

// resolveCommandUser layers ssh / scp's passthrough detection on top of
// resolveUser. skipDashL=true for scp because scp's -l is bandwidth-limit,
// not login name.
//
// Returns "" (skip emitting the user flag) when the passthrough already
// names a user OR when resolveUser was implicit-only. Otherwise returns the
// resolved user — even "engineer" is honored if the engineer chose it.
func resolveCommandUser(rt runtime, deviceID, flagUser string, profile ResolvedProfile, passthrough []string, skipDashL bool) string {
	if u := strings.TrimSpace(flagUser); u != "" {
		return u
	}
	if passthroughHasUserInfo(passthrough, skipDashL) {
		return ""
	}

	writer, _ := rt.openSSHConfWriter()
	resolved, explicit := resolveUser(writer, deviceID, "", profile)
	if !explicit {
		return ""
	}
	return resolved
}

// passthroughHasUserInfo reports whether the engineer's passthrough already
// pins a user via -l, -o User=, or user@host. Skips past flag-with-arg pairs
// via sshFlagConsumesArg so a value containing '@' (e.g.
// `-o ProxyCommand=ssh root@bastion ...`) doesn't false-positive.
func passthroughHasUserInfo(passthrough []string, skipDashL bool) bool {
	for i := 0; i < len(passthrough); i++ {
		token := passthrough[i]
		if token == "" {
			continue
		}

		if !skipDashL {
			if token == "-l" {
				return true
			}
			if strings.HasPrefix(token, "-l") && len(token) > 2 {
				return true
			}
		}
		if token == "-o" && i+1 < len(passthrough) {
			if strings.HasPrefix(strings.TrimSpace(passthrough[i+1]), "User=") {
				return true
			}
			i++
			continue
		}
		if strings.HasPrefix(token, "-oUser=") {
			return true
		}

		if token[0] == '-' {
			if sshFlagConsumesArg(token) && i+1 < len(passthrough) {
				i++
			}
			continue
		}

		if strings.Contains(token, "@") {
			return true
		}
	}
	return false
}
