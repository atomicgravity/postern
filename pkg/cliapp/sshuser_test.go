package cliapp

import (
	"path/filepath"
	"testing"

	"github.com/atomicgravity/postern/internal/sshconf"
)

// TestResolveUserPrecedence pins the four-tier precedence (flag >
// persistent ssh.conf stanza > profile default > built-in default)
// that addhost, ssh, scp, and tunnel share, plus the explicit/implicit
// signal ssh / scp use to decide whether to emit -l / -o User=.
func TestResolveUserPrecedence(t *testing.T) {
	const device = "device-1234"

	cases := []struct {
		name         string
		flagUser     string
		seedStanza   bool
		stanzaUser   string
		profile      Profile
		want         string
		wantExplicit bool
	}{
		{
			name:         "built-in-default-when-nothing-set",
			want:         DefaultSSHUser,
			wantExplicit: false,
		},
		{
			name:         "profile-default-overrides-built-in",
			profile:      Profile{DefaultSSHUser: "ops"},
			want:         "ops",
			wantExplicit: true,
		},
		{
			name:         "profile-explicit-engineer-is-still-explicit",
			profile:      Profile{DefaultSSHUser: DefaultSSHUser},
			want:         DefaultSSHUser,
			wantExplicit: true,
		},
		{
			name:         "persistent-stanza-overrides-profile",
			seedStanza:   true,
			stanzaUser:   "fleet-admin",
			profile:      Profile{DefaultSSHUser: "ops"},
			want:         "fleet-admin",
			wantExplicit: true,
		},
		{
			name:         "stanza-explicit-engineer-is-still-explicit",
			seedStanza:   true,
			stanzaUser:   DefaultSSHUser,
			want:         DefaultSSHUser,
			wantExplicit: true,
		},
		{
			name:         "flag-overrides-everything",
			flagUser:     "root",
			seedStanza:   true,
			stanzaUser:   "fleet-admin",
			profile:      Profile{DefaultSSHUser: "ops"},
			want:         "root",
			wantExplicit: true,
		},
		{
			name:         "flag-with-whitespace-is-trimmed-then-used",
			flagUser:     "  root  ",
			want:         "root",
			wantExplicit: true,
		},
		{
			name:         "blank-flag-falls-through-to-default",
			flagUser:     "   ",
			want:         DefaultSSHUser,
			wantExplicit: false,
		},
		{
			name:         "profile-whitespace-only-falls-through-to-default",
			profile:      Profile{DefaultSSHUser: "   "},
			want:         DefaultSSHUser,
			wantExplicit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ssh.conf")
			writer := sshconf.NewWriter(path)
			if tc.seedStanza {
				if err := writer.Upsert(sshconf.Stanza{
					Device:          device,
					User:            tc.stanzaUser,
					IdentityFile:    "/seed/key",
					CertificateFile: "/seed/" + device + ".cert",
				}); err != nil {
					t.Fatalf("seed Upsert() error = %v", err)
				}
			}

			got, gotExplicit := resolveUser(writer, device, tc.flagUser, ResolvedProfile{Profile: tc.profile})
			if got != tc.want || gotExplicit != tc.wantExplicit {
				t.Fatalf("resolveUser() = (%q, %v), want (%q, %v)", got, gotExplicit, tc.want, tc.wantExplicit)
			}
		})
	}
}

// TestResolveUserNilWriter covers the "writer couldn't be opened" path
// callers fall into when openSSHConfWriter fails. resolveUser must not
// panic; it simply skips the persistent-stanza tier.
func TestResolveUserNilWriter(t *testing.T) {
	got, explicit := resolveUser(nil, "device-1234", "", ResolvedProfile{Profile: Profile{DefaultSSHUser: "ops"}})
	if got != "ops" || !explicit {
		t.Fatalf("resolveUser(nil writer) = (%q, %v), want (%q, %v)", got, explicit, "ops", true)
	}
}
