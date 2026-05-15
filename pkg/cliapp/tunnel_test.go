package cliapp

import "testing"

// TestPassthroughHasUserInfo covers the flag walker that decides
// whether the engineer's passthrough already pins a user. The walker
// must skip flag-with-arg pairs cleanly so values that happen to
// contain '@' don't false-positive as user@host. The skipDashL flag
// switches between ssh semantics (-l is login name) and scp semantics
// (-l is bandwidth-limit).
func TestPassthroughHasUserInfo(t *testing.T) {
	cases := []struct {
		name      string
		argv      []string
		skipDashL bool
		want      bool
	}{
		{name: "ssh/empty", argv: nil, want: false},
		{name: "ssh/bare-host", argv: []string{"192.168.1.42"}, want: false},
		{name: "ssh/user-at-host", argv: []string{"alice@192.168.1.42"}, want: true},
		{name: "ssh/dash-l-user", argv: []string{"-l", "alice", "192.168.1.42"}, want: true},
		{name: "ssh/dash-l-user-after-intervening-flag", argv: []string{"-v", "-l", "alice", "192.168.1.42"}, want: true},
		{name: "ssh/dash-l-combined", argv: []string{"-lalice", "192.168.1.42"}, want: true},
		{name: "ssh/dash-o-user-equals", argv: []string{"-o", "User=alice", "192.168.1.42"}, want: true},
		{name: "ssh/dash-o-user-combined", argv: []string{"-oUser=alice", "192.168.1.42"}, want: true},
		{
			// -o ServerAliveInterval=30 followed by a bare host
			// must not trigger; the engineer hasn't pinned a user.
			name: "ssh/dash-o-other-then-bare-host",
			argv: []string{"-o", "ServerAliveInterval=30", "192.168.1.42"},
			want: false,
		},
		{
			// A value with '@' attached to a flag-consuming pair
			// must not be mistaken for user@host on the positional.
			name: "ssh/proxy-command-with-at-symbol-is-not-positional",
			argv: []string{"-o", "ProxyCommand=ssh root@bastion -W %h:%p", "device-1234"},
			want: false,
		},
		{
			// `-p 2222 alice@host` — port flag eats 2222, the
			// last positional is user@host so it returns true.
			name: "ssh/port-flag-then-user-at-host",
			argv: []string{"-p", "2222", "alice@host"},
			want: true,
		},
		{
			// Flags only; no positional, no -l, no -o User=.
			name: "ssh/flags-only-no-user",
			argv: []string{"-v", "-A"},
			want: false,
		},
		{
			// scp's `-l 1000` is bandwidth-limit, not login. With
			// skipDashL=true the walker must NOT treat it as user
			// info; the next iteration drops past 1000 via
			// sshFlagConsumesArg.
			name:      "scp/dash-l-bandwidth-not-user",
			argv:      []string{"-l", "1000", "foo.txt", "dev-1:/tmp/"},
			skipDashL: true,
			want:      false,
		},
		{
			// scp's combined `-l1000` form is bandwidth, not user.
			name:      "scp/dash-l-combined-bandwidth-not-user",
			argv:      []string{"-l1000", "foo.txt", "dev-1:/tmp/"},
			skipDashL: true,
			want:      false,
		},
		{
			// scp still recognizes user@host:path in positionals.
			name:      "scp/user-at-host-path-positional",
			argv:      []string{"foo.txt", "alice@dev-1:/tmp/"},
			skipDashL: true,
			want:      true,
		},
		{
			// scp still recognizes -o User=alice.
			name:      "scp/dash-o-user-equals",
			argv:      []string{"-o", "User=alice", "foo.txt", "dev-1:/tmp/"},
			skipDashL: true,
			want:      true,
		},
		{
			// scp bandwidth-limit followed by user@host:path —
			// engineer typed the user explicitly, return true.
			name:      "scp/dash-l-bandwidth-then-user-at-host",
			argv:      []string{"-l", "1000", "alice@dev-1:/tmp/foo"},
			skipDashL: true,
			want:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passthroughHasUserInfo(tc.argv, tc.skipDashL)
			if got != tc.want {
				t.Fatalf("passthroughHasUserInfo(%v, skipDashL=%v) = %v, want %v", tc.argv, tc.skipDashL, got, tc.want)
			}
		})
	}
}
