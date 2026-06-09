package cliapp

// Canonical flag names shared by ssh / scp / tunnel.
const (
	flagRefresh         = "refresh"
	flagTunnel          = "tunnel"
	flagMaxLifetime     = "max-lifetime"
	flagCertMaxLifetime = "cert-max-lifetime"
	flagUser            = "user"
	flagPortOnly        = "port-only"
	flagReap            = "reap"
	flagVerbose         = "verbose"
)

// sshIdentityArgs returns the identity / cert / cert-only-auth options
// every postern-built ssh / scp argv starts with. The pubkey-only pin
// defends against a misconfigured sshd advertising password or
// kbd-interactive methods.
func sshIdentityArgs(binary, keyPath, certPath string) []string {
	return []string{
		binary,
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
	}
}
