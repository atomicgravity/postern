// Command timefix-apply is the unprivileged on-device verifier. Runs as the
// `timefix` system user under sshd's ForceCommand: generates a 32-byte
// nonce, emits it on stdout, reads the broker's JWS from stdin, validates
// it against the CA pubkeys + local serial + in-memory nonce, and exec's
// the privileged setter with the integer timestamp.
//
// Privilege split: this binary has zero caps; the setter at
// /usr/sbin/timefix-set-clock carries cap_sys_time+ep. The exec replaces
// this process so the setter's stdio stays connected to the SSH channel.
//
// Exit codes are a stable wire contract for on-device log analysis:
//
//	0 success (test-only path; production exec replaces the process)
//	2 bad input
//	3 alg/typ mismatch
//	4 signature verify failure
//	5 claim validation failure
//	6 setter exec failure
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// setterBinaryPath is the privileged setter. Compile-time pinned so a
// hostile sshd env-passthrough cannot redirect exec to an attacker binary.
// Install perms are root:timefix 0750 with cap_sys_time+ep.
const setterBinaryPath = "/usr/sbin/timefix-set-clock"

// defaultPrincipalsPath is the device's authoritative timefix principal.
// principals-init writes this at boot from the operator-chosen identifier;
// sshd reads the same file to admit cert principals, keeping the device's
// and verifier's notion of identity in lockstep.
const defaultPrincipalsPath = "/etc/ssh/authorized_principals/timefix"

// deps groups the verifier's I/O + exec seams for test substitution.
type deps struct {
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	Random         io.Reader
	Now            func() time.Time
	PrincipalsPath string
	CAPubPath      string

	// ExecSetter replaces the process with the privileged setter on
	// success. Production wraps syscall.Exec — only on failure does this
	// return; tests inject a recording stub.
	ExecSetter func(argv []string) error
}

func main() {
	d := deps{
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Random:         rand.Reader,
		Now:            func() time.Time { return time.Now().UTC() },
		PrincipalsPath: defaultPrincipalsPath,
		CAPubPath:      resolveCAPubPath(),
		ExecSetter:     execSetter,
	}
	os.Exit(run(d))
}

// run is the testable entrypoint, returning an exit code rather than
// calling os.Exit. The non-zero codes map to the package doc's failure
// classes.
func run(d deps) int {
	caPubKeys, err := loadCAPubKeys(d.CAPubPath)
	if err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: load CA pubkey: %v\n", err)
		return exitBadInput
	}

	serial, err := readPrincipalSerial(d.PrincipalsPath)
	if err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: read principal: %v\n", err)
		return exitBadInput
	}

	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(d.Random, nonceBytes); err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: generate nonce: %v\n", err)
		return exitBadInput
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	// Emit two newline-terminated lines on stdout before reading the JWS:
	//   line 1: <base64url nonce>
	//   line 2: device-clock: <RFC3339 UTC snapshot>
	// The "device-clock: " prefix is the disambiguator so future verifier
	// diagnostics on stdout can't be mistaken for the clock snapshot.
	// The clock is engineer-facing diagnostic only — the broker doesn't
	// see it and the verifier doesn't consult it for the now-bound check
	// (the payload's `now` carries the time-binding).
	if _, err := fmt.Fprintln(d.Stdout, nonce); err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: emit nonce: %v\n", err)
		return exitBadInput
	}
	if _, err := fmt.Fprintf(d.Stdout, "device-clock: %s\n", d.Now().UTC().Format(time.RFC3339)); err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: emit device-clock: %v\n", err)
		return exitBadInput
	}
	if f, ok := d.Stdout.(*os.File); ok {
		_ = f.Sync()
	}

	jws, err := readJWS(d.Stdin)
	if err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: read JWS: %v\n", err)
		return exitBadInput
	}

	result := verify(verifyParams{
		JWS:            jws,
		ExpectedSerial: serial,
		ExpectedNonce:  nonce,
		CAPublicKeys:   caPubKeys,
	})
	if result.ExitCode != exitSuccess {
		fmt.Fprintf(d.Stderr, "timefix-apply: verify: %v\n", result.Err)
		return result.ExitCode
	}

	// Production exec replaces the process; only test stubs return.
	argv := []string{"timefix-set-clock", strconv.FormatInt(result.Timestamp, 10)}
	if err := d.ExecSetter(argv); err != nil {
		fmt.Fprintf(d.Stderr, "timefix-apply: exec setter: %v\n", err)
		return exitSetterExecFailure
	}
	return exitSuccess
}

// execSetter is the production exec seam — syscall.Exec doesn't return on
// success. Errors map to exit 6.
func execSetter(argv []string) error {
	return syscall.Exec(setterBinaryPath, argv, os.Environ())
}

// readJWS reads the JWS Compact with a hard size cap (a real payload is
// ~400 bytes; the cap is 10x). Past the cap is bad input — the verifier
// can't distinguish flood from corruption.
func readJWS(r io.Reader) (string, error) {
	limited := io.LimitReader(r, MaxJWSBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	if len(buf) > MaxJWSBytes {
		return "", fmt.Errorf("input exceeds %d byte cap", MaxJWSBytes)
	}
	return strings.TrimRight(string(buf), "\r\n"), nil
}

// loadCAPubKeys reads the on-device CA pubkey file (OpenSSH authorized_keys
// format, the same file sshd reads as TrustedUserCAKeys) and returns every
// plain Ed25519 key in it. Every other line is skipped: other key types
// (including sk-ssh-ed25519) may be trusted by sshd, but the broker's signer
// is plain Ed25519 only, and a stray line must not take timefix down.
func loadCAPubKeys(path string) ([]ed25519.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var keys []ed25519.PublicKey
	// ParseAuthorizedKey skips comments, blanks and unparseable lines, and
	// errors only once no key line remains.
	for rest := contents; len(rest) > 0; {
		var pubKey ssh.PublicKey
		pubKey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		if pubKey.Type() != ssh.KeyAlgoED25519 {
			continue
		}
		cryptoPub, ok := pubKey.(ssh.CryptoPublicKey)
		if !ok {
			continue
		}
		edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			continue
		}
		keys = append(keys, edPub)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no ed25519 CA pubkey found", path)
	}
	return keys, nil
}

// readPrincipalSerial extracts the serial from the timefix
// authorized_principals file (`device-<serial>-timefix`). The first non-
// blank, non-comment line must match. The serial is what the verifier
// rebuilds expected aud + device_serial claims against.
func readPrincipalSerial(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		serial, ok := strings.CutPrefix(line, "device-")
		if !ok {
			return "", fmt.Errorf("%s: principal %q does not match `device-<serial>-timefix`", path, line)
		}
		serial, ok = strings.CutSuffix(serial, "-timefix")
		if !ok {
			return "", fmt.Errorf("%s: principal %q does not match `device-<serial>-timefix`", path, line)
		}
		if serial == "" {
			return "", fmt.Errorf("%s: empty serial in principal %q", path, line)
		}
		return serial, nil
	}
	return "", fmt.Errorf("%s: no `device-<serial>-timefix` principal found", path)
}
