package registry

import (
	"net/http"
	"regexp"

	"github.com/atomicgravity/postern/internal/broker"
)

// serialPattern bounds the canonical hardware-serial format the broker
// embeds into the SSH cert's ValidPrincipals (`device-{serial}-operator`).
// Restricting to `[A-Za-z0-9_.-]` keeps the principal grep-friendly in
// the device-side AuthorizedPrincipalsFile and rejects whitespace, NUL,
// shell metas, and BIDI/control characters that could either smuggle a
// different principal past the on-device match or trip log-injection in
// audit consumers. 64 runes is a generous ceiling for real hardware
// serials.
var serialPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// validateSerial guards the post-resolve hand-off between Registry and the
// rest of the cert-mint pipeline. A registry compromise (or a bug in the
// operator's inventory service) is contained here: malformed serials fail
// the broker request as a registry-side failure rather than landing in a
// cert principal.
func validateSerial(serial string) error {
	if !serialPattern.MatchString(serial) {
		return broker.Error{StatusCode: http.StatusBadGateway, Message: "registry returned malformed serial"}
	}
	return nil
}
