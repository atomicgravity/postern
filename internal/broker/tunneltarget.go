package broker

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	// ErrTunnelingAllowedRoleARNsRequired is returned by NewTunnelIssuer when
	// TargetFromRegistry is on with no allowed role ARNs: without an allowlist
	// any registry writer could point the broker at an arbitrary role.
	ErrTunnelingAllowedRoleARNsRequired = errors.New("tunneling allowed role ARNs are required when targeting from the registry")
	// ErrTunnelingAllowedRoleARNInvalid is returned by NewTunnelIssuer for an
	// entry ValidAllowedRoleARN rejects.
	ErrTunnelingAllowedRoleARNInvalid = errors.New("tunneling allowed role ARN is invalid")
)

var (
	// IAM role ARN in the commercial partition; the role name may carry a
	// path. Other partitions are rejected: the broker's STS client only
	// reaches its own partition.
	tunnelRoleARNPattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
	// AWS region code: us-east-1, ap-southeast-2, eu-central-1. The CLI
	// interpolates it into the data-plane URL it dials.
	tunnelRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	// Allowlist entry: a concrete account, with `*` allowed only in the role
	// name. Excludes `,` (the env var is comma-joined) and `?` (an IAM
	// wildcard globMatch doesn't implement).
	allowedRoleARNPattern = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=.@_/*-]+$`)
)

// maxAuditTargetRunes caps unvalidated record values on a denial's audit
// row and log detail; IAM role ARNs top out at 2048 characters.
const maxAuditTargetRunes = 2048

// ValidAllowedRoleARN reports whether entry is a usable
// tunneling.allowed_role_arns entry: a commercial-partition IAM role ARN
// with a concrete 12-digit account, `*` wildcards only in the role name, and
// no `,` or `?`.
func ValidAllowedRoleARN(entry string) bool {
	return allowedRoleARNPattern.MatchString(entry)
}

// tunnelTargetDenial is a registry-targeting rejection: the audit reason,
// the engineer-facing error, and the operator-facing detail for the log.
// target is what the record asked for, set for an invalid or unlisted
// target so the audit row can record it; values that aren't strings stay
// empty, and the rest are capped at maxAuditTargetRunes since they haven't
// passed validation.
type tunnelTargetDenial struct {
	reason string
	err    error
	detail string
	target *TunnelTarget
}

// resolveTunnelTarget reads the tunnel target from the device record and
// checks it against the allowlist. There is no fallback to the broker's own
// account: a device without a target is not tunnel-reachable.
func resolveTunnelTarget(device DeviceRecord, allowedRoleARNs []string) (*TunnelTarget, *tunnelTargetDenial) {
	roleARN, hasRole, roleIsString := tunnelTargetAttribute(device.Attributes, TunnelRoleARNAttribute)
	region, hasRegion, regionIsString := tunnelTargetAttribute(device.Attributes, TunnelRegionAttribute)

	attempted := &TunnelTarget{
		RoleARN: TruncateRunes(roleARN, maxAuditTargetRunes),
		Region:  TruncateRunes(region, maxAuditTargetRunes),
	}
	invalid := func(detail string) *tunnelTargetDenial {
		return &tunnelTargetDenial{
			reason: DenyReasonTunnelTargetInvalid,
			err:    Error{StatusCode: http.StatusInternalServerError, Message: "device tunnel target is invalid; contact your operator"},
			detail: detail,
			target: attempted,
		}
	}

	switch {
	case !hasRole && !hasRegion:
		return nil, &tunnelTargetDenial{
			reason: DenyReasonTunnelTargetMissing,
			err:    Error{StatusCode: http.StatusConflict, Message: "device has no tunnel target; reach it over the LAN or contact your operator"},
			detail: "device record has neither " + TunnelRoleARNAttribute + " nor " + TunnelRegionAttribute,
		}
	case !hasRole:
		return nil, invalid("device record has " + TunnelRegionAttribute + " but no " + TunnelRoleARNAttribute)
	case !hasRegion:
		return nil, invalid("device record has " + TunnelRoleARNAttribute + " but no " + TunnelRegionAttribute)
	case !roleIsString:
		return nil, invalid(TunnelRoleARNAttribute + " is not a string")
	case !regionIsString:
		return nil, invalid(TunnelRegionAttribute + " is not a string")
	case !tunnelRoleARNPattern.MatchString(roleARN):
		return nil, invalid(fmt.Sprintf("%s %q is not a commercial-partition IAM role ARN", TunnelRoleARNAttribute, attempted.RoleARN))
	case !tunnelRegionPattern.MatchString(region):
		return nil, invalid(fmt.Sprintf("%s %q is not an AWS region code", TunnelRegionAttribute, attempted.Region))
	}

	if !roleARNAllowed(roleARN, allowedRoleARNs) {
		return nil, &tunnelTargetDenial{
			reason: DenyReasonTunnelRoleNotAllowed,
			err:    Error{StatusCode: http.StatusForbidden, Message: "device tunnel target role is not allowed by this broker"},
			detail: fmt.Sprintf("%s %q matches no allowed role ARN", TunnelRoleARNAttribute, attempted.RoleARN),
			target: attempted,
		}
	}

	return &TunnelTarget{RoleARN: roleARN, Region: region}, nil
}

// tunnelTargetAttribute reports whether key is set (non-empty) and whether
// its value is a string. Empty strings count as unset, matching how the
// registries drop them.
func tunnelTargetAttribute(attributes map[string]any, key string) (value string, present bool, isString bool) {
	raw, ok := attributes[key]
	if !ok || raw == nil {
		return "", false, false
	}
	text, isString := raw.(string)
	if !isString {
		return "", true, false
	}
	text = strings.TrimSpace(text)
	return text, text != "", true
}

// roleARNAllowed matches roleARN against exact ARNs or `*` globs. `*` spans
// any run of characters, including `/`, as in IAM resource ARNs.
func roleARNAllowed(roleARN string, allowed []string) bool {
	for _, pattern := range allowed {
		if globMatch(pattern, roleARN) {
			return true
		}
	}
	return false
}

// globMatch is a `*`-only wildcard match with backtracking to the last star.
func globMatch(pattern, value string) bool {
	p, v := 0, 0
	star, mark := -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, v
			p++
		case p < len(pattern) && pattern[p] == value[v]:
			p++
			v++
		case star >= 0:
			p = star + 1
			mark++
			v = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// validateAllowedRoleARNs applies ValidAllowedRoleARN to every entry; an
// empty list is the caller's check.
func validateAllowedRoleARNs(entries []string) error {
	var errs []error
	for index, entry := range entries {
		if !ValidAllowedRoleARN(entry) {
			errs = append(errs, fmt.Errorf("%w: [%d] %q", ErrTunnelingAllowedRoleARNInvalid, index, entry))
		}
	}
	return errors.Join(errs...)
}
