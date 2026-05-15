package policy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
)

func TestNewAVPPolicyRejectsEmptyPolicyStoreID(t *testing.T) {
	_, err := NewAVPPolicy(&fakeAVPClient{}, "")
	if !errors.Is(err, ErrPolicyStoreIDRequired) {
		t.Fatalf("NewAVPPolicy() error = %v, want ErrPolicyStoreIDRequired", err)
	}
}

// TestAllowRejectsUnknownMode locks the dispatch-default: any mode the broker
// hasn't wired (anything other than ModeOperator / ModeTimefix) returns 501
// rather than silently defaulting to Allow. Don't delete; this is the load-
// bearing branch that protects against a future mode addition that forgets
// to wire its Cedar action.
func TestAllowRejectsUnknownMode(t *testing.T) {
	policy, err := NewAVPPolicy(&fakeAVPClient{}, "store-1")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	err = policy.Allow(context.Background(), broker.PolicyRequest{Mode: "unknown-mode"})
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusNotImplemented {
		t.Fatalf("Allow() error = %v, want %d broker.Error", err, http.StatusNotImplemented)
	}
}

// TestAllowMapsTimefixModeToMintTimefixCertAction locks the dispatch for the
// time-payload pipeline: ModeTimefix translates to Postern::Action::
// MintTimefixCert. Operators writing Cedar policies for timefix access bind
// to this action id; drifting the id would silently break those policies.
func TestAllowMapsTimefixModeToMintTimefixCertAction(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-42")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	request := validRequest()
	request.Mode = broker.ModeTimefix
	if err := policy.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("IsAuthorizedWithToken calls = %d, want %d", got, want)
	}
	if got, want := *fake.calls[0].Action.ActionId, "MintTimefixCert"; got != want {
		t.Fatalf("action id = %q, want %q", got, want)
	}
}

// TestAllowMapsTunnelModeToOpenTunnelAction locks the dispatch for the
// tunnel-open pipeline: ModeTunnel translates to Postern::Action::
// OpenTunnel. Operators writing Cedar policies for the firewalled-device
// path bind to this action id; drifting the id would silently break those
// policies.
func TestAllowMapsTunnelModeToOpenTunnelAction(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-43")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	request := validRequest()
	request.Mode = broker.ModeTunnel
	if err := policy.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("IsAuthorizedWithToken calls = %d, want %d", got, want)
	}
	if got, want := *fake.calls[0].Action.ActionId, "OpenTunnel"; got != want {
		t.Fatalf("action id = %q, want %q", got, want)
	}
}

// TestAllowEmitsPolicyContextLifetime locks the Cedar context overlay:
// PolicyRequest.Context["requested_max_lifetime_minutes"] flows into the
// AVP context map as a Long attribute so operators can author per-fleet
// TTL ceilings with Cedar `when` clauses.
func TestAllowEmitsPolicyContextLifetime(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-tunnel")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	request := validRequest()
	request.Mode = broker.ModeTunnel
	request.Context = map[string]any{
		"requested_max_lifetime_minutes": int64(120),
	}
	if err := policy.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	contextMap, ok := fake.calls[0].Context.(*types.ContextDefinitionMemberContextMap)
	if !ok {
		t.Fatalf("context = %T, want *ContextDefinitionMemberContextMap", fake.calls[0].Context)
	}
	attr, present := contextMap.Value["requested_max_lifetime_minutes"]
	if !present {
		t.Fatalf("context.requested_max_lifetime_minutes missing: %#v", contextMap.Value)
	}
	long, ok := attr.(*types.AttributeValueMemberLong)
	if !ok {
		t.Fatalf("requested_max_lifetime_minutes type = %T, want *AttributeValueMemberLong", attr)
	}
	if got, want := long.Value, int64(120); got != want {
		t.Fatalf("requested_max_lifetime_minutes = %d, want %d", got, want)
	}
}

// TestAllowContextOverlayDoesNotShadowReservedKeys pins F-TN-A-5: the
// per-endpoint PolicyRequest.Context overlay must not let a request-
// supplied entry clobber the canonical baseline attributes (source_ip,
// user_agent, request_id, timestamp). A regression that flipped the
// overlay order — or that wrote the canonical fields before the
// per-endpoint loop — would let an engineer-influenced Context map
// override the broker-resolved source_ip / request_id used in Cedar
// policy evaluation. Parallels the entities() shadow guard for
// serial / friendly_id that TestAllowPassesPrincipalActionResourceShape
// pins.
func TestAllowContextOverlayDoesNotShadowReservedKeys(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-shadow")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	request := validRequest()
	request.Context = map[string]any{
		"source_ip":  "1.2.3.4",
		"user_agent": "attacker-agent/1.0",
		"request_id": "evil-request-id",
		"timestamp":  "1970-01-01T00:00:00Z",
	}
	if err := policy.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}

	contextMap, ok := fake.calls[0].Context.(*types.ContextDefinitionMemberContextMap)
	if !ok {
		t.Fatalf("context = %T, want *ContextDefinitionMemberContextMap", fake.calls[0].Context)
	}
	if got := stringAttr(t, contextMap.Value["source_ip"]); got != request.SourceIP {
		t.Fatalf("context.source_ip = %q, want %q (shadowed by Context overlay?)", got, request.SourceIP)
	}
	if got := stringAttr(t, contextMap.Value["user_agent"]); got != request.UserAgent {
		t.Fatalf("context.user_agent = %q, want %q (shadowed by Context overlay?)", got, request.UserAgent)
	}
	if got := stringAttr(t, contextMap.Value["request_id"]); got != request.RequestID {
		t.Fatalf("context.request_id = %q, want %q (shadowed by Context overlay?)", got, request.RequestID)
	}
	if got, want := datetimeAttr(t, contextMap.Value["timestamp"]), request.Timestamp.UTC().Format(time.RFC3339); got != want {
		t.Fatalf("context.timestamp = %q, want %q (shadowed by Context overlay?)", got, want)
	}
}

func TestAllowReturnsNilOnDecisionAllow(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-1")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	if err := policy.Allow(context.Background(), validRequest()); err != nil {
		t.Fatalf("Allow() error = %v, want nil", err)
	}
	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("IsAuthorizedWithToken calls = %d, want %d", got, want)
	}
}

// TestAllowOmitsTimestampWhenZero locks the contextMap defense: a caller that
// forgets to populate PolicyRequest.Timestamp gets the field skipped rather
// than a nonsense "0001-01-01T00:00:00Z" attribute leaking into AVP context.
func TestAllowOmitsTimestampWhenZero(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-1")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	request := validRequest()
	request.Timestamp = time.Time{}
	if err := policy.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	contextMap, ok := fake.calls[0].Context.(*types.ContextDefinitionMemberContextMap)
	if !ok {
		t.Fatalf("context = %T, want *ContextDefinitionMemberContextMap", fake.calls[0].Context)
	}
	if _, present := contextMap.Value["timestamp"]; present {
		t.Fatalf("context.timestamp present for zero PolicyRequest.Timestamp: %#v", contextMap.Value)
	}
}

func TestAllowMaps403OnDecisionDeny(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionDeny}
	policy, err := NewAVPPolicy(fake, "store-1")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	err = policy.Allow(context.Background(), validRequest())
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusForbidden {
		t.Fatalf("Allow() error = %v, want %d broker.Error", err, http.StatusForbidden)
	}
}

func TestAllowPropagatesAVPError(t *testing.T) {
	want := errors.New("AVP is unavailable")
	fake := &fakeAVPClient{err: want}
	policy, err := NewAVPPolicy(fake, "store-1")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	err = policy.Allow(context.Background(), validRequest())
	if !errors.Is(err, want) {
		t.Fatalf("Allow() error = %v, want errors.Is(%v)", err, want)
	}
	if !strings.Contains(err.Error(), "policy:") {
		t.Fatalf("Allow() error = %q, want policy: prefix", err.Error())
	}
}

// TestAllowPassesPrincipalActionResourceShape locks the AVP request shape: the
// action stays Postern::Action::MintOperatorCert, the resource is the device
// by Serial, the access token rides through, and the policy store ID matches
// the constructor input. If any of these drift, AVP policies that operators
// have written to the documented shape stop matching.
func TestAllowPassesPrincipalActionResourceShape(t *testing.T) {
	fake := &fakeAVPClient{decision: types.DecisionAllow}
	policy, err := NewAVPPolicy(fake, "store-42")
	if err != nil {
		t.Fatalf("NewAVPPolicy() error = %v", err)
	}

	request := validRequest()
	request.Device.Attributes = map[string]any{
		"fleet":             "prod",
		" ":                 "ignored",
		"blank":             " ",
		"production":        true,
		"firmware_revision": int64(42),
		"unsupported":       []string{"dropped"},
		// Attempted shadowing of the canonical Device entity fields.
		// The post-loop write in entities() must defeat these.
		"serial":      "ATTACKER-OVERRIDE",
		"friendly_id": "attacker-override",
	}
	if err := policy.Allow(context.Background(), request); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}

	if got, want := len(fake.calls), 1; got != want {
		t.Fatalf("IsAuthorizedWithToken calls = %d, want %d", got, want)
	}
	input := fake.calls[0]
	if got, want := *input.PolicyStoreId, "store-42"; got != want {
		t.Fatalf("policy store id = %q, want %q", got, want)
	}
	if got, want := *input.AccessToken, request.AccessToken; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
	if got, want := *input.Action.ActionType, "Postern::Action"; got != want {
		t.Fatalf("action type = %q, want %q", got, want)
	}
	if got, want := *input.Action.ActionId, "MintOperatorCert"; got != want {
		t.Fatalf("action id = %q, want %q", got, want)
	}
	if got, want := *input.Resource.EntityType, "Postern::Device"; got != want {
		t.Fatalf("resource type = %q, want %q", got, want)
	}
	if got, want := *input.Resource.EntityId, request.Device.Serial; got != want {
		t.Fatalf("resource id = %q, want %q", got, want)
	}

	contextMap, ok := input.Context.(*types.ContextDefinitionMemberContextMap)
	if !ok {
		t.Fatalf("context = %T, want *ContextDefinitionMemberContextMap", input.Context)
	}
	if got := stringAttr(t, contextMap.Value["source_ip"]); got != request.SourceIP {
		t.Fatalf("context.source_ip = %q, want %q", got, request.SourceIP)
	}
	if got := stringAttr(t, contextMap.Value["request_id"]); got != request.RequestID {
		t.Fatalf("context.request_id = %q, want %q", got, request.RequestID)
	}
	if got, want := datetimeAttr(t, contextMap.Value["timestamp"]), request.Timestamp.UTC().Format(time.RFC3339); got != want {
		t.Fatalf("context.timestamp = %q, want %q", got, want)
	}

	entityList, ok := input.Entities.(*types.EntitiesDefinitionMemberEntityList)
	if !ok {
		t.Fatalf("entities = %T, want *EntitiesDefinitionMemberEntityList", input.Entities)
	}
	if got, want := len(entityList.Value), 1; got != want {
		t.Fatalf("entities = %d, want %d", got, want)
	}
	entity := entityList.Value[0]
	if got, want := *entity.Identifier.EntityId, request.Device.Serial; got != want {
		t.Fatalf("entity id = %q, want %q", got, want)
	}
	if got, want := stringAttr(t, entity.Attributes["serial"]), request.Device.Serial; got != want {
		t.Fatalf("entity.serial = %q, want %q", got, want)
	}
	if got, want := stringAttr(t, entity.Attributes["fleet"]), "prod"; got != want {
		t.Fatalf("entity.fleet = %q, want %q", got, want)
	}
	if got, want := boolAttr(t, entity.Attributes["production"]), true; got != want {
		t.Fatalf("entity.production = %v, want %v", got, want)
	}
	if got, want := longAttr(t, entity.Attributes["firmware_revision"]), int64(42); got != want {
		t.Fatalf("entity.firmware_revision = %d, want %d", got, want)
	}
	if _, present := entity.Attributes[" "]; present {
		t.Fatalf("entity attributes retained whitespace key: %#v", entity.Attributes)
	}
	if _, present := entity.Attributes["blank"]; present {
		t.Fatalf("entity attributes retained blank value: %#v", entity.Attributes)
	}
	if _, present := entity.Attributes["unsupported"]; present {
		t.Fatalf("entity attributes retained unsupported Go type: %#v", entity.Attributes)
	}
	// M-11 regression: the canonical Serial/FriendlyID must win over any
	// shadowing attempt in the attributes map. A registry returning these
	// keys inside its attributes (legal per the HTTP API contract) must
	// not be able to clobber the broker-resolved device identity used
	// for Cedar policy evaluation.
	if got, want := stringAttr(t, entity.Attributes["serial"]), request.Device.Serial; got != want {
		t.Fatalf("entity.serial = %q, want %q (shadowed by attribute?)", got, want)
	}
	if got, want := stringAttr(t, entity.Attributes["friendly_id"]), request.Device.FriendlyID; got != want {
		t.Fatalf("entity.friendly_id = %q, want %q (shadowed by attribute?)", got, want)
	}
}

func validRequest() broker.PolicyRequest {
	return broker.PolicyRequest{
		AccessToken: "test-access-token",
		Mode:        broker.ModeOperator,
		Engineer:    broker.EngineerClaims{Subject: "engineer-1234"},
		Device: broker.DeviceRecord{
			Serial:     "SERIAL123",
			FriendlyID: "prod-a012",
		},
		SourceIP:  "203.0.113.7",
		UserAgent: "postern-cli/1.0",
		RequestID: "req-7",
		Timestamp: time.Unix(1747000000, 0).UTC(),
	}
}

func stringAttr(t *testing.T, value types.AttributeValue) string {
	t.Helper()
	asString, ok := value.(*types.AttributeValueMemberString)
	if !ok {
		t.Fatalf("attribute = %T, want *AttributeValueMemberString", value)
	}
	return asString.Value
}

func datetimeAttr(t *testing.T, value types.AttributeValue) string {
	t.Helper()
	asDatetime, ok := value.(*types.AttributeValueMemberDatetime)
	if !ok {
		t.Fatalf("attribute = %T, want *AttributeValueMemberDatetime", value)
	}
	return asDatetime.Value
}

func boolAttr(t *testing.T, value types.AttributeValue) bool {
	t.Helper()
	asBool, ok := value.(*types.AttributeValueMemberBoolean)
	if !ok {
		t.Fatalf("attribute = %T, want *AttributeValueMemberBoolean", value)
	}
	return asBool.Value
}

func longAttr(t *testing.T, value types.AttributeValue) int64 {
	t.Helper()
	asLong, ok := value.(*types.AttributeValueMemberLong)
	if !ok {
		t.Fatalf("attribute = %T, want *AttributeValueMemberLong", value)
	}
	return asLong.Value
}

type fakeAVPClient struct {
	calls    []*verifiedpermissions.IsAuthorizedWithTokenInput
	decision types.Decision
	err      error
}

func (c *fakeAVPClient) IsAuthorizedWithToken(_ context.Context, input *verifiedpermissions.IsAuthorizedWithTokenInput, _ ...func(*verifiedpermissions.Options)) (*verifiedpermissions.IsAuthorizedWithTokenOutput, error) {
	c.calls = append(c.calls, input)
	if c.err != nil {
		return nil, c.err
	}
	return &verifiedpermissions.IsAuthorizedWithTokenOutput{Decision: c.decision}, nil
}
