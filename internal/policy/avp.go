// Package policy is the broker's Policy impl: AWS Verified Permissions
// IsAuthorizedWithToken against the operator's Cedar policy store.
package policy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
)

// ErrPolicyStoreIDRequired is returned by NewAVPPolicy when the policy store
// ID is empty.
var ErrPolicyStoreIDRequired = errors.New("AVP policy store ID is required")

// AVPClient is the subset of the AWS Verified Permissions API the policy
// consumes.
type AVPClient interface {
	IsAuthorizedWithToken(context.Context, *verifiedpermissions.IsAuthorizedWithTokenInput, ...func(*verifiedpermissions.Options)) (*verifiedpermissions.IsAuthorizedWithTokenOutput, error)
}

// AVPPolicy is the broker's Policy impl backed by AVP. Each Allow call
// translates a broker.PolicyRequest into one IsAuthorizedWithToken RPC.
type AVPPolicy struct {
	client        AVPClient
	policyStoreID string
}

// NewAVPPolicy constructs an AVPPolicy against an existing AVP client.
func NewAVPPolicy(client AVPClient, policyStoreID string) (*AVPPolicy, error) {
	if policyStoreID == "" {
		return nil, ErrPolicyStoreIDRequired
	}
	return &AVPPolicy{client: client, policyStoreID: policyStoreID}, nil
}

// NewAVPPolicyFromConfig wires the AVP client from an aws.Config and
// delegates to NewAVPPolicy.
func NewAVPPolicyFromConfig(config aws.Config, policyStoreID string) (*AVPPolicy, error) {
	return NewAVPPolicy(verifiedpermissions.NewFromConfig(config), policyStoreID)
}

// Allow returns nil iff AVP returns Decision=Allow; a Deny becomes a 403
// broker.Error. An unrecognized Mode returns 501 — defense against a wrapper
// introducing a mode without wiring it through to AVP.
func (p *AVPPolicy) Allow(ctx context.Context, request broker.PolicyRequest) error {
	var actionID string
	switch request.Mode {
	case broker.ModeOperator:
		actionID = broker.PolicyActionMintOperatorCert
	case broker.ModeTimefix:
		actionID = broker.PolicyActionMintTimefixCert
	case broker.ModeTunnel:
		actionID = broker.PolicyActionOpenTunnel
	default:
		return broker.Error{StatusCode: http.StatusNotImplemented, Message: "policy mode is not implemented"}
	}
	output, err := p.client.IsAuthorizedWithToken(ctx, &verifiedpermissions.IsAuthorizedWithTokenInput{
		PolicyStoreId: aws.String(p.policyStoreID),
		AccessToken:   aws.String(request.AccessToken),
		Action: &types.ActionIdentifier{
			ActionType: aws.String("Postern::Action"),
			ActionId:   aws.String(actionID),
		},
		Resource: &types.EntityIdentifier{
			EntityType: aws.String("Postern::Device"),
			EntityId:   aws.String(request.Device.Serial),
		},
		Context:  contextMap(request),
		Entities: entities(request.Device),
	})
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if output.Decision != types.DecisionAllow {
		return broker.Error{StatusCode: http.StatusForbidden, Message: "authorization denied"}
	}

	return nil
}

func contextMap(request broker.PolicyRequest) types.ContextDefinition {
	attributes := map[string]types.AttributeValue{
		"source_ip":  &types.AttributeValueMemberString{Value: request.SourceIP},
		"user_agent": &types.AttributeValueMemberString{Value: request.UserAgent},
		"request_id": &types.AttributeValueMemberString{Value: request.RequestID},
	}
	if !request.Timestamp.IsZero() {
		attributes["timestamp"] = &types.AttributeValueMemberDatetime{Value: request.Timestamp.UTC().Format(time.RFC3339)}
	}

	// Per-endpoint context overlay (tunnel pipeline injects
	// requested_max_lifetime_minutes). Reserved keys above can't be
	// shadowed by request-supplied values.
	for key, value := range request.Context {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if _, reserved := attributes[trimmedKey]; reserved {
			continue
		}
		if emitted, ok := cedarAttributeValue(value); ok {
			attributes[trimmedKey] = emitted
		}
	}
	return &types.ContextDefinitionMemberContextMap{Value: attributes}
}

func entities(device broker.DeviceRecord) types.EntitiesDefinition {
	attributes := map[string]types.AttributeValue{}
	for rawKey, rawValue := range device.Attributes {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			continue
		}
		if emitted, ok := cedarAttributeValue(rawValue); ok {
			attributes[key] = emitted
		}
	}
	// Canonical fields written AFTER the attribute loop so a registry
	// returning serial / friendly_id inside its attributes map can't
	// shadow the broker-resolved values. The HTTP Registry can carry
	// arbitrary operator-controlled keys; clobbering serial would
	// propagate an attacker-controlled value into the Cedar Device.
	attributes["serial"] = &types.AttributeValueMemberString{Value: device.Serial}
	if device.FriendlyID != "" {
		attributes["friendly_id"] = &types.AttributeValueMemberString{Value: device.FriendlyID}
	}
	return &types.EntitiesDefinitionMemberEntityList{Value: []types.EntityItem{{
		Identifier: &types.EntityIdentifier{
			EntityType: aws.String("Postern::Device"),
			EntityId:   aws.String(device.Serial),
		},
		Attributes: attributes,
	}}}
}

// cedarAttributeValue maps a value to its Cedar representation: string →
// String, bool → Boolean, int64 → Long. Other types drop. Blank strings
// drop; false bools and zero ints are kept (they're meaningful).
func cedarAttributeValue(value any) (types.AttributeValue, bool) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil, false
		}
		return &types.AttributeValueMemberString{Value: trimmed}, true
	case bool:
		return &types.AttributeValueMemberBoolean{Value: typed}, true
	case int64:
		return &types.AttributeValueMemberLong{Value: typed}, true
	default:
		return nil, false
	}
}
