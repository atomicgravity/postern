// Package registry is the broker's Registry impl — resolving a device_id to
// a hardware-serial-keyed DeviceRecord. Two concretes ship: DynamoDB (the
// AWS-native default) and HTTP (for operators backing the lookup with their
// own inventory service).
package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ErrDynamoDBTableRequired is returned when the table name is empty.
var ErrDynamoDBTableRequired = errors.New("registry DynamoDB table is required")

// DynamoDBClient is the subset of the DynamoDB API the registry consumes.
type DynamoDBClient interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
}

// DynamoDBRegistry resolves device_id to broker.DeviceRecord via consistent
// reads — just-provisioned devices are visible immediately.
type DynamoDBRegistry struct {
	client DynamoDBClient
	table  string
}

// NewDynamoDBRegistry constructs a DynamoDBRegistry against an existing
// client.
func NewDynamoDBRegistry(client DynamoDBClient, table string) (*DynamoDBRegistry, error) {
	if table == "" {
		return nil, ErrDynamoDBTableRequired
	}
	return &DynamoDBRegistry{client: client, table: table}, nil
}

// NewDynamoDBRegistryFromConfig wires the DynamoDB client from an aws.Config.
func NewDynamoDBRegistryFromConfig(config aws.Config, table string) (*DynamoDBRegistry, error) {
	return NewDynamoDBRegistry(dynamodb.NewFromConfig(config), table)
}

// ResolveDevice looks up deviceID and returns the matching DeviceRecord. A
// missing item produces 404; an item lacking a serial attribute produces
// 500 (registry shape invariant violated upstream).
func (r *DynamoDBRegistry) ResolveDevice(ctx context.Context, deviceID string) (broker.DeviceRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusBadRequest, Message: "device_id is required"}
	}

	output, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(r.table),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"device_id": &types.AttributeValueMemberS{Value: deviceID},
		},
	})
	if err != nil {
		return broker.DeviceRecord{}, fmt.Errorf("registry: %w", err)
	}
	if len(output.Item) == 0 {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusNotFound, Message: "device not found"}
	}

	serial := stringAttribute(output.Item, "serial")
	if serial == "" {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusInternalServerError, Message: "registry item missing serial"}
	}
	if err := validateSerial(serial); err != nil {
		return broker.DeviceRecord{}, err
	}

	attributes := map[string]any{}
	for key, value := range output.Item {
		if key == "device_id" || key == "serial" || key == "friendly_id" {
			continue
		}
		if normalized, ok := normalizeDynamoDBAttribute(value); ok {
			attributes[key] = normalized
		}
	}

	return broker.DeviceRecord{
		Serial:     serial,
		FriendlyID: stringAttribute(output.Item, "friendly_id"),
		Attributes: attributes,
	}, nil
}

func stringAttribute(item map[string]types.AttributeValue, name string) string {
	return stringAttributeValue(item[name])
}

func stringAttributeValue(value types.AttributeValue) string {
	stringValue, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue.Value)
}

// normalizeDynamoDBAttribute coerces a DynamoDB attribute to one of the
// three types DeviceRecord.Attributes carries (string, bool, int64) — the
// types Policy can emit as Cedar (String, Boolean, Long). Whitespace-only
// strings drop; non-integer numerics drop; L/M/SS/NS/BS/NULL/B drop.
func normalizeDynamoDBAttribute(value types.AttributeValue) (any, bool) {
	switch typed := value.(type) {
	case *types.AttributeValueMemberS:
		trimmed := strings.TrimSpace(typed.Value)
		if trimmed == "" {
			return nil, false
		}
		return trimmed, true
	case *types.AttributeValueMemberBOOL:
		return typed.Value, true
	case *types.AttributeValueMemberN:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed.Value), 10, 64)
		if err != nil {
			return nil, false
		}
		return parsed, true
	default:
		return nil, false
	}
}
