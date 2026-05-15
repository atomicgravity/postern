package registry

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestDynamoDBRegistryResolveDeviceMapsAttributeTypes(t *testing.T) {
	client := &fakeDynamoDBClient{output: &dynamodb.GetItemOutput{
		Item: map[string]types.AttributeValue{
			"device_id":         &types.AttributeValueMemberS{Value: "prod-a012"},
			"serial":            &types.AttributeValueMemberS{Value: " SERIAL123 "},
			"friendly_id":       &types.AttributeValueMemberS{Value: " prod-a012 "},
			"fleet":             &types.AttributeValueMemberS{Value: " prod "},
			"empty_string":      &types.AttributeValueMemberS{Value: " "},
			"production":        &types.AttributeValueMemberBOOL{Value: true},
			"firmware_revision": &types.AttributeValueMemberN{Value: "42"},
			"decimal":           &types.AttributeValueMemberN{Value: "1.5"},
			"unsupported":       &types.AttributeValueMemberSS{Value: []string{"dropped"}},
		},
	}}

	registry, err := NewDynamoDBRegistry(client, "devices")
	if err != nil {
		t.Fatalf("NewDynamoDBRegistry() error = %v", err)
	}
	device, err := registry.ResolveDevice(context.Background(), "prod-a012")
	if err != nil {
		t.Fatalf("ResolveDevice() error = %v", err)
	}
	if got, want := device.Serial, "SERIAL123"; got != want {
		t.Fatalf("serial = %q, want %q", got, want)
	}
	if got, want := device.FriendlyID, "prod-a012"; got != want {
		t.Fatalf("friendly id = %q, want %q", got, want)
	}
	if got, want := device.Attributes["fleet"], "prod"; got != want {
		t.Fatalf("fleet = %v, want %v", got, want)
	}
	if got, want := device.Attributes["production"], true; got != want {
		t.Fatalf("production = %v, want %v", got, want)
	}
	if got, want := device.Attributes["firmware_revision"], int64(42); got != want {
		t.Fatalf("firmware_revision = %v, want %v", got, want)
	}
	if _, ok := device.Attributes["empty_string"]; ok {
		t.Fatalf("empty string attribute was retained: %#v", device.Attributes)
	}
	if _, ok := device.Attributes["decimal"]; ok {
		t.Fatalf("non-integer N attribute was retained: %#v", device.Attributes)
	}
	if _, ok := device.Attributes["unsupported"]; ok {
		t.Fatalf("unsupported DynamoDB type was retained: %#v", device.Attributes)
	}
}

func TestDynamoDBRegistryResolveDeviceMapsNotFound(t *testing.T) {
	client := &fakeDynamoDBClient{output: &dynamodb.GetItemOutput{}}
	registry, err := NewDynamoDBRegistry(client, "devices")
	if err != nil {
		t.Fatalf("NewDynamoDBRegistry() error = %v", err)
	}
	_, err = registry.ResolveDevice(context.Background(), "missing")
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusNotFound {
		t.Fatalf("ResolveDevice() error = %v, want %d broker.Error", err, http.StatusNotFound)
	}
}

func TestDynamoDBRegistryResolveDeviceRequiresSerial(t *testing.T) {
	client := &fakeDynamoDBClient{output: &dynamodb.GetItemOutput{
		Item: map[string]types.AttributeValue{
			"device_id": &types.AttributeValueMemberS{Value: "prod-a012"},
		},
	}}
	registry, err := NewDynamoDBRegistry(client, "devices")
	if err != nil {
		t.Fatalf("NewDynamoDBRegistry() error = %v", err)
	}
	_, err = registry.ResolveDevice(context.Background(), "prod-a012")
	var domainErr broker.Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("ResolveDevice() error = %v, want %d broker.Error", err, http.StatusInternalServerError)
	}
}

func TestNewDynamoDBRegistryRejectsEmptyTable(t *testing.T) {
	_, err := NewDynamoDBRegistry(&fakeDynamoDBClient{}, "")
	if !errors.Is(err, ErrDynamoDBTableRequired) {
		t.Fatalf("NewDynamoDBRegistry() error = %v, want ErrDynamoDBTableRequired", err)
	}
}

type fakeDynamoDBClient struct {
	output *dynamodb.GetItemOutput
	err    error
}

func (c *fakeDynamoDBClient) GetItem(_ context.Context, _ *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.output, nil
}
