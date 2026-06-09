// Package ratelimit is the broker's RateLimiter impl: a DynamoDB-backed
// fixed-window (tumbling) limiter. Each Allow does a conditional UpdateItem
// keyed on (engineer_sub, mode:window-bucket); the predicate makes the
// increment-or-reject atomic without a separate read. Adjacent windows each
// see a fresh counter, so at a boundary an engineer can briefly issue up
// to 2*limit — pick a window short enough that this burst is acceptable.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Default rate-limit knobs: 60 requests per (engineer, mode) per minute.
const (
	DefaultLimit  = 60
	DefaultWindow = time.Minute
)

// ErrTableRequired is returned when the DynamoDB table is empty.
var ErrTableRequired = errors.New("rate limit DynamoDB table is required")

// DynamoDBClient is the subset of the DynamoDB API the rate limiter consumes.
type DynamoDBClient interface {
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// DynamoDBRateLimiter enforces a per-engineer-per-mode tumbling window via a
// conditional UpdateItem on the configured DynamoDB table.
type DynamoDBRateLimiter struct {
	client DynamoDBClient
	table  string
	limit  int
	window time.Duration
	clock  broker.Clock
}

// newDynamoDBRateLimiter constructs a DynamoDBRateLimiter with the package
// default limit / window. Test-only — production wiring uses
// NewDynamoDBRateLimiterFromConfig.
func newDynamoDBRateLimiter(client DynamoDBClient, table string) (*DynamoDBRateLimiter, error) {
	return NewDynamoDBRateLimiterWithOptions(client, table, DefaultLimit, DefaultWindow, broker.SystemClock{})
}

// NewDynamoDBRateLimiterFromConfig wires the DynamoDB client from an
// aws.Config; limit and window must be positive.
func NewDynamoDBRateLimiterFromConfig(config aws.Config, table string, limit int, window time.Duration) (*DynamoDBRateLimiter, error) {
	return NewDynamoDBRateLimiterWithOptions(dynamodb.NewFromConfig(config), table, limit, window, broker.SystemClock{})
}

// NewDynamoDBRateLimiterWithOptions is the full-control constructor; rejects
// empty table and non-positive limit / window.
func NewDynamoDBRateLimiterWithOptions(client DynamoDBClient, table string, limit int, window time.Duration, clock broker.Clock) (*DynamoDBRateLimiter, error) {
	if table == "" {
		return nil, ErrTableRequired
	}
	if limit <= 0 {
		return nil, errors.New("rate limit must be positive")
	}
	if window <= 0 {
		return nil, errors.New("rate limit window must be positive")
	}
	if clock == nil {
		clock = broker.SystemClock{}
	}
	return &DynamoDBRateLimiter{client: client, table: table, limit: limit, window: window, clock: clock}, nil
}

// Allow returns nil if the engineer has remaining budget in the current
// window or a 429 broker.Error when the predicate fails.
func (l *DynamoDBRateLimiter) Allow(ctx context.Context, request broker.RateLimitRequest) error {
	engineerSub := strings.TrimSpace(request.Caller.Subject)
	if engineerSub == "" {
		return broker.Error{StatusCode: http.StatusUnauthorized, Message: "engineer subject is required"}
	}

	now := l.clock.Now().UTC()
	windowStart := now.Truncate(l.window).Unix()
	expiresAt := now.Add(2 * l.window).Unix()

	_, err := l.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(l.table),
		Key: map[string]types.AttributeValue{
			"engineer_sub": &types.AttributeValueMemberS{Value: engineerSub},
			"window":       &types.AttributeValueMemberS{Value: request.Mode + ":" + strconv.FormatInt(windowStart, 10)},
		},
		UpdateExpression:    aws.String("ADD #count :one SET #expires_at = :expires_at"),
		ConditionExpression: aws.String("attribute_not_exists(#count) OR #count < :limit"),
		ExpressionAttributeNames: map[string]string{
			"#count":      "count",
			"#expires_at": "expires_at",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":        &types.AttributeValueMemberN{Value: "1"},
			":limit":      &types.AttributeValueMemberN{Value: strconv.Itoa(l.limit)},
			":expires_at": &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt, 10)},
		},
	})
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return broker.Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"}
		}
		return fmt.Errorf("ratelimit: %w", err)
	}

	return nil
}
